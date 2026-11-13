"""In-memory job tracking, background execution and cleanup."""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .agent import PackagingAgent, Workspace
from .config import settings
from .llm import LLMError
from .output import build_deliverable

log = logging.getLogger(__name__)


@dataclass
class Job:
    id: str
    dir: Path
    description: str
    created: float = field(default_factory=time.time)
    status: str = "queued"  # queued | running | done | failed
    events: list[dict] = field(default_factory=list)
    ui: dict | None = None
    error: str | None = None
    usage: dict | None = None
    zip_path: Path | None = None
    logo_path: Path | None = None
    finished: float | None = None

    def emit(self, kind: str, message: str) -> None:
        self.events.append({"i": len(self.events), "t": round(time.time() - self.created, 1), "type": kind, "msg": message})

    def public(self, since: int = 0) -> dict:
        data = {
            "id": self.id,
            "status": self.status,
            "events": self.events[since:],
            "next": len(self.events),
            "error": self.error,
            "usage": self.usage,
            "elapsed": round((self.finished or time.time()) - self.created),
        }
        if self.status == "done" and self.ui:
            data["result"] = self.ui
        return data


class JobManager:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.sem = asyncio.Semaphore(max(1, settings.max_concurrent_jobs))
        self.root = settings.data_dir / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self._tasks: set[asyncio.Task] = set()

    def new_job(self, description: str) -> Job:
        job_id = uuid.uuid4().hex
        job = Job(id=job_id, dir=self.root / job_id, description=description)
        Workspace(job.dir)  # creates folders
        self.jobs[job_id] = job
        return job

    def start(self, job: Job) -> None:
        task = asyncio.create_task(self._run(job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, job: Job) -> None:
        if self.sem.locked():
            job.emit("step", "Waiting for a free slot")
        async with self.sem:
            job.status = "running"
            ws = Workspace(job.dir)
            agent = PackagingAgent(ws, job.emit, settings.agent_max_steps)
            try:
                files = await agent.prepare()
                result = await agent.run(job.description, files)
                agent.fallback_logo()
                job.emit("step", "Building package and documentation")
                zip_path, ui = await asyncio.to_thread(build_deliverable, result, ws.source, ws.output, ws.logo, job.id)
                job.zip_path = zip_path
                job.logo_path = ws.output / "logo.png" if ws.logo else None
                job.ui = ui
                job.status = "done"
                job.emit("done", "Package ready" if ui["feasible"] else "Finished - see explanation")
            except LLMError as exc:
                job.status, job.error = "failed", str(exc)
                job.emit("error", str(exc))
            except Exception as exc:
                log.exception("job %s failed", job.id)
                job.status, job.error = "failed", f"Internal error: {type(exc).__name__}: {exc}"
                job.emit("error", job.error)
            finally:
                if agent.session is not None:
                    job.usage = agent.session.usage.as_dict()
                job.finished = time.time()
                # the uploaded/extracted content is no longer needed once the zip exists
                shutil.rmtree(ws.work, ignore_errors=True)

    async def cleanup_loop(self) -> None:
        while True:
            try:
                cutoff = time.time() - settings.job_ttl_hours * 3600
                for job_id, job in list(self.jobs.items()):
                    if job.created < cutoff and job.status in ("done", "failed"):
                        shutil.rmtree(job.dir, ignore_errors=True)
                        self.jobs.pop(job_id, None)
                for d in self.root.iterdir():  # leftovers from previous runs
                    if d.is_dir() and d.name not in self.jobs and d.stat().st_mtime < cutoff:
                        shutil.rmtree(d, ignore_errors=True)
            except Exception:
                log.exception("cleanup failed")
            await asyncio.sleep(900)
