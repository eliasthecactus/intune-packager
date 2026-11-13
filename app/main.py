"""FastAPI app: web UI, upload, job status, downloads, shared-key auth."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile

from .config import settings
from .jobs import JobManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("intune-packager")
STATIC = Path(__file__).parent / "static"
COOKIE = "ip_session"
manager: JobManager | None = None
_failed_logins: dict[str, list[float]] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global manager
    manager = JobManager()
    cleanup = asyncio.create_task(manager.cleanup_loop())
    errors = settings.config_errors()
    log.info("Provider: %s%s", settings.provider_summary(), f" (NOT CONFIGURED: {'; '.join(errors)})" if errors else "")
    log.info("Shared key: %s", "required" if settings.shared_key else "disabled")
    yield
    cleanup.cancel()


app = FastAPI(title="Intune Packager", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- security
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


def _session_token() -> str:
    return hmac.new((settings.shared_key or "").encode(), b"intune-packager-session-v1", hashlib.sha256).hexdigest()


def is_authenticated(request: Request) -> bool:
    if not settings.shared_key:
        return True
    cookie = request.cookies.get(COOKIE, "")
    if cookie and hmac.compare_digest(cookie, _session_token()):
        return True
    header = request.headers.get("x-access-key") or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    return bool(header) and hmac.compare_digest(header.encode(), settings.shared_key.encode())


def require_auth(request: Request) -> None:
    if not is_authenticated(request):
        raise HTTPException(401, "Access key required")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.get("/api/config")
async def config(request: Request):
    errors = settings.config_errors()
    return {
        "auth_required": bool(settings.shared_key),
        "authenticated": is_authenticated(request),
        "provider": settings.provider_summary(),
        "configured": not errors,
        "config_errors": errors,
        "max_upload_mb": settings.max_upload_mb,
    }


@app.post("/api/login")
async def login(request: Request):
    if not settings.shared_key:
        return {"ok": True}
    ip = _client_ip(request)
    now = time.time()
    recent = [t for t in _failed_logins.get(ip, []) if now - t < 600]
    if len(recent) >= 10:
        raise HTTPException(429, "Too many attempts, try again later")
    try:
        body = await request.json()
    except json.JSONDecodeError:
        body = {}
    key = str(body.get("key", ""))
    if not hmac.compare_digest(key.encode(), settings.shared_key.encode()):
        recent.append(now)
        _failed_logins[ip] = recent
        await asyncio.sleep(1)
        raise HTTPException(401, "Wrong access key")
    _failed_logins.pop(ip, None)
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    secure = settings.cookie_secure == "true" or (settings.cookie_secure == "auto" and is_https)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(COOKIE, _session_token(), httponly=True, samesite="strict", secure=secure, max_age=30 * 24 * 3600)
    return resp


@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


# ------------------------------------------------------------------ jobs
def _safe_relpath(name: str) -> PurePosixPath | None:
    name = name.replace("\\", "/").strip()
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".", "/")]
    if not parts or any(p == ".." or re.search(r'[<>:"|?*\x00-\x1f]', p) for p in parts):
        return None
    if parts[0] == "__MACOSX" or parts[-1] in (".DS_Store", "Thumbs.db", "desktop.ini"):
        return None
    return PurePosixPath(*parts)


@app.post("/api/jobs")
async def create_job(request: Request):
    require_auth(request)
    errors = settings.config_errors()
    if errors:
        raise HTTPException(503, "AI provider not configured: " + "; ".join(errors))
    limit = settings.max_upload_mb * 1024 * 1024
    if int(request.headers.get("content-length") or 0) > limit + 1024 * 1024:
        raise HTTPException(413, f"Upload larger than {settings.max_upload_mb} MB")

    form = await request.form(max_files=10000, max_fields=20000)
    description = str(form.get("description") or "")[:20000]
    uploads = [f for f in form.getlist("files") if isinstance(f, UploadFile)]
    try:
        paths = json.loads(str(form.get("paths") or "[]"))
    except json.JSONDecodeError:
        paths = []
    if not description.strip() and not uploads:
        raise HTTPException(400, "Upload files or describe what you need (or both)")

    job = manager.new_job(description)
    source = job.dir / "source"
    total = 0
    try:
        for i, upload in enumerate(uploads):
            rel = _safe_relpath(paths[i] if i < len(paths) and paths[i] else (upload.filename or f"file{i}"))
            if rel is None:
                continue
            target = source / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as out:
                while chunk := await upload.read(1024 * 1024):
                    total += len(chunk)
                    if total > limit:
                        raise HTTPException(413, f"Upload larger than {settings.max_upload_mb} MB")
                    out.write(chunk)
    except HTTPException:
        shutil.rmtree(job.dir, ignore_errors=True)
        manager.jobs.pop(job.id, None)
        raise
    finally:
        await form.close()

    count = sum(1 for p in source.rglob("*") if p.is_file())
    job.emit("step", f"Received {count} file(s), {total / 1024 / 1024:.1f} MB" if count else "No files - working from the description")
    manager.start(job)
    return {"id": job.id}


def _job(request: Request, job_id: str):
    require_auth(request)
    job = manager.jobs.get(job_id) if re.fullmatch(r"[0-9a-f]{32}", job_id) else None
    if not job:
        raise HTTPException(404, "Job not found (jobs expire after a while)")
    return job


@app.get("/api/jobs/{job_id}")
async def job_status(request: Request, job_id: str, since: int = 0):
    return _job(request, job_id).public(max(0, since))


@app.get("/api/jobs/{job_id}/download")
async def job_download(request: Request, job_id: str):
    job = _job(request, job_id)
    if not job.zip_path or not job.zip_path.is_file():
        raise HTTPException(404, "No download available")
    return FileResponse(job.zip_path, media_type="application/zip", filename=job.zip_path.name)


@app.get("/api/jobs/{job_id}/logo")
async def job_logo(request: Request, job_id: str):
    job = _job(request, job_id)
    if not job.logo_path or not job.logo_path.is_file():
        raise HTTPException(404, "No logo")
    return FileResponse(job.logo_path, media_type="image/png")


@app.get("/healthz")
async def health():
    return {"ok": True}


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
