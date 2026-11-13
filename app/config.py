"""Runtime configuration, read once from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else default


def _int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value else default


def _bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # --- AI provider -------------------------------------------------------
    llm_provider: str = field(default_factory=lambda: (_env("LLM_PROVIDER", "openrouter") or "").lower())

    openrouter_api_key: str | None = field(default_factory=lambda: _env("OPENROUTER_API_KEY"))
    openrouter_model: str = field(default_factory=lambda: _env("OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash"))
    openrouter_base_url: str = field(default_factory=lambda: _env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"))

    # Microsoft Foundry: FOUNDRY_RESOURCE (name) or FOUNDRY_ENDPOINT (full URL)
    foundry_resource: str | None = field(default_factory=lambda: _env("FOUNDRY_RESOURCE"))
    foundry_endpoint: str | None = field(default_factory=lambda: _env("FOUNDRY_ENDPOINT"))
    foundry_api_key: str | None = field(default_factory=lambda: _env("FOUNDRY_API_KEY"))
    foundry_model: str = field(default_factory=lambda: _env("FOUNDRY_MODEL", "claude-opus-5-5"))
    # auto = Claude deployments use the Anthropic Messages API, everything else the OpenAI v1 API
    foundry_api_style: str = field(default_factory=lambda: (_env("FOUNDRY_API_STYLE", "auto") or "auto").lower())
    foundry_auth_header: str = field(default_factory=lambda: (_env("FOUNDRY_AUTH_HEADER", "api-key") or "api-key").lower())
    foundry_api_version: str | None = field(default_factory=lambda: _env("FOUNDRY_API_VERSION"))
    # Optional Claude fallback deployment used when the main model refuses (must be deployed)
    foundry_fallback_model: str | None = field(default_factory=lambda: _env("FOUNDRY_FALLBACK_MODEL"))

    # Claude effort level (low|medium|high|xhigh|max); empty = model default
    claude_effort: str | None = field(default_factory=lambda: _env("CLAUDE_EFFORT", "high"))
    llm_max_tokens: int = field(default_factory=lambda: _int("LLM_MAX_TOKENS", 16000))
    agent_max_steps: int = field(default_factory=lambda: _int("AGENT_MAX_STEPS", 60))

    # --- Research ------------------------------------------------------------
    search_provider: str = field(default_factory=lambda: (_env("SEARCH_PROVIDER", "auto") or "auto").lower())
    tavily_api_key: str | None = field(default_factory=lambda: _env("TAVILY_API_KEY"))
    brave_api_key: str | None = field(default_factory=lambda: _env("BRAVE_API_KEY"))
    searxng_url: str | None = field(default_factory=lambda: _env("SEARXNG_URL"))
    allow_private_urls: bool = field(default_factory=lambda: _bool("ALLOW_PRIVATE_URLS", False))
    download_max_mb: int = field(default_factory=lambda: _int("DOWNLOAD_MAX_MB", 2048))

    # --- App -----------------------------------------------------------------
    shared_key: str | None = field(default_factory=lambda: _env("SHARED_KEY"))
    cookie_secure: str = field(default_factory=lambda: (_env("COOKIE_SECURE", "auto") or "auto").lower())
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "./data")).resolve())
    max_upload_mb: int = field(default_factory=lambda: _int("MAX_UPLOAD_MB", 4096))
    max_concurrent_jobs: int = field(default_factory=lambda: _int("MAX_CONCURRENT_JOBS", 2))
    job_ttl_hours: int = field(default_factory=lambda: _int("JOB_TTL_HOURS", 24))

    def provider_summary(self) -> str:
        if self.llm_provider == "openrouter":
            return f"OpenRouter · {self.openrouter_model}"
        if self.llm_provider == "foundry":
            return f"Microsoft Foundry · {self.foundry_model}"
        return self.llm_provider

    def config_errors(self) -> list[str]:
        errors: list[str] = []
        if self.llm_provider == "openrouter":
            if not self.openrouter_api_key:
                errors.append("OPENROUTER_API_KEY is not set")
        elif self.llm_provider == "foundry":
            if not (self.foundry_resource or self.foundry_endpoint):
                errors.append("FOUNDRY_RESOURCE or FOUNDRY_ENDPOINT must be set")
            if not self.foundry_api_key:
                errors.append("FOUNDRY_API_KEY is not set")
        else:
            errors.append(f"LLM_PROVIDER must be 'openrouter' or 'foundry' (got '{self.llm_provider}')")
        return errors


settings = Settings()
