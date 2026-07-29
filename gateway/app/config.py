"""Runtime configuration.

Everything here is env-overridable so the same image runs in dev and prod.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env"), env_prefix="SCANNER_", extra="ignore"
    )

    # --- storage -----------------------------------------------------------
    database_url: str = f"sqlite+aiosqlite:///{REPO_ROOT / 'scanner.db'}"

    @field_validator("database_url")
    @classmethod
    def _use_async_driver(cls, v: str) -> str:
        # Managed Postgres (Railway, Heroku, ...) hands out a plain
        # postgres[ql]:// URL — SQLAlchemy's async engine needs the asyncpg
        # driver named explicitly.
        if v.startswith("postgres://"):
            return "postgresql+asyncpg://" + v[len("postgres://"):]
        if v.startswith("postgresql://"):
            return "postgresql+asyncpg://" + v[len("postgresql://"):]
        return v

    # --- upstream providers ------------------------------------------------
    anthropic_base_url: str = "https://api.anthropic.com"
    openai_base_url: str = "https://api.openai.com"
    upstream_timeout_s: float = 600.0
    upstream_connect_timeout_s: float = 10.0

    # --- council -----------------------------------------------------------
    # The council calls Claude. Credentials resolve the normal SDK way:
    # ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile.
    council_enabled: bool = True
    council_specialist_model: str = "claude-opus-5"
    council_adjudicator_model: str = "claude-opus-5"
    council_specialist_effort: str = "medium"
    council_adjudicator_effort: str = "high"
    council_max_tokens: int = 8000
    # Prompts scoring below this on the fast gate never reach the council.
    council_min_score: int = 15
    council_max_concurrency: int = 8
    council_timeout_s: float = 120.0

    # --- enforcement -------------------------------------------------------
    policy_path: Path = REPO_ROOT / "gateway" / "app" / "policy" / "policy.yaml"
    # Global kill switch: force every decision to ALLOW while still recording.
    shadow_mode: bool = False
    # Chars of prompt text retained on a finding for investigation. 0 disables.
    evidence_context_chars: int = 80
    # Retain raw prompt text on records. Off by default — the store becomes a
    # secondary copy of the very data we are trying to protect.
    store_raw_prompts: bool = False

    # --- api ---------------------------------------------------------------
    dashboard_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    # Shared secret the browser extension and dashboard present. Rotate in prod.
    api_key: str = "dev-scanner-key"
    require_api_key: bool = False

    # --- dashboard auth ------------------------------------------------------
    # HTTP Basic Auth in front of the CISO dashboard's API, live feed, and
    # admin routes. An unset password disables it — fine for local dev, but
    # set both before deploying anywhere reachable off your own machine.
    dashboard_username: str = "admin"
    dashboard_password: str | None = None

    # --- alerting ----------------------------------------------------------
    webhook_url: str | None = None
    webhook_min_severity: str = "high"


@lru_cache
def get_settings() -> Settings:
    return Settings()
