"""
core/config.py — Centralised application configuration.

All settings are read from environment variables / .env file via pydantic-settings.
This is the single source of truth for runtime configuration. No other module
should read os.environ directly for settings that affect safety behaviour.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from .env or environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    app_name: str = "ForensiWipe"
    app_version: str = "1.0.0-phase1"
    debug: bool = False
    operator_id: str = "forensiwipe-operator"

    # ── Safety ────────────────────────────────────────────────────────────────
    # SAFE_MODE defaults to True. This cannot be changed without explicit env override.
    safe_mode: bool = True
    allow_physical_erase: bool = False

    # Approved directory for demo images (loopback targets must live here in safe mode).
    safe_demo_dir: Path = Path("demo")

    # ── Paths ─────────────────────────────────────────────────────────────────
    audit_db_path: Path = Path("forensiwipe_audit.db")
    recovered_dir: Path = Path("recovered")
    reports_dir: Path = Path("reports_output")

    # ── Server ────────────────────────────────────────────────────────────────
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    frontend_origin: str = "http://localhost:5173"

    # ── Validation ────────────────────────────────────────────────────────────

    @field_validator("safe_demo_dir", "audit_db_path", "recovered_dir", "reports_dir", mode="before")
    @classmethod
    def _resolve_path(cls, v: object) -> Path:
        return Path(str(v)).resolve()

    @model_validator(mode="after")
    def _safety_invariant(self) -> "Settings":
        """
        Enforce the safety invariant at startup:
        Physical erase cannot be enabled while safe mode is on.
        If someone sets SAFE_MODE=false but forgets ALLOW_PHYSICAL_ERASE=true,
        physical erase remains disabled — this is intentional fail-safe behaviour.
        """
        if self.allow_physical_erase and self.safe_mode:
            # Safe mode takes precedence; silently demote allow_physical_erase.
            object.__setattr__(self, "allow_physical_erase", False)
        return self

    # ── Derived helpers ───────────────────────────────────────────────────────

    @property
    def physical_erase_enabled(self) -> bool:
        """True only when BOTH safe_mode=False AND allow_physical_erase=True."""
        return (not self.safe_mode) and self.allow_physical_erase

    @property
    def safe_demo_dir_resolved(self) -> Path:
        return self.safe_demo_dir.resolve()

    def ensure_directories(self) -> None:
        """Create output directories if they do not exist."""
        self.recovered_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.audit_db_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached singleton Settings instance.
    Call get_settings() from any module — it is cheap after the first call.
    """
    s = Settings()
    s.ensure_directories()
    return s
