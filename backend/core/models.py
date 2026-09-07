"""
core/models.py — Shared Pydantic models and enumerations used across all modules.

These are the canonical data contracts for the API layer and internal services.
Module-specific models extend or reference these but do not redefine them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Enumerations ──────────────────────────────────────────────────────────────


class OperationStatus(str, Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class OperationModule(str, Enum):
    DRIVE_ERASE = "DRIVE_ERASE"
    FILE_ERASE  = "FILE_ERASE"
    CARVE       = "CARVE"
    AUDIT       = "AUDIT"
    SYSTEM      = "SYSTEM"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EraseStandard(str, Enum):
    ZERO_FILL = "ZERO_FILL"          # Single-pass zero overwrite — basic clear
    RANDOM_FILL = "RANDOM_FILL"      # Single-pass PRNG overwrite
    DOD_3PASS = "DOD_3PASS"         # DoD 5220.22-M 3-pass (demo/historical)
    GUTMANN_35 = "GUTMANN_35"       # Gutmann 35-pass (demo/historical)
    NIST_CLEAR = "NIST_CLEAR"       # NIST SP 800-88 Clear
    NIST_PURGE = "NIST_PURGE"       # NIST SP 800-88 Purge (hw-dependent)
    CRYPTO_ERASE = "CRYPTO_ERASE"   # Cryptographic erase (hw-dependent)


class MediaType(str, Enum):
    HDD = "HDD"
    SSD = "SSD"
    NVME = "NVME"
    USB = "USB"
    LOOP = "LOOP"
    UNKNOWN = "UNKNOWN"


class VerificationStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ── Operation models ──────────────────────────────────────────────────────────


def _new_operation_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    short = str(uuid.uuid4()).split("-")[0].upper()
    return f"OP-{ts}-{short}"


class OperationRecord(BaseModel):
    """Runtime state of a long-running operation — held in memory during execution."""

    operation_id: str = Field(default_factory=_new_operation_id)
    module: OperationModule
    status: OperationStatus = OperationStatus.QUEUED
    target: str
    standard: Optional[EraseStandard] = None
    operator_id: str
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = "initialising"
    message: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[dict[str, Any]] = None

    model_config = ConfigDict(use_enum_values=True)


class ProgressEvent(BaseModel):
    """WebSocket / SSE progress event payload."""

    operation_id: str
    stage: str
    progress: int = Field(ge=0, le=100)
    message: str
    status: OperationStatus
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidationResult(BaseModel):
    """Structured result from the target validator."""

    allowed: bool
    safe_mode: bool
    device: str
    reason: str
    risk_level: RiskLevel
    checks_passed: list[str] = Field(default_factory=list)
    checks_failed: list[str] = Field(default_factory=list)
    media_type: MediaType = MediaType.UNKNOWN
    is_mounted: bool = False
    is_system_disk: bool = False
    is_loopback: bool = False
    backing_file: Optional[str] = None


class VerificationResult(BaseModel):
    """Result of post-erase sector/offset sampling verification."""

    status: VerificationStatus
    samples_total: int = 0
    samples_passed: int = 0
    samples_failed: int = 0
    offsets_checked: list[int] = Field(default_factory=list)
    evidence_hash: Optional[str] = None
    note: str = (
        "Verification sampled regions only. "
        "This does not prove every physical sector was sanitised."
    )


class OperationSummary(BaseModel):
    """Compact operation summary for list views."""

    operation_id: str
    module: OperationModule
    status: OperationStatus
    target: str
    standard: Optional[EraseStandard] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    verification: Optional[VerificationStatus] = None
    audit_hash: Optional[str] = None
