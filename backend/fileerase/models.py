"""
fileerase/models.py — Pydantic models for Module 2: Secure File & Folder Eraser.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class FileEraseStandard(str, Enum):
    ZERO_FILL   = "ZERO_FILL"
    RANDOM_FILL = "RANDOM_FILL"
    DOD_3PASS   = "DOD_3PASS"


class FilesystemSupport(str, Enum):
    """Capability level badge for a detected filesystem type."""
    FULL    = "FULL"      # 🟢 Fully tested prototype support
    PARTIAL = "PARTIAL"   # 🟡 Detection / interface; advanced sanitisation limited
    STUB    = "STUB"      # 🟡 Detection / interface stub
    DETECT  = "DETECT"    # ⚪ Detection only


class MetadataStatus(str, Enum):
    REMOVED       = "REMOVED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED        = "FAILED"
    UNSUPPORTED   = "UNSUPPORTED"


class ResidualStatus(str, Enum):
    FOUND         = "FOUND"
    REMOVED       = "REMOVED"
    NOT_ACCESSIBLE = "NOT_ACCESSIBLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_APPLICABLE  = "NOT_APPLICABLE"
    CLEAN           = "CLEAN"


class FileEraseStatus(str, Enum):
    SUCCESS   = "SUCCESS"
    FAILED    = "FAILED"
    SKIPPED   = "SKIPPED"


# ── Per-file result ───────────────────────────────────────────────────────────

class MetadataResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    status:  MetadataStatus
    removed_fields: list[str]  = Field(default_factory=list)
    note:    str = ""


class ResidualFinding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    location:     str         # which store was checked
    status:       ResidualStatus
    detail:       str = ""


class FileEraseResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    path:            str
    size_bytes:      int  = 0
    sha256_before:   Optional[str] = None
    file_type:       str = ""
    filesystem:      str = ""
    erase_status:    FileEraseStatus = FileEraseStatus.SUCCESS
    passes_written:  int  = 0
    bytes_written:   int  = 0
    metadata:        MetadataResult = Field(
        default_factory=lambda: MetadataResult(
            status=MetadataStatus.NOT_APPLICABLE,
            note="Metadata sanitisation was not evaluated.",
        )
    )
    residuals:       list[ResidualFinding] = Field(default_factory=list)
    error:           Optional[str] = None
    notes:           list[str] = Field(default_factory=list)


# ── Operation-level models ────────────────────────────────────────────────────

class FileEraseRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    paths:       list[str]           # files and/or directories
    standard:    FileEraseStandard = FileEraseStandard.ZERO_FILL
    recursive:   bool = True
    glob_pattern: Optional[str] = None
    sanitise_metadata: bool = True
    scan_residuals:    bool = True
    operator_id: Optional[str] = None
    demo_mode:   bool = False        # simulate without actual writes


class FileErasePreview(BaseModel):
    """Dry-run preview — no writes."""
    model_config = ConfigDict(populate_by_name=True)
    files:              list[str]
    total_files:        int
    total_size_bytes:   int
    total_size_human:   str
    filesystem:         str
    filesystem_support: FilesystemSupport
    metadata_available: bool
    residual_scan_available: bool
    warnings:           list[str] = Field(default_factory=list)


class FileEraseOperationResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    operation_id:    str
    standard:        FileEraseStandard
    total_files:     int   = 0
    succeeded:       int   = 0
    failed:          int   = 0
    skipped:         int   = 0
    total_bytes:     int   = 0
    directories_removed: int = 0
    directories_not_empty: int = 0
    file_results:    list[FileEraseResult] = Field(default_factory=list)
    residual_summary: list[ResidualFinding] = Field(default_factory=list)
    audit_sequence:  Optional[int] = None
    audit_hash:      Optional[str] = None
    simulated:       bool = False
    notes:           list[str] = Field(default_factory=list)


# ── Filesystem capability badge ───────────────────────────────────────────────

class FilesystemBadge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name:        str
    support:     FilesystemSupport
    icon:        str   # emoji
    description: str
    limitations: list[str] = Field(default_factory=list)
