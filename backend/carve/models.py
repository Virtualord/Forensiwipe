"""
carve/models.py — Pydantic models for Module 3: Advanced File Carving.

All carved objects are immutable after creation — the scanner writes once,
the API reads. The source evidence image is never modified.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class CarvedFileType(str, Enum):
    JPEG   = "JPEG"
    PNG    = "PNG"
    PDF    = "PDF"
    ZIP    = "ZIP"
    DOCX   = "DOCX"
    XLSX   = "XLSX"
    PPTX   = "PPTX"
    UNKNOWN = "UNKNOWN"


class CarvingMethod(str, Enum):
    SIGNATURE      = "SIGNATURE"       # Header/footer match only
    VALIDATED      = "VALIDATED"       # + structural validation
    DECODER        = "DECODER"         # + successful decoder round-trip
    RECONSTRUCTED  = "RECONSTRUCTED"   # Fragment heuristic reconstruction


class ValidationStatus(str, Enum):
    PASSED  = "PASSED"
    FAILED  = "FAILED"
    SKIPPED = "SKIPPED"
    PARTIAL = "PARTIAL"


class ScanStatus(str, Enum):
    QUEUED     = "QUEUED"
    RUNNING    = "RUNNING"
    COMPLETED  = "COMPLETED"
    FAILED     = "FAILED"
    CANCELLED  = "CANCELLED"


# ── Per-file models ───────────────────────────────────────────────────────────

class ConfidenceBreakdown(BaseModel):
    """Itemised heuristic forensic confidence score (0–100)."""
    model_config = ConfigDict(populate_by_name=True)

    header_match:        int = 0   # max 25
    footer_match:        int = 0   # max 20
    structure_valid:     int = 0   # max 25
    decoder_validation:  int = 0   # max 20
    entropy_plausible:   int = 0   # max 10
    total:               int = 0   # sum, capped at 100

    note: str = (
        "Heuristic forensic confidence score. "
        "Not a machine-learning probability. "
        "Higher scores indicate more structural evidence of a valid file."
    )


class FragmentInfo(BaseModel):
    """Metadata about a fragmentation reconstruction attempt."""
    model_config = ConfigDict(populate_by_name=True)

    attempted:          bool = False
    candidates_found:   int  = 0
    best_candidate_offset: Optional[int] = None
    decoder_validation: ValidationStatus = ValidationStatus.SKIPPED
    result:             str  = ""   # "ACCEPTED" | "REJECTED" | "NOT_ATTEMPTED"


class CarvedFile(BaseModel):
    """
    A single file recovered from the evidence image.

    Recovered files are written to:
        recovered/<operation_id>/<index>_<type>_<offset>.ext
    The source evidence image is never modified.
    """
    model_config = ConfigDict(populate_by_name=True)

    index:            int                      # 0-based position in this scan
    file_type:        CarvedFileType
    offset:           int                      # byte offset in evidence image
    size:             int                      # bytes
    size_human:       str                      # e.g. "182.4 KB"
    sha256:           Optional[str]  = None
    output_path:      Optional[str]  = None    # absolute path to saved file
    carving_method:   CarvingMethod  = CarvingMethod.SIGNATURE
    confidence:       int            = 0       # 0–100
    confidence_breakdown: ConfidenceBreakdown  = Field(default_factory=ConfidenceBreakdown)
    structure_valid:  ValidationStatus = ValidationStatus.SKIPPED
    decoder_valid:    ValidationStatus = ValidationStatus.SKIPPED
    entropy:          Optional[float] = None   # bits/byte
    entropy_label:    str             = ""     # e.g. "plausible compressed data"
    fragment:         FragmentInfo    = Field(default_factory=FragmentInfo)
    notes:            list[str]       = Field(default_factory=list)
    extension:        str             = ""


class ScanProgress(BaseModel):
    """Live progress snapshot for WebSocket / polling."""
    model_config = ConfigDict(populate_by_name=True)

    operation_id:    str
    status:          ScanStatus
    bytes_scanned:   int   = 0
    total_bytes:     int   = 0
    progress_pct:    int   = 0
    scan_speed_mbps: float = 0.0
    matches_found:   int   = 0
    validated:       int   = 0
    rejected:        int   = 0
    fragments:       int   = 0
    current_offset:  int   = 0
    message:         str   = ""


class ScanResult(BaseModel):
    """Complete result of a carving scan operation."""
    model_config = ConfigDict(populate_by_name=True)

    operation_id:       str
    evidence_path:      str
    evidence_sha256_before: Optional[str] = None
    evidence_sha256_after:  Optional[str] = None
    evidence_integrity: str = ""    # "PRESERVED" | "COMPROMISED" | "UNKNOWN"

    scan_started_at:    Optional[datetime] = None
    scan_finished_at:   Optional[datetime] = None
    total_bytes:        int   = 0
    bytes_scanned:      int   = 0

    files_found:        int   = 0
    files_validated:    int   = 0
    files_rejected:     int   = 0
    fragments_attempted: int  = 0

    carved_files:       list[CarvedFile] = Field(default_factory=list)
    output_directory:   Optional[str]    = None
    status:             ScanStatus       = ScanStatus.QUEUED
    error:              Optional[str]    = None

    audit_sequence:     Optional[int]    = None
    audit_hash:         Optional[str]    = None
