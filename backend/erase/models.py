"""
erase/models.py — Pydantic models specific to the drive-erase module.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.core.models import (
    EraseStandard,
    MediaType,
    OperationRecord,
    RiskLevel,
    ValidationResult,
    VerificationResult,
)


class DeviceInfo(BaseModel):
    """Discovered storage device descriptor."""

    path: str                              # e.g. /dev/sda or /dev/loop0
    name: str                              # Short name, e.g. sda
    model: Optional[str] = None
    serial: Optional[str] = None
    size_bytes: int = 0
    size_human: str = "0 B"
    media_type: MediaType = MediaType.UNKNOWN
    is_removable: bool = False
    is_system_disk: bool = False
    is_loopback: bool = False
    is_mounted: bool = False
    mount_points: list[str] = Field(default_factory=list)
    filesystem: Optional[str] = None
    backing_file: Optional[str] = None    # For loopback devices
    safety_status: str = "UNKNOWN"        # "SAFE" | "BLOCKED" | "UNKNOWN"
    safety_reason: str = ""


class EraseRequest(BaseModel):
    """Incoming API request to start a drive-erase operation."""

    target: str                            # Device path
    standard: EraseStandard
    operator_id: Optional[str] = None
    # Exact confirmation string — must equal target path for physical devices.
    confirmation: Optional[str] = None
    # Second confirmation required for physical devices.
    second_confirmation: Optional[str] = None
    # Demo mode: simulate progress animation without actual write
    demo_mode: bool = False


class EraseResult(BaseModel):
    """Final result of a completed drive-erase operation."""

    operation_id: str
    target: str
    standard: EraseStandard
    validation: ValidationResult
    verification: VerificationResult
    sha256_before: Optional[str] = None   # Only meaningful for image files
    sha256_after: Optional[str] = None
    bytes_written: int = 0
    passes_completed: int = 0
    audit_sequence: Optional[int] = None
    audit_hash: Optional[str] = None
    simulated: bool = False               # True for demo/simulation runs
    notes: list[str] = Field(default_factory=list)


class StandardInfo(BaseModel):
    """Metadata about an erasure standard for display in the UI."""

    id: EraseStandard
    name: str
    description: str
    passes: int
    hdd_applicable: bool
    ssd_applicable: bool
    hardware_dependent: bool
    nist_approved: bool
    notes: list[str] = Field(default_factory=list)
    warning: Optional[str] = None
