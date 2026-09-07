"""
audit/models.py — Pydantic models for audit records and hash-chain verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AuditRecord(BaseModel):
    """
    A single tamper-evident audit record.

    The current_hash is computed as:
        SHA256(
            canonical_json(record_without_current_hash)
            + previous_hash
        )

    The first record in the chain uses previous_hash = "GENESIS".
    """

    model_config = ConfigDict(populate_by_name=True)

    # Sequence number — 1-based, monotonically increasing.
    sequence: int

    # Globally unique operation identifier.
    operation_id: str

    # When the record was created.
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Who performed the operation.
    operator_id: str

    # Which module generated this record.
    module: str

    # Human-readable description of what happened.
    action: str

    # Target device/file/path.
    target: str

    # Device serial or image path for additional identification.
    device_identifier: Optional[str] = None

    # Sanitisation standard used, if applicable.
    standard: Optional[str] = None

    # ISO-8601 timestamps for the operation itself.
    operation_started_at: Optional[datetime] = None
    operation_finished_at: Optional[datetime] = None

    # Outcome.
    result: str  # "SUCCESS" | "FAILURE" | "CANCELLED" | "INFO"

    # Post-operation verification outcome.
    verification_result: Optional[str] = None

    # Hash chain.
    previous_hash: str   # "GENESIS" for the first record
    current_hash: str    # Computed — see hash_chain.py

    # Optional arbitrary metadata (JSON-serialisable).
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChainVerificationResult(BaseModel):
    """Result of a full audit chain integrity verification."""

    valid: bool
    checked_records: int
    first_invalid_sequence: Optional[int] = None
    first_invalid_operation_id: Optional[str] = None
    reason: Optional[str] = None
    details: list[str] = Field(default_factory=list)
