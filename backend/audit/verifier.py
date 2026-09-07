"""
audit/verifier.py — Full audit chain integrity verification.

Reads every record from the database, recomputes each hash from scratch,
and verifies:
  1. Each record's current_hash matches the re-derived value.
  2. Each record's previous_hash equals the current_hash of the record before it.
  3. The first record's previous_hash is GENESIS.
  4. No records are missing (gap detection via sequence numbers).

This is the feature that makes tamper-detection demonstrable at the hackathon.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from backend.audit import database
from backend.audit.hash_chain import (
    GENESIS_HASH,
    canonical_json,
    compute_record_hash,
    verify_record_hash,
)
from backend.audit.models import ChainVerificationResult

logger = logging.getLogger("forensiwipe.audit.verifier")


def _row_to_hash_input(row: dict) -> dict[str, Any]:
    """
    Convert a raw database row dict into the fields that were hashed when
    the record was originally created.

    The current_hash field itself is excluded from the hash input.
    The metadata field is stored as JSON string in SQLite — parse it back.
    """
    data = dict(row)
    data.pop("sequence", None)     # sequence is DB-assigned, not hashed
    data.pop("current_hash", None) # excluded from its own hash

    # Parse metadata JSON string back to dict if needed.
    if isinstance(data.get("metadata"), str):
        try:
            data["metadata"] = json.loads(data["metadata"])
        except (json.JSONDecodeError, TypeError):
            data["metadata"] = {}

    return data


async def verify_chain() -> ChainVerificationResult:
    """
    Re-derive and verify the entire audit hash chain.

    Returns a ChainVerificationResult describing whether the chain is intact.
    """
    records = await database.get_all_records()
    details: list[str] = []

    if not records:
        return ChainVerificationResult(
            valid=True,
            checked_records=0,
            reason="No audit records found — chain is empty.",
            details=["Chain is empty; nothing to verify."],
        )

    expected_previous = GENESIS_HASH
    expected_sequence = records[0]["sequence"]

    for i, row in enumerate(records):
        seq = row["sequence"]
        op_id = row["operation_id"]

        # ── Gap detection ─────────────────────────────────────────────────────
        if seq != expected_sequence:
            return ChainVerificationResult(
                valid=False,
                checked_records=i,
                first_invalid_sequence=seq,
                first_invalid_operation_id=op_id,
                reason=(
                    f"Sequence gap detected: expected {expected_sequence}, "
                    f"found {seq}. Records may have been deleted or reordered."
                ),
                details=details,
            )

        # ── Previous hash linkage check ───────────────────────────────────────
        stored_previous = row["previous_hash"]
        if stored_previous != expected_previous:
            return ChainVerificationResult(
                valid=False,
                checked_records=i,
                first_invalid_sequence=seq,
                first_invalid_operation_id=op_id,
                reason=(
                    f"Previous-hash mismatch at sequence {seq}. "
                    f"Expected '{expected_previous[:16]}...', "
                    f"found '{stored_previous[:16]}...'. "
                    "Record may have been reordered or chain broken."
                ),
                details=details,
            )

        # ── Hash recomputation ────────────────────────────────────────────────
        claimed_hash = row["current_hash"]
        hash_input = _row_to_hash_input(row)
        recomputed = compute_record_hash(hash_input, expected_previous)

        if recomputed != claimed_hash:
            return ChainVerificationResult(
                valid=False,
                checked_records=i,
                first_invalid_sequence=seq,
                first_invalid_operation_id=op_id,
                reason=(
                    f"Hash mismatch at sequence {seq} (operation {op_id}). "
                    "Record content has been modified after creation."
                ),
                details=details,
            )

        details.append(f"Sequence {seq}: OK  ({claimed_hash[:16]}...)")
        expected_previous = claimed_hash
        expected_sequence = seq + 1

    return ChainVerificationResult(
        valid=True,
        checked_records=len(records),
        reason="All records verified — chain is intact.",
        details=details,
    )
