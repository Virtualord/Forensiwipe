"""
audit/service.py — High-level audit service used by all modules.

Every destructive or significant operation calls audit_service.record(...)
to append a new entry to the hash chain.  This is the only way to write
audit records — modules never access the database or hash chain directly.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from backend.audit import database
from backend.audit.hash_chain import GENESIS_HASH, compute_record_hash
from backend.core.config import get_settings

logger = logging.getLogger("forensiwipe.audit.service")

# Fetching the previous hash and inserting the next record must be one atomic
# application-level action. SQLite serialises writes, but cannot by itself stop
# two coroutines from deriving their record from the same previous hash.
_append_lock = asyncio.Lock()


async def record(
    operation_id: str,
    module: str,
    action: str,
    target: str,
    result: str,
    *,
    operator_id: Optional[str] = None,
    device_identifier: Optional[str] = None,
    standard: Optional[str] = None,
    operation_started_at: Optional[datetime] = None,
    operation_finished_at: Optional[datetime] = None,
    verification_result: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict:
    """
    Append a new tamper-evident audit record to the hash chain.

    Steps:
    1. Fetch the previous (most recent) hash from the database.
    2. Assemble the record fields (without current_hash).
    3. Compute current_hash using the hash chain formula.
    4. Insert the complete record into the database.
    5. Return the full record dict including the assigned sequence number.
    """
    async with _append_lock:
        return await _record_locked(
            operation_id, module, action, target, result,
            operator_id=operator_id,
            device_identifier=device_identifier,
            standard=standard,
            operation_started_at=operation_started_at,
            operation_finished_at=operation_finished_at,
            verification_result=verification_result,
            metadata=metadata,
        )


async def _record_locked(
    operation_id: str, module: str, action: str, target: str, result: str,
    *, operator_id: Optional[str], device_identifier: Optional[str],
    standard: Optional[str], operation_started_at: Optional[datetime],
    operation_finished_at: Optional[datetime], verification_result: Optional[str],
    metadata: Optional[dict[str, Any]],
) -> dict:
    """Append one record while the chain append lock is held."""
    settings = get_settings()
    op_id = operator_id or settings.operator_id
    now = datetime.now(timezone.utc)

    # ── Fetch previous hash ───────────────────────────────────────────────────
    previous_hash = await database.get_latest_hash()

    # ── Build record data (without current_hash) ──────────────────────────────
    record_data: dict[str, Any] = {
        "operation_id": operation_id,
        "timestamp": now.isoformat(),
        "operator_id": op_id,
        "module": module,
        "action": action,
        "target": target,
        "device_identifier": device_identifier,
        "standard": standard,
        "operation_started_at": operation_started_at.isoformat() if operation_started_at else None,
        "operation_finished_at": operation_finished_at.isoformat() if operation_finished_at else None,
        "result": result,
        "verification_result": verification_result,
        "previous_hash": previous_hash,
        "metadata": metadata or {},
    }

    # ── Compute current hash ─────────────────────────────────────────────────
    current_hash = compute_record_hash(record_data, previous_hash)
    record_data["current_hash"] = current_hash

    # ── Persist ───────────────────────────────────────────────────────────────
    sequence = await database.insert_record(record_data)
    record_data["sequence"] = sequence

    logger.info(
        "audit_record_created sequence=%d op=%s module=%s action=%s result=%s",
        sequence, operation_id, module, action, result,
    )

    return record_data
