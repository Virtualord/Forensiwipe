"""
api/audit.py — Audit log and hash-chain verification endpoints.

GET  /api/audit/history              — Paginated audit record list
GET  /api/audit/history/{op_id}      — Records for a specific operation
POST /api/audit/verify               — Full chain integrity verification
GET  /api/audit/latest-hash          — Current chain head hash (for live display)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.audit import database as audit_db
from backend.audit import verifier as audit_verifier
from backend.audit.models import AuditRecord, ChainVerificationResult

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.audit")


class LatestHashResponse(BaseModel):
    latest_hash: str
    record_count: int


@router.get(
    "/history",
    response_model=list[dict],
    summary="Audit record history",
)
async def get_audit_history(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """
    Return paginated audit records, most recent first.

    Each record includes its position in the hash chain (sequence, previous_hash,
    current_hash) so the UI can display the chain linkage.
    """
    all_records = await audit_db.get_all_records()
    # Return newest first for the UI
    reversed_records = list(reversed(all_records))
    page = reversed_records[offset: offset + limit]
    logger.info("audit_history_request limit=%d offset=%d returned=%d", limit, offset, len(page))
    return page


@router.get(
    "/history/{operation_id}",
    response_model=list[dict],
    summary="Audit records for a specific operation",
)
async def get_operation_audit(operation_id: str) -> list[dict]:
    """Return all audit records for a specific operation_id."""
    records = await audit_db.get_records_for_operation(operation_id)
    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"No audit records found for operation '{operation_id}'.",
        )
    return records


@router.post(
    "/verify",
    response_model=ChainVerificationResult,
    summary="Verify audit chain integrity",
)
async def verify_audit_chain() -> ChainVerificationResult:
    """
    Recompute the entire audit hash chain from genesis and verify every record.

    Detects:
    - Modified records (hash mismatch)
    - Deleted records (sequence gap)
    - Reordered records (previous-hash mismatch)
    - Broken chain links

    This is the primary tamper-detection endpoint.
    The frontend AUDIT INTEGRITY dashboard card calls this.
    """
    logger.info("audit_chain_verify_requested")
    result = await audit_verifier.verify_chain()
    logger.info(
        "audit_chain_verify_complete valid=%s checked=%d",
        result.valid, result.checked_records,
    )
    return result


@router.get(
    "/latest-hash",
    response_model=LatestHashResponse,
    summary="Current chain head hash",
)
async def get_latest_hash() -> LatestHashResponse:
    """
    Return the current_hash of the most recent audit record.

    Used by the dashboard to display the live chain head.
    """
    all_records = await audit_db.get_all_records()
    latest = await audit_db.get_latest_hash()
    return LatestHashResponse(
        latest_hash=latest,
        record_count=len(all_records),
    )
