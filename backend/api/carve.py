"""
api/carve.py — File carving API endpoints (Module 3).

POST /api/carve/scan              — Start a carving scan (async background task)
GET  /api/carve/{op_id}/results   — Full ScanResult for a completed scan
GET  /api/carve/{op_id}/files     — List of CarvedFile objects only
GET  /api/carve/{op_id}/status    — Lightweight ScanProgress poll endpoint
POST /api/carve/integrity         — Verify evidence file integrity (hash check)

The evidence image is ALWAYS opened read-only.
The source image is NEVER modified by any carving operation.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from backend.carve.hashing import sha256_file, verify_evidence_integrity
from backend.carve.models import CarvedFile, ScanResult, ScanStatus
from backend.carve.scanner import run_scan
from backend.core import tasks as task_store
from backend.core.config import get_settings
from backend.core.models import OperationModule, OperationRecord, OperationStatus

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.carve")

# In-memory scan result store (keyed by operation_id).
# For Phase 4 this would persist to SQLite; for now the ScanResult lives in RAM.
_scan_results: dict[str, ScanResult] = {}


# ── Request / Response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    evidence_path: str
    operator_id: Optional[str] = None


class IntegrityCheckRequest(BaseModel):
    evidence_path: str
    expected_sha256: str


class IntegrityCheckResponse(BaseModel):
    evidence_path: str
    expected_sha256: str
    actual_sha256: Optional[str]
    intact: bool
    message: str


class ScanStartedResponse(BaseModel):
    operation_id: str
    status: str
    evidence_path: str
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanStartedResponse, summary="Start carving scan")
async def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanStartedResponse:
    """
    Start a forensic file-carving scan on an evidence image.

    The scan runs as a background task.  Monitor progress via:
    - GET /api/carve/{operation_id}/status  (polling)
    - WS  /ws/operations/{operation_id}     (real-time)

    The evidence image is opened read-only.  It is never modified.
    """
    evidence_path = req.evidence_path
    settings = get_settings()

    # Basic path validation
    p = Path(evidence_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Evidence file not found: {evidence_path}")
    if not p.is_file():
        raise HTTPException(status_code=422, detail=f"Evidence path is not a file: {evidence_path}")

    logger.info("carve_scan_request evidence=%s", evidence_path)

    # Create operation record
    operation = OperationRecord(
        module=OperationModule.CARVE,
        target=evidence_path,
        operator_id=req.operator_id or settings.operator_id,
        status=OperationStatus.QUEUED,
    )
    await task_store.register_operation(operation)

    op_id = operation.operation_id

    # Set up output directory
    output_dir = settings.recovered_dir / op_id

    # Progress bridge: scanner → task_store progress events
    async def _progress(prog) -> None:
        await task_store.update_progress(
            op_id,
            prog.progress_pct,
            "scanning",
            prog.message,
            OperationStatus.RUNNING if prog.status == ScanStatus.RUNNING else None,
        )

    async def _run():
        try:
            await task_store.update_progress(op_id, 1, "starting", "Initialising scan…", OperationStatus.RUNNING)
            result = await run_scan(
                evidence_path=evidence_path,
                operation_id=op_id,
                output_dir=output_dir,
                progress_callback=_progress,
                operator_id=req.operator_id or settings.operator_id,
            )
            _scan_results[op_id] = result
            if result.status == ScanStatus.COMPLETED:
                await task_store.complete_operation(op_id, {"files_found": result.files_found})
            else:
                await task_store.fail_operation(op_id, result.error or "Scan failed")
        except Exception as exc:
            logger.exception("carve_background_error op=%s", op_id)
            await task_store.fail_operation(op_id, str(exc))

    background_tasks.add_task(_run)

    logger.info("carve_scan_queued op=%s evidence=%s", op_id, evidence_path)

    return ScanStartedResponse(
        operation_id=op_id,
        status="QUEUED",
        evidence_path=evidence_path,
        message=f"Scan queued. Monitor at GET /api/carve/{op_id}/status",
    )


@router.get("/{operation_id}/results", response_model=ScanResult, summary="Full scan result")
async def get_scan_result(operation_id: str) -> ScanResult:
    """
    Return the complete ScanResult for a finished scan, including all CarvedFile objects.

    Only available after status = COMPLETED.
    """
    result = _scan_results.get(operation_id)
    if result is None:
        op = await task_store.get_operation(operation_id)
        if op is None:
            raise HTTPException(status_code=404, detail=f"Operation '{operation_id}' not found.")
        if op.status not in (OperationStatus.COMPLETED, OperationStatus.FAILED):
            raise HTTPException(
                status_code=202,
                detail=f"Scan still in progress. Status: {op.status}",
            )
        raise HTTPException(status_code=404, detail="Scan result not available.")
    return result


@router.get("/{operation_id}/files", response_model=list[CarvedFile], summary="List carved files")
async def list_carved_files(operation_id: str) -> list[CarvedFile]:
    """
    Return only the list of recovered CarvedFile objects for a completed scan.
    Lighter than /results — suitable for the results table in the UI.
    """
    result = _scan_results.get(operation_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No results for operation '{operation_id}'.")
    return result.carved_files


@router.get("/{operation_id}/status", summary="Scan progress (polling)")
async def get_scan_status(operation_id: str) -> dict:
    """
    Lightweight polling endpoint for scan progress.
    Returns current status, progress%, and summary counts.
    """
    op = await task_store.get_operation(operation_id)
    if op is None:
        raise HTTPException(status_code=404, detail=f"Operation '{operation_id}' not found.")

    result = _scan_results.get(operation_id)
    return {
        "operation_id": operation_id,
        "status": op.status,
        "progress": op.progress,
        "stage": op.current_stage,
        "message": op.message,
        "files_found": result.files_found if result else 0,
        "files_validated": result.files_validated if result else 0,
        "evidence_integrity": result.evidence_integrity if result else "",
    }


@router.post("/integrity", response_model=IntegrityCheckResponse, summary="Verify evidence integrity")
async def check_evidence_integrity(req: IntegrityCheckRequest) -> IntegrityCheckResponse:
    """
    Verify that an evidence file's SHA-256 matches an expected hash.

    Used to confirm the evidence image has not been modified since the
    original hash was recorded.
    """
    p = Path(req.evidence_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Evidence file not found: {req.evidence_path}")

    intact, actual = verify_evidence_integrity(req.evidence_path, req.expected_sha256)

    return IntegrityCheckResponse(
        evidence_path=req.evidence_path,
        expected_sha256=req.expected_sha256,
        actual_sha256=actual,
        intact=intact,
        message="Evidence integrity preserved." if intact else
                "CRITICAL: Evidence hash mismatch — file may have been modified.",
    )
