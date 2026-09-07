"""
api/erase.py — Drive erasure API endpoints.

POST /api/erase/validate        — Validate a target (dry run, no writes)
POST /api/erase/start           — Start an erase operation (async background task)
GET  /api/erase/standards       — List available erasure standards with metadata
POST /api/erase/confirm         — Two-phase confirmation for physical targets
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from backend.core.config import get_settings
from backend.core.models import (
    EraseStandard,
    OperationModule,
    OperationRecord,
    OperationStatus,
    ValidationResult,
)
from backend.core.security import ConfirmationError, validate_exact_confirmation
from backend.core import tasks as task_store
from backend.erase import target_validator
from backend.erase.engine import run_erase
from backend.erase.models import EraseRequest, StandardInfo
from backend.erase.standards import list_standards

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.erase")


# ── Request / Response models ─────────────────────────────────────────────────

class ValidateRequest(BaseModel):
    target: str


class StartEraseRequest(BaseModel):
    target: str
    standard: EraseStandard
    operator_id: Optional[str] = None
    # Exact target path confirmation (required for physical devices, accepted for demo)
    confirmation: Optional[str] = None
    # Second confirmation — required for physical devices only
    second_confirmation: Optional[str] = None
    # When True, simulates progress without actual writes
    demo_mode: bool = False


class EraseStartedResponse(BaseModel):
    operation_id: str
    status: OperationStatus
    target: str
    standard: EraseStandard
    message: str
    simulated: bool


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/standards", response_model=list[StandardInfo], summary="List erasure standards")
async def get_standards() -> list[StandardInfo]:
    """
    Return all available erasure standards with descriptions and applicability flags.

    The UI should display warnings for hardware-dependent standards.
    """
    return list_standards()


@router.post("/validate", response_model=ValidationResult, summary="Validate erase target")
async def validate_target(req: ValidateRequest) -> ValidationResult:
    """
    Run all 12 validation checks against a target path without making any writes.

    Use this before showing the confirmation step in the UI.
    Returns a ValidationResult — check `allowed` before proceeding.
    """
    logger.info("validate_request target=%s", req.target)
    result = target_validator.validate_target(req.target, operator_approved=False)
    return result


@router.post("/start", response_model=EraseStartedResponse, summary="Start erase operation")
async def start_erase(
    req: StartEraseRequest,
    background_tasks: BackgroundTasks,
) -> EraseStartedResponse:
    """
    Start a secure erase operation.

    The operation runs as a background task and can be monitored via:
    - GET /api/operations/{operation_id}
    - WebSocket /ws/operations/{operation_id}

    **Confirmation rules:**
    - Safe mode / demo: confirmation is accepted but not strictly required.
    - Physical device (safe mode off): `confirmation` must equal the exact target path.
    - Physical device: `second_confirmation` must also equal the exact target path.

    Returns immediately with operation_id and QUEUED status.
    """
    settings = get_settings()
    target = req.target

    logger.info(
        "erase_start_request target=%s standard=%s demo=%s",
        target, req.standard, req.demo_mode,
    )

    # ── Pre-validate before touching the task store ───────────────────────────
    # operator_approved=False here so check 11 can be evaluated separately below
    validation = target_validator.validate_target(target, operator_approved=False)

    # For physical erase, confirmation is mandatory and must be exact.
    if settings.physical_erase_enabled and not validation.is_loopback:
        if not req.confirmation:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Physical device erase requires explicit confirmation. "
                    f"Type the exact target path '{target}' in the confirmation field."
                ),
            )
        try:
            validate_exact_confirmation(target, req.confirmation)
        except ConfirmationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        if not req.second_confirmation:
            raise HTTPException(
                status_code=422,
                detail="Physical device erase requires a second confirmation.",
            )
        try:
            validate_exact_confirmation(target, req.second_confirmation)
        except ConfirmationError as exc:
            raise HTTPException(status_code=422, detail=f"Second confirmation failed: {exc}")

    # Re-validate with operator_approved=True now that confirmation is satisfied.
    validation = target_validator.validate_target(target, operator_approved=True)

    if not validation.allowed:
        logger.warning("erase_blocked target=%s reason=%s", target, validation.reason)
        raise HTTPException(
            status_code=403,
            detail={
                "blocked": True,
                "reason": validation.reason,
                "risk_level": validation.risk_level,
                "safe_mode": validation.safe_mode,
            },
        )

    # ── Create operation record ───────────────────────────────────────────────
    operation = OperationRecord(
        module=OperationModule.DRIVE_ERASE,
        target=target,
        standard=req.standard,
        operator_id=req.operator_id or settings.operator_id,
        status=OperationStatus.QUEUED,
    )
    await task_store.register_operation(operation)

    erase_request = EraseRequest(
        target=target,
        standard=req.standard,
        operator_id=req.operator_id or settings.operator_id,
        confirmation=req.confirmation,
        second_confirmation=req.second_confirmation,
        demo_mode=req.demo_mode,
    )

    # ── Dispatch background task ──────────────────────────────────────────────
    async def _run():
        try:
            await run_erase(erase_request, operation.operation_id)
        except Exception as exc:
            logger.exception("background_erase_error op=%s", operation.operation_id)

    background_tasks.add_task(_run)

    logger.info(
        "erase_queued op=%s target=%s standard=%s",
        operation.operation_id, target, req.standard,
    )

    is_simulated = req.demo_mode or req.standard in (
        EraseStandard.NIST_PURGE, EraseStandard.CRYPTO_ERASE
    )

    return EraseStartedResponse(
        operation_id=operation.operation_id,
        status=OperationStatus.QUEUED,
        target=target,
        standard=req.standard,
        message=(
            "[SIMULATED] Operation queued. No actual writes will occur."
            if is_simulated else
            f"Operation queued. Monitoring: GET /api/operations/{operation.operation_id}"
        ),
        simulated=is_simulated,
    )
