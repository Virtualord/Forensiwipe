"""
api/operations.py — Operation lifecycle management endpoints.

GET    /api/operations                — List all operations
GET    /api/operations/{id}           — Get single operation with full detail
POST   /api/operations/{id}/cancel    — Request cancellation
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.core.models import OperationRecord, OperationStatus
from backend.core import tasks as task_store

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.operations")


class CancelResponse(BaseModel):
    operation_id: str
    cancelled: bool
    message: str


@router.get("", response_model=list[OperationRecord], summary="List all operations")
async def list_operations() -> list[OperationRecord]:
    """Return all operations in reverse chronological order (most recent first)."""
    return await task_store.list_operations()


@router.get("/{operation_id}", response_model=OperationRecord, summary="Get operation status")
async def get_operation(operation_id: str) -> OperationRecord:
    """
    Return the current state of a specific operation.

    Poll this endpoint for progress updates, or use the WebSocket endpoint
    for real-time events.
    """
    op = await task_store.get_operation(operation_id)
    if op is None:
        raise HTTPException(
            status_code=404,
            detail=f"Operation '{operation_id}' not found.",
        )
    return op


@router.post("/{operation_id}/cancel", response_model=CancelResponse, summary="Cancel operation")
async def cancel_operation(operation_id: str) -> CancelResponse:
    """
    Request cancellation of a running or queued operation.

    Cancellation is best-effort — the running erase coroutine checks the
    status flag between write blocks. A COMPLETED operation cannot be cancelled.
    """
    op = await task_store.get_operation(operation_id)
    if op is None:
        raise HTTPException(
            status_code=404,
            detail=f"Operation '{operation_id}' not found.",
        )

    if op.status in (OperationStatus.COMPLETED, OperationStatus.FAILED):
        return CancelResponse(
            operation_id=operation_id,
            cancelled=False,
            message=f"Operation is already in terminal state: {op.status}.",
        )

    cancelled = await task_store.cancel_operation(operation_id)
    logger.info("cancel_request op=%s result=%s", operation_id, cancelled)

    return CancelResponse(
        operation_id=operation_id,
        cancelled=cancelled,
        message=(
            "Cancellation requested. The operation will stop at the next safe checkpoint."
            if cancelled else
            "Cancellation not possible in the current state."
        ),
    )
