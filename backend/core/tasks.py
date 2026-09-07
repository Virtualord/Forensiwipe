"""
core/tasks.py — In-memory operation registry and task lifecycle management.

Every long-running operation is tracked here. The registry acts as a
lightweight job store — it does NOT persist across restarts (the audit DB
is the persistence layer). Operations are keyed by operation_id.

Thread safety: asyncio.Lock guards all mutations. The registry is accessed
from async route handlers and background asyncio tasks.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Callable, Coroutine, Optional

from backend.core.models import (
    OperationModule,
    OperationRecord,
    OperationStatus,
    ProgressEvent,
)

logger = logging.getLogger("forensiwipe.tasks")

# ── Registry ──────────────────────────────────────────────────────────────────

_registry: dict[str, OperationRecord] = {}
_lock = asyncio.Lock()

# Progress listeners: operation_id → list of async callables that receive ProgressEvent
_listeners: dict[str, list[Callable[[ProgressEvent], Coroutine]]] = {}


async def register_operation(operation: OperationRecord) -> OperationRecord:
    """Add a new operation to the registry. Raises if ID already exists."""
    async with _lock:
        if operation.operation_id in _registry:
            raise ValueError(f"Duplicate operation_id: {operation.operation_id}")
        _registry[operation.operation_id] = operation
        _listeners[operation.operation_id] = []
        logger.info(
            "operation_registered id=%s module=%s target=%s",
            operation.operation_id,
            operation.module,
            operation.target,
        )
    return operation


async def get_operation(operation_id: str) -> Optional[OperationRecord]:
    """Return operation or None if not found."""
    return _registry.get(operation_id)


async def list_operations() -> list[OperationRecord]:
    """Return all operations, most recent first."""
    return sorted(
        _registry.values(),
        key=lambda op: op.started_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )


async def update_progress(
    operation_id: str,
    progress: int,
    stage: str,
    message: str,
    status: Optional[OperationStatus] = None,
) -> None:
    """Update progress fields and notify all registered listeners."""
    async with _lock:
        op = _registry.get(operation_id)
        if op is None:
            return
        op.progress = max(0, min(100, progress))
        op.current_stage = stage
        op.message = message
        if status is not None:
            op.status = status
            if status == OperationStatus.RUNNING and op.started_at is None:
                op.started_at = datetime.now(timezone.utc)
            if status in (
                OperationStatus.COMPLETED,
                OperationStatus.FAILED,
                OperationStatus.CANCELLED,
            ):
                op.finished_at = datetime.now(timezone.utc)

    event = ProgressEvent(
        operation_id=operation_id,
        stage=stage,
        progress=progress,
        message=message,
        status=op.status,
    )

    logger.debug(
        "progress id=%s stage=%s progress=%d status=%s",
        operation_id, stage, progress, op.status,
    )

    # Notify listeners outside the lock to avoid deadlocks.
    for listener in list(_listeners.get(operation_id, [])):
        try:
            await listener(event)
        except Exception:
            logger.exception("Progress listener error for %s", operation_id)


async def fail_operation(operation_id: str, error: str) -> None:
    """Mark operation as FAILED with an error message."""
    async with _lock:
        op = _registry.get(operation_id)
        if op:
            op.status = OperationStatus.FAILED
            op.error = error
            op.finished_at = datetime.now(timezone.utc)
    logger.error("operation_failed id=%s error=%s", operation_id, error)


async def complete_operation(
    operation_id: str, result: Optional[dict] = None
) -> None:
    """Mark operation as COMPLETED."""
    async with _lock:
        op = _registry.get(operation_id)
        if op:
            op.status = OperationStatus.COMPLETED
            op.progress = 100
            op.finished_at = datetime.now(timezone.utc)
            if result:
                op.result = result
    logger.info("operation_completed id=%s", operation_id)


async def cancel_operation(operation_id: str) -> bool:
    """
    Request cancellation of a running operation.
    Returns True if the operation was cancellable at this moment.
    Actual stop logic is the responsibility of the running coroutine which
    should periodically check operation status and exit if CANCELLED.
    """
    async with _lock:
        op = _registry.get(operation_id)
        if op is None:
            return False
        if op.status in (OperationStatus.QUEUED, OperationStatus.VALIDATING, OperationStatus.RUNNING):
            op.status = OperationStatus.CANCELLED
            op.finished_at = datetime.now(timezone.utc)
            logger.info("operation_cancelled id=%s", operation_id)
            return True
        return False


async def is_cancelled(operation_id: str) -> bool:
    """Convenience check for long-running loops to detect cancellation."""
    op = _registry.get(operation_id)
    return op is not None and op.status == OperationStatus.CANCELLED


def add_listener(
    operation_id: str,
    listener: Callable[[ProgressEvent], Coroutine],
) -> None:
    """Register an async callback to receive ProgressEvents for an operation."""
    if operation_id in _listeners:
        _listeners[operation_id].append(listener)


def remove_listener(
    operation_id: str,
    listener: Callable[[ProgressEvent], Coroutine],
) -> None:
    """Remove a previously registered listener."""
    if operation_id in _listeners:
        try:
            _listeners[operation_id].remove(listener)
        except ValueError:
            pass
