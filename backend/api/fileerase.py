"""
api/fileerase.py — File and folder erasure API endpoints (Module 2).

POST /api/fileerase/preview   — Dry-run preview (no writes)
POST /api/fileerase/start     — Start erase operation (async background)
GET  /api/fileerase/{id}/status — Operation status (polling)
GET  /api/fileerase/filesystems — Filesystem capability badge matrix
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException

from backend.core import tasks as task_store
from backend.core.config import get_settings
from backend.core.models import OperationModule, OperationRecord, OperationStatus
from backend.fileerase.engine import run_file_erase
from backend.fileerase.filesystem import all_badges, detect_filesystem, get_badge
from backend.fileerase.models import (
    FileEraseOperationResult,
    FileErasePreview,
    FileEraseRequest,
    FilesystemBadge,
)
from backend.fileerase.patterns import collect_files

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.fileerase")

# In-memory result store (same pattern as carve)
_results: dict[str, FileEraseOperationResult] = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/filesystems", response_model=list[FilesystemBadge],
            summary="Filesystem capability matrix")
async def get_filesystems() -> list[FilesystemBadge]:
    """Return the filesystem capability badge matrix for display in the UI."""
    return all_badges()


@router.post("/preview", response_model=FileErasePreview,
             summary="Preview files to be erased (dry run)")
async def preview_erase(req: FileEraseRequest) -> FileErasePreview:
    """
    Resolve all paths and return a preview without making any changes.

    Shows: file count, total size, filesystem type + badge, metadata availability.
    Use this before calling /start to show the confirmation step.
    """
    files = collect_files(req.paths, req.recursive, req.glob_pattern)

    if not files:
        return FileErasePreview(
            files=[], total_files=0, total_size_bytes=0,
            total_size_human="0 B", filesystem="unknown",
            filesystem_support="DETECT",
            metadata_available=False, residual_scan_available=False,
            warnings=["No files matched the specified paths/pattern."],
        )

    total_size = sum(
        Path(f).stat().st_size for f in files if Path(f).exists()
    )
    fs_type = detect_filesystem(files[0]) if files else "unknown"
    badge   = get_badge(fs_type)

    warnings: list[str] = []
    if badge.limitations:
        warnings.extend(badge.limitations[:2])

    # Check metadata sanitisation availability
    try:
        from PIL import Image
        meta_ok = True
    except ImportError:
        meta_ok = False

    def _human(n: int) -> str:
        for u in ("B","KB","MB","GB"):
            if n < 1024: return f"{n:.1f} {u}"
            n //= 1024
        return f"{n:.1f} TB"

    return FileErasePreview(
        files=files[:100],            # cap list for response size
        total_files=len(files),
        total_size_bytes=total_size,
        total_size_human=_human(total_size),
        filesystem=fs_type,
        filesystem_support=badge.support.value,
        metadata_available=meta_ok,
        residual_scan_available=True,
        warnings=warnings,
    )


@router.post("/start", summary="Start file erase operation")
async def start_file_erase(
    req: FileEraseRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Start an asynchronous file erasure operation.

    Monitor via GET /api/fileerase/{operation_id}/status
    or WebSocket /ws/operations/{operation_id}.
    """
    settings = get_settings()

    # Quick sanity check — at least one path must exist
    existing = [p for p in req.paths if Path(p).exists()]
    if not existing:
        raise HTTPException(
            status_code=404,
            detail="None of the specified paths exist.",
        )

    operation = OperationRecord(
        module=OperationModule.FILE_ERASE,
        target=", ".join(req.paths[:3]),
        operator_id=req.operator_id or settings.operator_id,
        status=OperationStatus.QUEUED,
    )
    await task_store.register_operation(operation)
    op_id = operation.operation_id

    async def _progress(pct: int, msg: str) -> None:
        await task_store.update_progress(
            op_id, pct, "erasing", msg, OperationStatus.RUNNING
        )

    async def _run() -> None:
        try:
            await task_store.update_progress(
                op_id, 1, "starting", "Initialising…", OperationStatus.RUNNING
            )
            result = await run_file_erase(req, op_id, _progress)
            _results[op_id] = result
            await task_store.complete_operation(
                op_id, {"succeeded": result.succeeded, "failed": result.failed}
            )
        except Exception as exc:
            logger.exception("fileerase_background_error op=%s", op_id)
            await task_store.fail_operation(op_id, str(exc))

    background_tasks.add_task(_run)
    logger.info("fileerase_queued op=%s paths=%s", op_id, req.paths[:3])

    return {
        "operation_id": op_id,
        "status": "QUEUED",
        "total_paths": len(req.paths),
        "message": f"File erase queued. Monitor at GET /api/fileerase/{op_id}/status",
        "simulated": req.demo_mode,
    }


@router.get("/{operation_id}/status", summary="File erase operation status")
async def get_status(operation_id: str) -> dict:
    op = await task_store.get_operation(operation_id)
    if op is None:
        raise HTTPException(status_code=404,
                            detail=f"Operation '{operation_id}' not found.")
    result = _results.get(operation_id)
    return {
        "operation_id": operation_id,
        "status":       op.status,
        "progress":     op.progress,
        "message":      op.message,
        "succeeded":    result.succeeded if result else 0,
        "failed":       result.failed    if result else 0,
        "total_files":  result.total_files if result else 0,
        "simulated":    result.simulated if result else False,
    }


@router.get("/{operation_id}/results",
            response_model=FileEraseOperationResult,
            summary="Full file erase result")
async def get_results(operation_id: str) -> FileEraseOperationResult:
    result = _results.get(operation_id)
    if result is None:
        op = await task_store.get_operation(operation_id)
        if op is None:
            raise HTTPException(status_code=404,
                                detail=f"Operation '{operation_id}' not found.")
        raise HTTPException(status_code=202,
                            detail=f"Operation still in progress: {op.status}")
    return result
