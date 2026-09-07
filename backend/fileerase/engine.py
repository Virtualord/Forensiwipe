"""
fileerase/engine.py — Secure file and folder erasure orchestrator (Module 2).

Per-file workflow:
  1. Record metadata (path, size, type).
  2. Compute SHA-256 before deletion (for audit evidence).
  3. Identify filesystem type.
  4. Attempt metadata sanitisation on a working copy (if enabled).
  5. Overwrite file contents with selected pattern.
  6. Flush (fsync).
  7. Unlink file.
  8. Scan for residual references (if enabled).
  9. Record result and add audit entry.

Directory handling: files processed first, directories unlinkable after.

Safety:
  - We never modify the user's original file before the overwrite+unlink
    is committed (metadata sanitisation uses a temp copy).
  - Failures are recorded per-file; the operation continues with remaining files.
  - We never report SUCCESS after a partial failure without flagging it.

Demo mode: simulates progress without actual writes or unlinks.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Coroutine, Optional

from backend.audit import service as audit_service
from backend.core.config import get_settings
from backend.core.models import OperationModule
from backend.fileerase import metadata as meta_mod, residuals, patterns
from backend.fileerase.filesystem import detect_filesystem, get_badge, journal_warning
from backend.fileerase.models import (
    FileEraseOperationResult,
    FileEraseRequest,
    FileEraseResult,
    FileEraseStatus,
    MetadataResult,
    MetadataStatus,
    ResidualFinding,
    ResidualStatus,
)

logger = logging.getLogger("forensiwipe.fileerase.engine")


def _sha256_path(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


async def run_file_erase(
    request: FileEraseRequest,
    operation_id: str,
    progress_callback: Optional[Callable[..., Coroutine]] = None,
) -> FileEraseOperationResult:
    """
    Execute the file erasure operation for all specified paths.

    Long-running — yields to the event loop between files.
    """
    settings    = get_settings()
    op_id       = request.operator_id or settings.operator_id
    started_at  = datetime.now(timezone.utc)
    standard    = request.standard.value

    result = FileEraseOperationResult(
        operation_id=operation_id,
        standard=request.standard,
        simulated=request.demo_mode,
    )

    async def _emit(msg: str, pct: int) -> None:
        if progress_callback:
            try:
                await progress_callback(pct, msg)
            except Exception:
                pass
        await asyncio.sleep(0)

    await _emit("Collecting files…", 1)

    # ── Collect file list ──────────────────────────────────────────────────────
    file_list = patterns.collect_files(
        request.paths, request.recursive, request.glob_pattern
    )
    directories = patterns.selected_directories(request.paths, request.recursive)

    if not file_list:
        result.notes.append("No files matched the specified paths/pattern.")
        return result

    result.total_files = len(file_list)
    total_size = sum(Path(f).stat().st_size for f in file_list if Path(f).exists())
    result.total_bytes = total_size

    # Detect filesystem from first file's location
    fs_type = detect_filesystem(file_list[0])
    badge   = get_badge(fs_type)
    j_warn  = journal_warning(fs_type)

    if j_warn:
        result.notes.append(j_warn)

    # Audit: start
    await audit_service.record(
        operation_id=operation_id,
        module=OperationModule.FILE_ERASE.value,
        action="FILE_ERASE_STARTED",
        target=", ".join(request.paths[:3]),
        result="INFO",
        operator_id=op_id,
        operation_started_at=started_at,
        standard=standard,
        metadata={
            "total_files":    result.total_files,
            "total_bytes":    total_size,
            "filesystem":     fs_type,
            "fs_support":     badge.support.value,
            "simulated":      request.demo_mode,
        },
    )

    # ── Process each file ──────────────────────────────────────────────────────
    for idx, file_path in enumerate(file_list):
        pct = 5 + int((idx / result.total_files) * 85)
        await _emit(f"Erasing {Path(file_path).name}… ({idx+1}/{result.total_files})", pct)

        file_result = await _erase_single_file(
            file_path=file_path,
            standard=standard,
            sanitise_metadata=request.sanitise_metadata,
            scan_residuals_flag=request.scan_residuals,
            demo_mode=request.demo_mode,
            fs_type=fs_type,
        )
        result.file_results.append(file_result)

        if file_result.erase_status == FileEraseStatus.SUCCESS:
            result.succeeded += 1
        elif file_result.erase_status == FileEraseStatus.FAILED:
            result.failed += 1
        else:
            result.skipped += 1

    # Directories are removed only after their selected children.  A directory
    # that still contains an unselected file (for example after a glob filter)
    # is retained and explicitly reported rather than treated as a failure.
    if not request.demo_mode:
        for directory in directories:
            try:
                directory.rmdir()
                result.directories_removed += 1
            except OSError:
                result.directories_not_empty += 1
    elif directories:
        result.notes.append(
            f"[DEMO MODE] {len(directories)} selected directory/directories retained."
        )

    # ── Aggregate residual summary ─────────────────────────────────────────────
    all_residuals: list[ResidualFinding] = []
    for fr in result.file_results:
        all_residuals.extend(fr.residuals)
    result.residual_summary = all_residuals

    # ── Audit: complete ────────────────────────────────────────────────────────
    finished_at = datetime.now(timezone.utc)
    audit_rec = await audit_service.record(
        operation_id=operation_id,
        module=OperationModule.FILE_ERASE.value,
        action="FILE_ERASE_COMPLETED",
        target=", ".join(request.paths[:3]),
        result="SUCCESS" if result.failed == 0 else "PARTIAL",
        operator_id=op_id,
        standard=standard,
        operation_started_at=started_at,
        operation_finished_at=finished_at,
        metadata={
            "total_files": result.total_files,
            "succeeded":   result.succeeded,
            "failed":      result.failed,
            "skipped":     result.skipped,
            "directories_removed": result.directories_removed,
            "directories_not_empty": result.directories_not_empty,
            "simulated":   request.demo_mode,
        },
    )
    result.audit_sequence = audit_rec.get("sequence")
    result.audit_hash     = audit_rec.get("current_hash")

    await _emit("Complete.", 100)
    logger.info(
        "file_erase_complete op=%s files=%d succeeded=%d failed=%d",
        operation_id, result.total_files, result.succeeded, result.failed,
    )
    return result


async def _erase_single_file(
    file_path:        str,
    standard:         str,
    sanitise_metadata: bool,
    scan_residuals_flag: bool,
    demo_mode:        bool,
    fs_type:          str,
) -> FileEraseResult:
    """Process one file through the full erase workflow."""
    p = Path(file_path)

    if not p.exists() or not p.is_file():
        return FileEraseResult(
            path=file_path,
            erase_status=FileEraseStatus.SKIPPED,
            error="File does not exist or is not a regular file.",
        )

    size       = p.stat().st_size
    file_type  = p.suffix.lower()
    sha_before = _sha256_path(file_path)

    fr = FileEraseResult(
        path=file_path,
        size_bytes=size,
        sha256_before=sha_before,
        file_type=file_type,
        filesystem=fs_type,
    )

    # ── Step 1: Metadata sanitisation (working copy) ───────────────────────────
    clean_bytes: Optional[bytes] = None
    if sanitise_metadata and not demo_mode:
        meta_result, clean_bytes = meta_mod.sanitise_metadata(file_path)
        fr.metadata = meta_result
    else:
        fr.metadata = MetadataResult(
            status=MetadataStatus.NOT_APPLICABLE if demo_mode else MetadataStatus.NOT_APPLICABLE,
            note="Metadata sanitisation skipped (demo mode or disabled)." if demo_mode
                 else "Metadata sanitisation not requested.",
        )

    if demo_mode:
        # Simulate — no actual writes or unlinks
        fr.erase_status  = FileEraseStatus.SUCCESS
        fr.passes_written = {"ZERO_FILL":1,"RANDOM_FILL":1,"DOD_3PASS":3}.get(standard, 1)
        fr.bytes_written  = size * fr.passes_written
        fr.notes.append("[DEMO MODE] File erase simulated — no actual writes performed.")
        if scan_residuals_flag:
            fr.residuals = residuals.scan_residuals(file_path)
        return fr

    # ── Step 2: Validate the sanitised working copy ───────────────────────────
    # A file-erase operation must never replace or otherwise modify the selected
    # original before its overwrite+unlink commitment.  The reconstructed bytes
    # are therefore written only to a short-lived working copy, then removed.
    # This records whether the format-specific metadata workflow was feasible;
    # it does not claim that metadata is removed from filesystem journals.
    if clean_bytes is not None:
        temp_name: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="forensiwipe-metadata-", suffix=p.suffix, delete=False
            ) as tmp:
                temp_name = tmp.name
                tmp.write(clean_bytes)
                tmp.flush()
                os.fsync(tmp.fileno())
            logger.debug("metadata_working_copy_validated path=%s", file_path)
        except Exception as exc:
            logger.warning("metadata_working_copy_error path=%s exc=%s", file_path, exc)
            fr.metadata = MetadataResult(
                status=MetadataStatus.FAILED,
                note=f"Could not create sanitised working copy: {exc}",
            )
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name)
                except OSError:
                    logger.warning("metadata_working_copy_cleanup_failed path=%s", temp_name)

    # ── Step 3: Overwrite ──────────────────────────────────────────────────────
    try:
        written, passes = patterns.overwrite_file(file_path, standard)
        fr.bytes_written  = written
        fr.passes_written = passes
    except Exception as exc:
        logger.error("overwrite_error path=%s exc=%s", file_path, exc)
        fr.erase_status = FileEraseStatus.FAILED
        fr.error        = f"Overwrite failed: {exc}"
        return fr

    # ── Step 4: Unlink ─────────────────────────────────────────────────────────
    try:
        os.unlink(file_path)
        logger.info("file_unlinked path=%s", file_path)
    except Exception as exc:
        logger.error("unlink_error path=%s exc=%s", file_path, exc)
        fr.erase_status = FileEraseStatus.FAILED
        fr.error        = f"Unlink failed after overwrite: {exc}"
        return fr

    fr.erase_status = FileEraseStatus.SUCCESS

    # ── Step 5: Residual scan ──────────────────────────────────────────────────
    if scan_residuals_flag:
        fr.residuals = residuals.scan_residuals(file_path)

    return fr
