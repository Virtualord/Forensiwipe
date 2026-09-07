"""
carve/scanner.py — Chunked evidence image scanner (Module 3 orchestrator).

Architecture:
  1. Open evidence image READ-ONLY — NEVER modify it.
  2. Compute SHA-256 of evidence before scan.
  3. Scan in overlapping chunks to catch signatures that span chunk boundaries.
  4. For each signature match:
       a. Extract candidate bytes (header → footer or header + max_size).
       b. Run structural validator.
       c. Compute entropy.
       d. Score confidence.
       e. Attempt JPEG fragmentation heuristic if applicable.
       f. Write recovered file to output directory.
       g. Hash the output file.
  5. Emit progress events via callback.
  6. Compute SHA-256 of evidence after scan.
  7. Compare before/after — report if evidence was modified (should never happen).
  8. Write audit record.
  9. Return ScanResult.

Chunked scanning:
  - Read in READ_CHUNK_SIZE blocks.
  - Maintain an OVERLAP of max(header_length) bytes between chunks so we
    never miss a signature that straddles a chunk boundary.
  - Never load the entire image into RAM.

The scanner is async — long operations yield to the event loop periodically.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Coroutine, Optional

from backend.audit import service as audit_service
from backend.carve import classifier, entropy as entropy_mod, fragment as frag_mod
from backend.carve import hashing, signatures as sig_mod, validators
from backend.carve.models import (
    CarvedFile,
    CarvedFileType,
    CarvingMethod,
    ConfidenceBreakdown,
    FragmentInfo,
    ScanProgress,
    ScanResult,
    ScanStatus,
    ValidationStatus,
)
from backend.core.config import get_settings
from backend.core.models import OperationModule

logger = logging.getLogger("forensiwipe.carve.scanner")

# ── Tuning constants ──────────────────────────────────────────────────────────

READ_CHUNK_SIZE    = 2 * 1024 * 1024     # 2 MB read blocks
OVERLAP_SIZE       = 256                 # bytes — max header length across all types
PROGRESS_INTERVAL  = 0.25               # emit progress every N seconds

# Minimum score to save a carved file (reject very low confidence candidates)
MIN_CONFIDENCE_TO_SAVE = 15


# ── Scanner ───────────────────────────────────────────────────────────────────

async def run_scan(
    evidence_path: str,
    operation_id: str,
    output_dir: Optional[Path] = None,
    progress_callback: Optional[Callable[[ScanProgress], Coroutine]] = None,
    operator_id: Optional[str] = None,
) -> ScanResult:
    """
    Execute a full carving scan on the evidence image.

    Parameters
    ----------
    evidence_path:     Absolute path to the disk image (opened read-only).
    operation_id:      Unique operation ID for audit and output naming.
    output_dir:        Directory for recovered files (default: recovered/<op_id>).
    progress_callback: Async callable receiving ScanProgress events.
    operator_id:       For audit records.

    Returns
    -------
    ScanResult — complete scan report.
    """
    settings   = get_settings()
    op_id      = operator_id or settings.operator_id
    started_at = datetime.now(timezone.utc)

    if output_dir is None:
        output_dir = settings.recovered_dir / operation_id
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = ScanResult(
        operation_id=operation_id,
        evidence_path=evidence_path,
        scan_started_at=started_at,
        output_directory=str(output_dir),
        status=ScanStatus.RUNNING,
    )

    async def _emit(msg: str, progress_pct: int, **kwargs) -> None:
        if progress_callback:
            prog = ScanProgress(
                operation_id=operation_id,
                status=ScanStatus.RUNNING,
                message=msg,
                progress_pct=progress_pct,
                **kwargs,
            )
            try:
                await progress_callback(prog)
            except Exception:
                pass
        await asyncio.sleep(0)   # yield to event loop

    # ── Step 1: Evidence integrity (before) ───────────────────────────────────
    await _emit("Computing evidence hash…", 1)
    logger.info("scan_started op=%s evidence=%s", operation_id, evidence_path)

    ev_path = Path(evidence_path)
    if not ev_path.exists():
        result.status = ScanStatus.FAILED
        result.error  = f"Evidence file not found: {evidence_path}"
        return result

    if not os.access(evidence_path, os.R_OK):
        result.status = ScanStatus.FAILED
        result.error  = f"Evidence file not readable: {evidence_path}"
        return result

    sha_before = hashing.sha256_file(evidence_path)
    result.evidence_sha256_before = sha_before
    result.total_bytes = ev_path.stat().st_size
    logger.info("evidence_hash_before op=%s hash=%s", operation_id, sha_before[:16] if sha_before else "NONE")

    # Audit: scan start
    await audit_service.record(
        operation_id=operation_id,
        module=OperationModule.CARVE.value,
        action="CARVE_STARTED",
        target=evidence_path,
        result="INFO",
        operator_id=op_id,
        operation_started_at=started_at,
        metadata={
            "evidence_sha256_before": sha_before,
            "total_bytes": result.total_bytes,
        },
    )

    # ── Step 2: Chunked scan ──────────────────────────────────────────────────
    carved_files:   list[CarvedFile] = []
    file_index      = 0
    bytes_scanned   = 0
    last_progress_t = time.monotonic()
    scan_start_t    = time.monotonic()

    # Buffer: current chunk + overlap from previous chunk
    overlap_buf     = b""

    try:
        with open(evidence_path, "rb") as fd:
            while True:
                chunk = fd.read(READ_CHUNK_SIZE)
                if not chunk:
                    break

                # Working buffer = leftover overlap + new chunk
                buf    = overlap_buf + chunk
                buf_abs_start = bytes_scanned - len(overlap_buf)  # abs offset of buf[0]

                # Scan this buffer for all signature headers
                pos = 0
                while pos < len(buf):
                    sig = sig_mod.match_header(buf, pos)
                    if sig is None:
                        pos += 1
                        continue

                    abs_offset = buf_abs_start + pos

                    # ── Extract candidate ─────────────────────────────────────
                    candidate, footer_found = _extract_candidate(
                        fd, buf, pos, abs_offset, sig, result.total_bytes
                    )

                    if candidate is None or len(candidate) < sig.min_size:
                        pos += len(sig.header)
                        continue

                    # ── Validate ──────────────────────────────────────────────
                    v_status, v_notes, actual_type = validators.validate(
                        sig.file_type, candidate
                    )

                    # ── Entropy ───────────────────────────────────────────────
                    ent_val   = entropy_mod.sample_entropy(candidate)
                    ent_label = entropy_mod.entropy_label(ent_val, actual_type.value)

                    # ── Decoder status from validator notes ───────────────────
                    dec_status = _parse_decoder_status(v_notes, actual_type)

                    # ── Confidence score ──────────────────────────────────────
                    breakdown = classifier.compute_confidence(
                        actual_type, footer_found, v_status, dec_status, ent_val
                    )
                    method = classifier.determine_carving_method(
                        footer_found, v_status, dec_status
                    )

                    if breakdown.total < MIN_CONFIDENCE_TO_SAVE:
                        result.files_rejected += 1
                        logger.debug(
                            "candidate_rejected offset=%d type=%s confidence=%d",
                            abs_offset, actual_type, breakdown.total,
                        )
                        pos += len(sig.header)
                        continue

                    # ── Fragment heuristic (JPEG only, if structural fail) ─────
                    frag_info = FragmentInfo()
                    if (
                        actual_type == CarvedFileType.JPEG
                        and v_status in (ValidationStatus.FAILED, ValidationStatus.PARTIAL)
                        and breakdown.total >= 25    # at least header match
                    ):
                        buf_window = buf[max(0, pos - 1024): min(len(buf), pos + sig.max_size)]
                        reconstructed, frag_info = frag_mod.attempt_reconstruction(
                            candidate, buf_window, start_offset_in_buffer=min(1024, pos)
                        )
                        if reconstructed and frag_info.result == "ACCEPTED":
                            candidate  = reconstructed
                            v_status   = ValidationStatus.PASSED
                            dec_status = ValidationStatus.PASSED
                            method     = CarvingMethod.RECONSTRUCTED
                            breakdown  = classifier.compute_confidence(
                                actual_type, footer_found, v_status, dec_status, ent_val
                            )
                            result.fragments_attempted += 1

                    # ── Write recovered file ──────────────────────────────────
                    out_ext = _get_extension(actual_type, sig)
                    out_path, sha256 = hashing.write_carved_file(
                        candidate, output_dir, file_index,
                        actual_type.value, abs_offset, out_ext,
                    )

                    carved = CarvedFile(
                        index=file_index,
                        file_type=actual_type,
                        offset=abs_offset,
                        size=len(candidate),
                        size_human=sig_mod.human_size(len(candidate)),
                        sha256=sha256,
                        output_path=out_path,
                        carving_method=method,
                        confidence=breakdown.total,
                        confidence_breakdown=breakdown,
                        structure_valid=v_status,
                        decoder_valid=dec_status,
                        entropy=ent_val,
                        entropy_label=ent_label,
                        fragment=frag_info,
                        notes=v_notes[:8],   # cap notes list for response size
                        extension=out_ext,
                    )
                    carved_files.append(carved)
                    file_index += 1

                    if v_status in (ValidationStatus.PASSED, ValidationStatus.PARTIAL):
                        result.files_validated += 1
                    else:
                        result.files_rejected += 1

                    logger.info(
                        "file_carved type=%s offset=%d size=%d confidence=%d method=%s",
                        actual_type, abs_offset, len(candidate),
                        breakdown.total, method,
                    )

                    # Skip past the carved region to avoid re-matching inside it.
                    # candidate was extracted starting at buf[pos], so advance by
                    # the full candidate length (minimum: header length).
                    pos += max(len(sig.header), len(candidate))

                # Keep overlap for next iteration
                bytes_scanned += len(chunk)
                overlap_buf    = buf[-OVERLAP_SIZE:] if len(buf) >= OVERLAP_SIZE else buf

                # Emit progress
                now = time.monotonic()
                if now - last_progress_t >= PROGRESS_INTERVAL:
                    elapsed   = max(0.001, now - scan_start_t)
                    speed     = (bytes_scanned / elapsed) / (1024 * 1024)
                    pct       = int(bytes_scanned * 90 / max(1, result.total_bytes))
                    await _emit(
                        f"Scanning… {bytes_scanned // (1024*1024)} MB / {result.total_bytes // (1024*1024)} MB",
                        pct,
                        bytes_scanned=bytes_scanned,
                        total_bytes=result.total_bytes,
                        scan_speed_mbps=round(speed, 2),
                        matches_found=len(carved_files),
                        validated=result.files_validated,
                        rejected=result.files_rejected,
                        fragments=result.fragments_attempted,
                        current_offset=bytes_scanned,
                    )
                    last_progress_t = now

    except Exception as exc:
        logger.exception("scan_error op=%s exc=%s", operation_id, exc)
        result.status = ScanStatus.FAILED
        result.error  = str(exc)
        return result

    # ── Step 3: Evidence integrity (after) ────────────────────────────────────
    await _emit("Verifying evidence integrity…", 92)
    sha_after = hashing.sha256_file(evidence_path)
    result.evidence_sha256_after = sha_after

    if sha_before and sha_after:
        if sha_before == sha_after:
            result.evidence_integrity = "PRESERVED"
            logger.info("evidence_integrity op=%s PRESERVED", operation_id)
        else:
            result.evidence_integrity = "COMPROMISED"
            logger.critical(
                "EVIDENCE_INTEGRITY_COMPROMISED op=%s before=%s after=%s",
                operation_id, sha_before[:16], sha_after[:16],
            )
    else:
        result.evidence_integrity = "UNKNOWN"

    # ── Step 4: Finalise result ───────────────────────────────────────────────
    finished_at            = datetime.now(timezone.utc)
    result.bytes_scanned   = bytes_scanned
    result.files_found     = len(carved_files)
    result.carved_files    = carved_files
    result.scan_finished_at = finished_at
    result.status          = ScanStatus.COMPLETED

    # Audit: scan complete
    audit_rec = await audit_service.record(
        operation_id=operation_id,
        module=OperationModule.CARVE.value,
        action="CARVE_COMPLETED",
        target=evidence_path,
        result="SUCCESS",
        operator_id=op_id,
        operation_started_at=started_at,
        operation_finished_at=finished_at,
        metadata={
            "evidence_sha256_before": sha_before,
            "evidence_sha256_after":  sha_after,
            "evidence_integrity":     result.evidence_integrity,
            "files_found":            result.files_found,
            "files_validated":        result.files_validated,
            "bytes_scanned":          bytes_scanned,
        },
    )
    result.audit_sequence = audit_rec.get("sequence")
    result.audit_hash     = audit_rec.get("current_hash")

    await _emit("Scan complete.", 100, matches_found=len(carved_files))
    logger.info(
        "scan_complete op=%s files=%d validated=%d rejected=%d integrity=%s",
        operation_id, result.files_found, result.files_validated,
        result.files_rejected, result.evidence_integrity,
    )
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_candidate(
    fd,
    buf:        bytes,
    pos:        int,
    abs_offset: int,
    sig:        sig_mod.FileSignature,
    total_size: int,
) -> tuple[Optional[bytes], bool]:
    """
    Extract the raw bytes for a candidate file.

    Strategy:
    1. Look for the footer within the in-memory buffer first (fast path).
    2. If not found and max_size > remaining buffer, read more from fd.
    3. Return (candidate_bytes, footer_found).

    The file descriptor position is NOT advanced — we restore it.
    """
    # Search in current buffer (avoid extra read for small files)
    footer_end = sig_mod.find_footer(buf, sig, pos + len(sig.header), sig.max_size)
    if footer_end != -1:
        return buf[pos:footer_end], True

    # Footer not in current buffer — read ahead
    current_fd_pos = fd.tell()
    bytes_already_in_buf = len(buf) - pos
    remaining_to_read    = sig.max_size - bytes_already_in_buf

    if remaining_to_read <= 0:
        # max_size exceeded within buffer
        return buf[pos: pos + sig.max_size], False

    try:
        extra = fd.read(min(remaining_to_read, sig.max_size))
    except OSError:
        fd.seek(current_fd_pos)
        return None, False

    extended = buf[pos:] + extra
    footer_end_ext = sig_mod.find_footer(extended, sig, len(sig.header), sig.max_size)

    # Restore fd position so the main loop can continue normally
    fd.seek(current_fd_pos)

    if footer_end_ext != -1:
        return extended[:footer_end_ext], True
    else:
        # No footer found — use max_size as boundary
        return extended[:sig.max_size], False


def _parse_decoder_status(notes: list[str], file_type: CarvedFileType) -> ValidationStatus:
    """
    Infer decoder validation status from validator notes strings.

    Validators write notes like "Pillow decode: OK (1024×768 px)" or
    "Pillow decode: FAILED (...)". We parse those here rather than
    threading a separate return value through all validators.
    """
    for note in notes:
        lower = note.lower()
        if "pillow decode: ok" in lower:
            return ValidationStatus.PASSED
        if "pillow decode: failed" in lower:
            return ValidationStatus.FAILED
        if "pillow not available" in lower or "decoder validation skipped" in lower:
            return ValidationStatus.SKIPPED
    return ValidationStatus.SKIPPED


def _get_extension(file_type: CarvedFileType, sig: sig_mod.FileSignature) -> str:
    """Return the file extension for a detected type."""
    _OVERRIDES = {
        CarvedFileType.DOCX: ".docx",
        CarvedFileType.XLSX: ".xlsx",
        CarvedFileType.PPTX: ".pptx",
    }
    return _OVERRIDES.get(file_type, sig.extension)
