"""
erase/engine.py — The secure drive erase engine.

This is the only place that issues write commands to storage targets.

Architecture:
    1. Validate target (target_validator.py — mandatory, no bypass)
    2. Acquire operation lock (mark_target_active)
    3. Record START audit event
    4. Compute before-hash (image files only)
    5. Execute selected strategy (EraseStrategy subclass)
    6. Flush writes
    7. Verify result (verification.py)
    8. Record verification result
    9. Compute after-hash (image files only)
    10. Write COMPLETE audit event with hash chain
    11. Release operation lock

Erase strategies are stateless classes that take (target, fd, size, callback).
The engine owns the fd lifecycle and safety checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import struct
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from backend.audit import service as audit_service
from backend.core.config import get_settings
from backend.core.models import (
    EraseStandard,
    OperationModule,
    OperationStatus,
    VerificationStatus,
)
from backend.core.tasks import (
    fail_operation,
    is_cancelled,
    update_progress,
)
from backend.erase import target_validator, verification
from backend.erase.models import EraseRequest, EraseResult

logger = logging.getLogger("forensiwipe.erase.engine")

# Block size for all write operations.
WRITE_BLOCK_SIZE = 512 * 1024   # 512 KB

# Gutmann patterns — 35 passes in order.
_GUTMANN_PATTERNS: list[Optional[bytes]] = [
    None, None, None, None,                      # passes 1–4: random
    bytes([0x55]), bytes([0xAA]),
    bytes.fromhex("924924"), bytes.fromhex("492492"), bytes.fromhex("DB6DB6"),
    bytes.fromhex("B6DB6D"), bytes.fromhex("6DB6DB"),
    bytes([0x00]), bytes([0x11]), bytes([0x22]), bytes([0x33]),
    bytes([0x44]), bytes([0x55]), bytes([0x66]), bytes([0x77]),
    bytes([0x88]), bytes([0x99]), bytes([0xAA]), bytes([0xBB]),
    bytes([0xCC]), bytes([0xDD]), bytes([0xEE]), bytes([0xFF]),
    bytes.fromhex("924924"), bytes.fromhex("492492"), bytes.fromhex("DB6DB6"),
    bytes.fromhex("B6DB6D"), bytes.fromhex("6DB6DB"),
    None, None, None, None,                      # passes 32–35: random
]


# ── Strategy base class ───────────────────────────────────────────────────────

class EraseStrategy(ABC):
    """Base class for all erase strategies."""

    name: str
    simulated: bool = False   # True for hw-dependent strategies in demo mode

    @abstractmethod
    async def execute(
        self,
        fd: int,
        size: int,
        operation_id: str,
        progress_base: int,
        progress_range: int,
    ) -> dict:
        """
        Write to the open file descriptor `fd` covering `size` bytes.

        Returns a dict of execution metadata (bytes_written, passes_completed, notes).
        Progress updates must use update_progress(operation_id, ...).
        """
        ...

    async def _write_single_pass(
        self,
        fd: int,
        size: int,
        pattern: Optional[bytes],  # None = random
        operation_id: str,
        progress_base: int,
        progress_range: int,
        pass_label: str,
    ) -> int:
        """
        Write one complete pass over `size` bytes.
        Returns total bytes written.
        """
        written = 0
        os.lseek(fd, 0, os.SEEK_SET)

        while written < size:
            if await is_cancelled(operation_id):
                logger.info("erase_cancelled op=%s at_offset=%d", operation_id, written)
                return written

            remaining = size - written
            chunk_size = min(WRITE_BLOCK_SIZE, remaining)

            if pattern is None:
                chunk = os.urandom(chunk_size)
            else:
                chunk = (pattern * (chunk_size // len(pattern) + 1))[:chunk_size]

            os.write(fd, chunk)
            written += chunk_size

            # Progress: map written bytes within [progress_base, progress_base+progress_range]
            frac = written / size
            current_progress = progress_base + int(frac * progress_range)
            await update_progress(
                operation_id,
                current_progress,
                "erasing",
                f"{pass_label}: {written // (1024*1024)} MB / {size // (1024*1024)} MB written",
            )
            # Yield to event loop periodically so we don't block.
            await asyncio.sleep(0)

        return written


# ── Strategy implementations ──────────────────────────────────────────────────

class ZeroFillStrategy(EraseStrategy):
    name = "ZERO_FILL"

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        written = await self._write_single_pass(
            fd, size, bytes([0x00]), operation_id,
            progress_base, progress_range, "Zero Fill"
        )
        return {"bytes_written": written, "passes_completed": 1, "notes": []}


class RandomFillStrategy(EraseStrategy):
    name = "RANDOM_FILL"

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        written = await self._write_single_pass(
            fd, size, None, operation_id,
            progress_base, progress_range, "Random Fill"
        )
        return {"bytes_written": written, "passes_completed": 1, "notes": []}


class DoD3PassStrategy(EraseStrategy):
    name = "DOD_3PASS"

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        passes = [
            (bytes([0x00]), "DoD Pass 1/3: 0x00"),
            (bytes([0xFF]), "DoD Pass 2/3: 0xFF"),
            (None,          "DoD Pass 3/3: random"),
        ]
        total_written = 0
        slice_size = progress_range // 3
        for i, (pattern, label) in enumerate(passes):
            w = await self._write_single_pass(
                fd, size, pattern, operation_id,
                progress_base + i * slice_size, slice_size, label
            )
            total_written += w
        return {
            "bytes_written": total_written,
            "passes_completed": 3,
            "notes": [
                "DoD 5220.22-M: 0x00 / 0xFF / random",
                "NOTE: Not a current NIST recommendation. For demonstration only.",
            ],
        }


class Gutmann35Strategy(EraseStrategy):
    name = "GUTMANN_35"

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        total_written = 0
        slice_size = max(1, progress_range // 35)
        for i, pattern in enumerate(_GUTMANN_PATTERNS):
            if await is_cancelled(operation_id):
                break
            label = f"Gutmann Pass {i+1}/35"
            w = await self._write_single_pass(
                fd, size, pattern, operation_id,
                progress_base + i * slice_size, slice_size, label
            )
            total_written += w
        return {
            "bytes_written": total_written,
            "passes_completed": 35,
            "notes": [
                "Gutmann 35-pass: historically significant.",
                "Excessive for modern drives. Not effective on SSD/NVMe.",
            ],
        }


class NISTClearStrategy(EraseStrategy):
    name = "NIST_CLEAR"

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        written = await self._write_single_pass(
            fd, size, bytes([0x00]), operation_id,
            progress_base, progress_range, "NIST Clear"
        )
        return {
            "bytes_written": written,
            "passes_completed": 1,
            "notes": [
                "NIST SP 800-88 Rev 1 Clear: single-pass zero overwrite.",
                "Software overwrite only — does not reach SSD overprovisioned areas.",
            ],
        }


class NISTSimulatedPurgeStrategy(EraseStrategy):
    name = "NIST_PURGE"
    simulated = True

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        # Simulate progress without actual hardware command.
        for pct in range(0, 101, 10):
            if await is_cancelled(operation_id):
                break
            await update_progress(
                operation_id,
                progress_base + int(pct * progress_range / 100),
                "simulating_purge",
                f"[SIMULATION] NIST Purge — hardware command simulation {pct}%",
            )
            await asyncio.sleep(0.1)
        return {
            "bytes_written": 0,
            "passes_completed": 0,
            "notes": [
                "SIMULATION ONLY: ATA Security Erase / NVMe Sanitize not executed.",
                "Hardware-dependent purge requires device-specific commands.",
                "This prototype demonstrates the interface and workflow only.",
            ],
        }


class CryptoEraseSimulatedStrategy(EraseStrategy):
    name = "CRYPTO_ERASE"
    simulated = True

    async def execute(self, fd, size, operation_id, progress_base, progress_range):
        for pct in range(0, 101, 20):
            if await is_cancelled(operation_id):
                break
            await update_progress(
                operation_id,
                progress_base + int(pct * progress_range / 100),
                "simulating_crypto_erase",
                f"[SIMULATION] Crypto Erase — key destruction simulation {pct}%",
            )
            await asyncio.sleep(0.1)
        return {
            "bytes_written": 0,
            "passes_completed": 0,
            "notes": [
                "SIMULATION ONLY: Cryptographic key destruction not executed.",
                "Requires hardware FDE (TCG Opal / ATA Crypto Scramble / NVMe Crypto Erase).",
                "Demo simulation — cryptographic sanitisation concept demonstrated.",
            ],
        }


# ── Strategy registry ─────────────────────────────────────────────────────────

_STRATEGIES: dict[EraseStandard, EraseStrategy] = {
    EraseStandard.ZERO_FILL:    ZeroFillStrategy(),
    EraseStandard.RANDOM_FILL:  RandomFillStrategy(),
    EraseStandard.DOD_3PASS:    DoD3PassStrategy(),
    EraseStandard.GUTMANN_35:   Gutmann35Strategy(),
    EraseStandard.NIST_CLEAR:   NISTClearStrategy(),
    EraseStandard.NIST_PURGE:   NISTSimulatedPurgeStrategy(),
    EraseStandard.CRYPTO_ERASE: CryptoEraseSimulatedStrategy(),
}


# ── SHA-256 hashing helper ────────────────────────────────────────────────────

def _sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 of a file.  Returns None if unreadable or too large."""
    try:
        p = Path(path)
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ── Main erase entry point ────────────────────────────────────────────────────

async def run_erase(request: EraseRequest, operation_id: str) -> EraseResult:
    """
    Execute a complete erase operation.

    This function is called from a background asyncio task.
    It should NOT be awaited directly from a route handler — use asyncio.create_task.
    """
    settings = get_settings()
    target = request.target
    standard = request.standard
    operator_id = request.operator_id or settings.operator_id
    started_at = datetime.now(timezone.utc)

    logger.info("erase_started op=%s target=%s standard=%s", operation_id, target, standard)

    # ── Stage 1: Validate ─────────────────────────────────────────────────────
    await update_progress(operation_id, 2, "validating", "Validating target…", OperationStatus.VALIDATING)

    validation = target_validator.validate_target(
        target,
        operator_approved=True,   # Approval confirmed via API confirmation step
    )

    if not validation.allowed:
        await fail_operation(operation_id, validation.reason)
        await audit_service.record(
            operation_id=operation_id,
            module=OperationModule.DRIVE_ERASE.value,
            action="ERASE_BLOCKED",
            target=target,
            result="FAILURE",
            operator_id=operator_id,
            standard=standard.value,
            metadata={"validation_reason": validation.reason},
        )
        return EraseResult(
            operation_id=operation_id,
            target=target,
            standard=standard,
            validation=validation,
            verification=verification.VerificationResult(
                status=VerificationStatus.NOT_APPLICABLE
            ),
        )

    await update_progress(operation_id, 5, "validated", "Target validated.", OperationStatus.RUNNING)

    # ── Stage 2: Lock target ──────────────────────────────────────────────────
    target_validator.mark_target_active(target)

    sha256_before: Optional[str] = None
    sha256_after: Optional[str] = None
    exec_meta: dict = {}

    try:
        # ── Stage 3: Before-hash (image files only) ───────────────────────────
        is_image = Path(target).is_file() and target.endswith(".img")
        if is_image:
            await update_progress(operation_id, 6, "hashing", "Computing before-hash…")
            sha256_before = _sha256_file(target)
            logger.info("before_hash op=%s hash=%s", operation_id, sha256_before)

        # ── Stage 4: Audit START event ────────────────────────────────────────
        await audit_service.record(
            operation_id=operation_id,
            module=OperationModule.DRIVE_ERASE.value,
            action="ERASE_STARTED",
            target=target,
            result="INFO",
            operator_id=operator_id,
            standard=standard.value,
            operation_started_at=started_at,
            metadata={
                "sha256_before": sha256_before,
                "validation_checks_passed": len(validation.checks_passed),
                "simulated": request.demo_mode,
            },
        )

        # ── Stage 5: Execute erase strategy ──────────────────────────────────
        strategy = _STRATEGIES[standard]

        if request.demo_mode or strategy.simulated:
            # Demo / simulated path — no actual writes.
            await update_progress(operation_id, 10, "erasing", "[DEMO] Simulating erase…")
            # For genuinely simulated strategies (NIST_PURGE, CRYPTO_ERASE), call execute.
            # For real strategies in demo_mode, produce a canned response without any fd.
            if strategy.simulated:
                exec_meta = await strategy.execute(None, 0, operation_id, 10, 70)
            else:
                # Simulate progress without writes
                for pct in range(0, 101, 10):
                    if await is_cancelled(operation_id):
                        break
                    await update_progress(
                        operation_id,
                        10 + int(pct * 0.7),
                        "erasing",
                        f"[DEMO] Simulating {standard.value} — {pct}%",
                    )
                    await asyncio.sleep(0.05)
                exec_meta = {
                    "bytes_written": 0,
                    "passes_completed": 0,
                    "notes": [f"[DEMO MODE] {standard.value} simulated — no actual writes performed."],
                }
        else:
            # Real write path — open target for writing.
            try:
                fd = os.open(target, os.O_WRONLY | os.O_SYNC)
            except PermissionError as exc:
                raise RuntimeError(
                    f"Cannot open target for writing: {exc}. "
                    "Run with appropriate privileges (e.g. sudo for block devices)."
                ) from exc

            try:
                size = os.lseek(fd, 0, os.SEEK_END)
                if size == 0:
                    raise RuntimeError("Target has zero size — cannot erase.")

                exec_meta = await strategy.execute(fd, size, operation_id, 10, 70)

                # Flush write buffers
                os.fsync(fd)
                logger.info("erase_flushed op=%s", operation_id)

            finally:
                os.close(fd)

        # ── Stage 6: Verify ───────────────────────────────────────────────────
        await update_progress(operation_id, 82, "verifying", "Verifying sampled sectors…", OperationStatus.VERIFYING)

        if request.demo_mode or strategy.simulated:
            verify_result = verification.VerificationResult(
                status=VerificationStatus.NOT_APPLICABLE,
                note="Verification not applicable — operation was simulated/demo mode.",
            )
        else:
            verify_result = verification.verify_target(target, standard)

        await update_progress(operation_id, 92, "hashing_after", "Computing after-hash…")

        # ── Stage 7: After-hash (image files only) ────────────────────────────
        if is_image:
            sha256_after = _sha256_file(target)
            logger.info("after_hash op=%s hash=%s", operation_id, sha256_after)

        # ── Stage 8: Audit COMPLETE event ─────────────────────────────────────
        finished_at = datetime.now(timezone.utc)
        audit_rec = await audit_service.record(
            operation_id=operation_id,
            module=OperationModule.DRIVE_ERASE.value,
            action="ERASE_COMPLETED",
            target=target,
            result="SUCCESS",
            operator_id=operator_id,
            standard=standard.value,
            operation_started_at=started_at,
            operation_finished_at=finished_at,
            verification_result=verify_result.status.value,
            metadata={
                "sha256_before": sha256_before,
                "sha256_after": sha256_after,
                "bytes_written": exec_meta.get("bytes_written", 0),
                "passes_completed": exec_meta.get("passes_completed", 0),
                "verification_samples_total": verify_result.samples_total,
                "verification_samples_passed": verify_result.samples_passed,
                "verification_evidence_hash": verify_result.evidence_hash,
                "simulated": request.demo_mode or strategy.simulated,
                "notes": exec_meta.get("notes", []),
            },
        )

        await update_progress(operation_id, 100, "completed", "Operation completed.", OperationStatus.COMPLETED)

        result = EraseResult(
            operation_id=operation_id,
            target=target,
            standard=standard,
            validation=validation,
            verification=verify_result,
            sha256_before=sha256_before,
            sha256_after=sha256_after,
            bytes_written=exec_meta.get("bytes_written", 0),
            passes_completed=exec_meta.get("passes_completed", 0),
            audit_sequence=audit_rec.get("sequence"),
            audit_hash=audit_rec.get("current_hash"),
            simulated=request.demo_mode or strategy.simulated,
            notes=exec_meta.get("notes", []),
        )

        logger.info(
            "erase_finished op=%s standard=%s verify=%s simulated=%s",
            operation_id, standard, verify_result.status, result.simulated,
        )
        return result

    except Exception as exc:
        logger.exception("erase_engine_error op=%s exc=%s", operation_id, exc)
        await fail_operation(operation_id, str(exc))
        await audit_service.record(
            operation_id=operation_id,
            module=OperationModule.DRIVE_ERASE.value,
            action="ERASE_FAILED",
            target=target,
            result="FAILURE",
            operator_id=operator_id,
            standard=standard.value,
            operation_started_at=started_at,
            operation_finished_at=datetime.now(timezone.utc),
            metadata={"error": str(exc)},
        )
        raise

    finally:
        target_validator.mark_target_inactive(target)
