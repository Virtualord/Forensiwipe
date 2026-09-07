"""
erase/verification.py — Post-erase sector/offset sampling verification.

IMPORTANT: This verification samples random regions of the target.
It DOES NOT prove every physical sector has been sanitised.
This distinction is forensically honest and must be preserved in UI copy.

For image files:
  - Sample N random offsets
  - Read a block at each offset
  - Compare against the expected pattern for the chosen standard
  - Record pass/fail per sample
  - Compute a SHA-256 evidence hash over all sample results

For physical block devices:
  - Same logic, but size is obtained from the device
  - Sampling is capped to avoid overly long post-erase verification
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import struct
from pathlib import Path
from typing import Optional

from backend.core.models import EraseStandard, VerificationStatus
from backend.core.models import VerificationResult

logger = logging.getLogger("forensiwipe.erase.verification")

# Bytes per sample block read during verification.
SAMPLE_BLOCK_SIZE = 4096

# Number of samples to take.
DEFAULT_SAMPLE_COUNT = 64

# Maximum file size for which we attempt full-block verification.
FULL_VERIFY_THRESHOLD_BYTES = 64 * 1024 * 1024  # 64 MB


def _expected_byte(standard: EraseStandard, pass_index: int = 0) -> Optional[int]:
    """
    Return the single byte value expected after erasure for simple patterns.
    Returns None if the pattern is random (cannot be reproduced for verification).
    """
    if standard in (EraseStandard.ZERO_FILL, EraseStandard.NIST_CLEAR):
        return 0x00
    # DoD 3-pass: final pass is random — not byte-verifiable
    # Gutmann 35-pass: final passes are random — not byte-verifiable
    # All other standards: non-deterministic or hardware-dependent
    return None  # Random / multi-pattern / hardware — cannot byte-verify


def _read_block(fd: int, offset: int, size: int) -> bytes:
    """Read `size` bytes from file descriptor at `offset`."""
    os.lseek(fd, offset, os.SEEK_SET)
    return os.read(fd, size)


def verify_target(
    target_path: str,
    standard: EraseStandard,
    sample_count: int = DEFAULT_SAMPLE_COUNT,
) -> VerificationResult:
    """
    Verify that the target looks consistent with the applied erase standard
    by sampling random offsets.

    Parameters
    ----------
    target_path: Path to device or image file (opened read-only).
    standard:    The erasure standard that was applied.
    sample_count: Number of random offset samples to take.

    Returns
    -------
    VerificationResult with detailed pass/fail statistics.
    """
    expected_byte = _expected_byte(standard)

    if expected_byte is None:
        # Cannot verify random/hardware patterns by byte comparison.
        logger.info(
            "verification_skipped target=%s standard=%s reason=non-deterministic pattern",
            target_path, standard,
        )
        return VerificationResult(
            status=VerificationStatus.NOT_APPLICABLE,
            samples_total=0,
            note=(
                f"Verification not applicable for {standard}: "
                "the write pattern is non-deterministic (random or hardware-dependent). "
                "Sector integrity cannot be byte-verified for this standard."
            ),
        )

    # ── Open target read-only ────────────────────────────────────────────────
    p = Path(target_path)
    if not p.exists():
        return VerificationResult(
            status=VerificationStatus.FAILED,
            note=f"Verification failed: target '{target_path}' not found.",
        )

    try:
        fd = os.open(target_path, os.O_RDONLY)
    except PermissionError as exc:
        return VerificationResult(
            status=VerificationStatus.FAILED,
            note=f"Cannot open target for verification: {exc}",
        )

    try:
        # Determine size
        size = os.lseek(fd, 0, os.SEEK_END)
        if size == 0:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                note="Target has zero size — nothing to verify.",
            )

        # Clamp sample count for very small targets
        effective_samples = min(sample_count, max(1, size // SAMPLE_BLOCK_SIZE))

        # Generate deterministic-ish random sample offsets (block-aligned)
        rng = random.Random(0xF04E_751C)   # deterministic seed for reproducibility
        max_offset = size - SAMPLE_BLOCK_SIZE
        if max_offset <= 0:
            offsets = [0]
        else:
            block_count = max_offset // SAMPLE_BLOCK_SIZE
            chosen_blocks = sorted(
                rng.sample(range(int(block_count)), min(effective_samples, int(block_count)))
            )
            offsets = [b * SAMPLE_BLOCK_SIZE for b in chosen_blocks]

        passed = 0
        failed = 0
        evidence_hasher = hashlib.sha256()

        for offset in offsets:
            try:
                block = _read_block(fd, offset, SAMPLE_BLOCK_SIZE)
                expected_block = bytes([expected_byte]) * len(block)
                block_hash = hashlib.sha256(block).hexdigest()

                if block == expected_block:
                    passed += 1
                    evidence_hasher.update(f"PASS:{offset}:{block_hash}".encode())
                else:
                    failed += 1
                    evidence_hasher.update(f"FAIL:{offset}:{block_hash}".encode())
                    logger.debug(
                        "verification_mismatch offset=%d first_bytes=%s",
                        offset, block[:8].hex(),
                    )
            except OSError as exc:
                failed += 1
                logger.warning("verification_read_error offset=%d exc=%s", offset, exc)

        evidence_hash = evidence_hasher.hexdigest()

        if failed == 0 and passed > 0:
            status = VerificationStatus.PASSED
        elif passed > 0 and failed > 0:
            status = VerificationStatus.PARTIAL
        else:
            status = VerificationStatus.FAILED

        note = (
            f"Verification sampled {passed + failed} sectors. "
            f"Passed: {passed}, Failed: {failed}. "
            "This verifies the sampled regions only — it does NOT prove "
            "every physical sector or cell has been sanitised."
        )

        logger.info(
            "verification_complete target=%s status=%s passed=%d failed=%d",
            target_path, status, passed, failed,
        )

        return VerificationResult(
            status=status,
            samples_total=passed + failed,
            samples_passed=passed,
            samples_failed=failed,
            offsets_checked=offsets[:20],   # Record first 20 for the report
            evidence_hash=evidence_hash,
            note=note,
        )

    finally:
        os.close(fd)
