"""
carve/entropy.py — Shannon entropy calculation for carved file candidates.

Entropy is used as a corruption/noise indicator, NOT as proof of validity.

Display example:
    Entropy: 7.42 bits/byte
    Assessment: plausible compressed data

Entropy ranges and their forensic interpretation:
    0.0 – 1.0   Very low  — likely zeroed/unwritten region or constant fill
    1.0 – 5.0   Low       — plain text, simple structured data
    5.0 – 7.0   Medium    — structured binary, some compression
    7.0 – 7.9   High      — compressed, encrypted, or image/audio data
    7.9 – 8.0   Very high — near-maximum entropy; typical of encrypted/compressed data

We do NOT claim entropy can prove file validity.

IMPORTANT: Entropy is sampled over a subset of bytes to keep carving fast.
We never load the entire file into RAM for entropy — we sample the first
N bytes of the candidate.
"""

from __future__ import annotations

import math
from collections import Counter

# Maximum bytes to sample for entropy calculation
ENTROPY_SAMPLE_BYTES = 4096


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of `data` in bits per byte.

    Returns a value in [0.0, 8.0].
    An empty input returns 0.0.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total  = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def sample_entropy(data: bytes, sample_size: int = ENTROPY_SAMPLE_BYTES) -> float:
    """
    Compute entropy over a sample of up to `sample_size` bytes.
    Uses the beginning of the data to avoid loading large files.
    """
    sample = data[:sample_size]
    return shannon_entropy(sample)


def entropy_label(entropy: float, file_type: str = "") -> str:
    """
    Return a human-readable assessment of an entropy value.

    The label is contextual — e.g. high entropy is expected for JPEG/ZIP
    but suspicious for a plain-text file.
    """
    if entropy < 1.0:
        return "very low — likely zeroed or constant-fill region"
    elif entropy < 3.0:
        return "low — consistent with plain text or simple structured data"
    elif entropy < 5.5:
        return "medium — consistent with structured binary data"
    elif entropy < 7.0:
        return "moderate-high — consistent with encoded or lightly compressed data"
    elif entropy < 7.8:
        return "high — plausible compressed or image data"
    else:
        return "near-maximum — typical of compressed, encrypted, or random data"


def entropy_score(entropy: float, file_type: str = "") -> int:
    """
    Translate entropy into a confidence sub-score (0 or 10).

    For image/compressed formats (JPEG, PNG, ZIP, DOCX, XLSX, PPTX):
        Expect high entropy (> 6.5) → +10 points
    For text-based formats (PDF can vary):
        Moderate entropy (> 3.0) → +10 points
    Very low entropy (< 1.0) → always 0 (suspicious for any non-trivial file)
    """
    ft = file_type.upper()

    if entropy < 1.0:
        return 0   # Zero region — no confidence contribution

    if ft in ("JPEG", "PNG", "ZIP", "DOCX", "XLSX", "PPTX"):
        return 10 if entropy > 6.5 else (5 if entropy > 4.0 else 0)

    if ft == "PDF":
        return 10 if entropy > 3.0 else 0

    # Generic: any non-trivial entropy is positive
    return 10 if entropy > 2.0 else 0
