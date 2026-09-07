"""
carve/classifier.py — Heuristic forensic confidence scoring engine.

Every recovered object receives a score from 0–100 based on observable
structural evidence. This is NOT a machine-learning classifier.

Score components (must sum to ≤ 100):

    Header match          +25   (always present if we reached this point)
    Footer match          +20   (footer found within size limit)
    Structure valid       +25   (type-specific structural validation passed)
    Decoder validation    +20   (Pillow decode passed for images)
    Entropy plausible     +10   (entropy is in the expected range for the type)
    ─────────────────────────
    Maximum               100

Partial credit:
    Structure PARTIAL     +12   (instead of +25)
    No footer found        +0   (instead of +20)

The score is deterministic — the same candidate always produces the same score.

Thresholds for UI display:
    ≥ 80   HIGH confidence   (all major checks passed)
    60–79  MEDIUM confidence (most checks passed)
    40–59  LOW confidence    (header + some structure)
    < 40   VERY LOW          (header only, or failing structural checks)
"""

from __future__ import annotations

from backend.carve.entropy import entropy_score
from backend.carve.models import (
    CarvedFileType,
    CarvedFile,
    CarvingMethod,
    ConfidenceBreakdown,
    ValidationStatus,
)


def compute_confidence(
    file_type:        CarvedFileType,
    footer_found:     bool,
    structure_status: ValidationStatus,
    decoder_status:   ValidationStatus,
    entropy_value:    float,
) -> ConfidenceBreakdown:
    """
    Compute the heuristic forensic confidence breakdown.

    Parameters
    ----------
    file_type:        The detected file type.
    footer_found:     Whether a valid footer was found.
    structure_status: Result of the structural validator.
    decoder_status:   Result of the decoder round-trip (if attempted).
    entropy_value:    Shannon entropy of sampled bytes.

    Returns
    -------
    ConfidenceBreakdown with itemised scores and total.
    """
    bd = ConfidenceBreakdown()

    # Header match — always awarded if we are scoring a candidate
    # (header was already matched by the scanner to reach this point)
    bd.header_match = 25

    # Footer match
    bd.footer_match = 20 if footer_found else 0

    # Structural validation
    if structure_status == ValidationStatus.PASSED:
        bd.structure_valid = 25
    elif structure_status == ValidationStatus.PARTIAL:
        bd.structure_valid = 12
    else:
        bd.structure_valid = 0

    # Decoder validation
    if decoder_status == ValidationStatus.PASSED:
        bd.decoder_validation = 20
    elif decoder_status == ValidationStatus.PARTIAL:
        bd.decoder_validation = 10
    else:
        bd.decoder_validation = 0

    # Entropy
    bd.entropy_plausible = entropy_score(entropy_value, file_type.value)

    bd.total = min(
        100,
        bd.header_match
        + bd.footer_match
        + bd.structure_valid
        + bd.decoder_validation
        + bd.entropy_plausible,
    )

    return bd


def determine_carving_method(
    footer_found:     bool,
    structure_status: ValidationStatus,
    decoder_status:   ValidationStatus,
    is_reconstructed: bool = False,
) -> CarvingMethod:
    """Select the most informative CarvingMethod label."""
    if is_reconstructed:
        return CarvingMethod.RECONSTRUCTED
    if decoder_status == ValidationStatus.PASSED:
        return CarvingMethod.DECODER
    if structure_status in (ValidationStatus.PASSED, ValidationStatus.PARTIAL):
        return CarvingMethod.VALIDATED
    return CarvingMethod.SIGNATURE


def confidence_label(score: int) -> str:
    """Return a short display label for a confidence score."""
    if score >= 80:
        return "HIGH"
    elif score >= 60:
        return "MEDIUM"
    elif score >= 40:
        return "LOW"
    else:
        return "VERY LOW"
