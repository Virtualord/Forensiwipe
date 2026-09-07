"""
carve/fragment.py — JPEG fragmentation heuristic.

Goal: detect a JPEG whose data appears fragmented (interrupted by unrelated
content) and attempt to reconstruct it by finding a valid continuation.

SCOPE LIMITATIONS — stated honestly:
  - This is a constrained heuristic, not a universal defragmenter.
  - It targets a specific, common pattern: one fragment gap in a JPEG stream.
  - Reconstruction is ONLY accepted if Pillow successfully decodes the result.
  - If reconstruction cannot be validated → REJECTED (not silently saved).

Algorithm:
  1. Receive a JPEG candidate that failed full structural validation.
  2. Find where the JPEG stream becomes implausible (entropy drop / bad markers).
  3. Search the surrounding N bytes for a region that looks like JPEG continuation:
       - High entropy
       - Valid-looking marker bytes
       - Followed eventually by FF D9
  4. Splice the best candidate into the stream.
  5. Attempt Pillow decode.
  6. Return result — ACCEPTED only if decode succeeds.

The caller (scanner.py) decides whether to use the reconstructed output.
"""

from __future__ import annotations

import io
import logging
from typing import Optional

from backend.carve.models import FragmentInfo, ValidationStatus

logger = logging.getLogger("forensiwipe.carve.fragment")

# How far forward from the truncation point to search for continuation
SEARCH_WINDOW_BYTES = 2 * 1024 * 1024    # 2 MB

# Minimum size of a candidate continuation block
MIN_CONTINUATION_SIZE = 512

# Maximum gap size to bridge (data between end of valid stream and continuation)
MAX_GAP_SIZE = 512 * 1024   # 512 KB

_JPEG_SOI = b"\xFF\xD8"
_JPEG_EOI = b"\xFF\xD9"
_JPEG_SOS = b"\xFF\xDA"


def _find_truncation_point(data: bytes) -> int:
    """
    Find the approximate offset where the JPEG stream becomes implausible.

    Strategy: walk the JPEG marker chain from the start; return the offset
    of the first marker whose stated length would go out of bounds, or
    where a non-JPEG byte sequence interrupts the stream.

    Returns the offset, or len(data) if the stream looks fully intact.
    """
    import struct

    if not data.startswith(b"\xFF\xD8"):
        return 0

    pos = 2
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            return pos   # Stream corrupted here

        marker = data[pos + 1]
        if marker == 0xD9:   # EOI — stream ended cleanly
            return len(data)
        elif marker == 0xDA:  # SOS — remainder is scan data
            # Walk scan data looking for EOI
            eoi = data.find(_JPEG_EOI, pos + 2)
            return eoi + 2 if eoi != -1 else pos + 2
        elif marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
            # Restart markers — standalone
            pos += 2
            continue
        elif marker in (0xD8,):
            pos += 2
            continue
        else:
            if pos + 3 >= len(data):
                return pos
            try:
                length = struct.unpack(">H", data[pos + 2: pos + 4])[0]
            except struct.error:
                return pos
            if length < 2:
                return pos
            next_pos = pos + 2 + length
            if next_pos > len(data) + 64:
                return pos   # Length out of bounds — truncation here
            pos = next_pos

    return pos


def _looks_like_jpeg_continuation(chunk: bytes) -> bool:
    """
    Heuristic: does this chunk look like it could be a JPEG scan continuation?

    Checks for:
    - Non-zero entropy (not a blank region)
    - Presence of 0xFF marker bytes at a plausible density
    - Contains FF D9 (EOI) somewhere in the window
    """
    if len(chunk) < MIN_CONTINUATION_SIZE:
        return False

    # Count 0xFF bytes — JPEG scan data has them at a predictable density
    ff_count = chunk.count(b"\xFF")
    ff_density = ff_count / len(chunk)

    # Blank / zero region
    zero_density = chunk.count(b"\x00") / len(chunk)
    if zero_density > 0.95:
        return False

    # Too few markers suggests non-JPEG data
    if ff_density < 0.001:
        return False

    # Must have an EOI somewhere ahead
    if _JPEG_EOI not in chunk:
        return False

    return True


def attempt_reconstruction(
    jpeg_data: bytes,
    image_buffer: bytes,
    start_offset_in_buffer: int,
) -> tuple[Optional[bytes], FragmentInfo]:
    """
    Attempt JPEG fragment reconstruction.

    Parameters
    ----------
    jpeg_data:
        The bytes of the candidate JPEG (already extracted from image).
    image_buffer:
        A window of the raw image around the candidate for searching
        continuation fragments.
    start_offset_in_buffer:
        Where in image_buffer the jpeg_data starts.

    Returns
    -------
    (reconstructed_bytes, FragmentInfo)
    reconstructed_bytes is None if reconstruction was rejected or not attempted.
    """
    info = FragmentInfo(
        attempted=True,
        result="NOT_ATTEMPTED",
    )

    # Find where the JPEG stream breaks
    trunc_point = _find_truncation_point(jpeg_data)
    valid_prefix = jpeg_data[:trunc_point]

    if trunc_point >= len(jpeg_data) - 8:
        # Stream looks complete — no fragmentation detected
        info.attempted = False
        info.result = "NOT_ATTEMPTED"
        return None, info

    logger.debug(
        "fragment_truncation_at offset_in_candidate=%d candidate_size=%d",
        trunc_point, len(jpeg_data),
    )

    # Search for continuation in image_buffer after the candidate
    search_start = start_offset_in_buffer + trunc_point
    search_end   = min(search_start + SEARCH_WINDOW_BYTES, len(image_buffer))

    candidates: list[tuple[int, bytes]] = []

    pos = search_start
    while pos < search_end - MIN_CONTINUATION_SIZE:
        # Look for a non-zero region that ends with EOI
        chunk = image_buffer[pos: pos + MAX_GAP_SIZE]
        eoi_pos = chunk.find(_JPEG_EOI)
        if eoi_pos != -1:
            candidate_chunk = chunk[:eoi_pos + 2]
            if _looks_like_jpeg_continuation(candidate_chunk):
                candidates.append((pos, candidate_chunk))
                logger.debug("fragment_candidate_found at buffer_offset=%d size=%d", pos, len(candidate_chunk))
            pos += eoi_pos + 2
        else:
            pos += MIN_CONTINUATION_SIZE

    info.candidates_found = len(candidates)

    if not candidates:
        info.result = "NO_CANDIDATES"
        logger.info("fragment_no_candidates")
        return None, info

    # Try each candidate in order (first found is usually best for sequential storage)
    for candidate_offset, continuation in candidates:
        info.best_candidate_offset = candidate_offset
        reconstructed = valid_prefix + continuation

        # Validate via Pillow
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(reconstructed))
            img.verify()
            img2 = Image.open(io.BytesIO(reconstructed))
            w, h = img2.size
            if w > 0 and h > 0:
                info.decoder_validation = ValidationStatus.PASSED
                info.result = "ACCEPTED"
                logger.info(
                    "fragment_reconstruction_accepted size=%d dims=%dx%d",
                    len(reconstructed), w, h,
                )
                return reconstructed, info
        except ImportError:
            info.result = "DECODER_UNAVAILABLE"
            logger.info("fragment_pillow_unavailable")
            return None, info
        except Exception as exc:
            logger.debug("fragment_decode_failed exc=%s", exc)
            continue

    # All candidates tried, none passed decoder validation
    info.decoder_validation = ValidationStatus.FAILED
    info.result = "REJECTED"
    logger.info("fragment_reconstruction_rejected all_candidates_failed")
    return None, info
