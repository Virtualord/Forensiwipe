"""
audit/hash_chain.py — Blockchain-inspired tamper-evident hash chain.

Each audit record is linked to the previous one by including the previous
record's hash in the input to SHA-256.  Modifying, deleting, or reordering
any record breaks every subsequent hash in the chain.

DESIGN NOTE:
    We do NOT call this a "blockchain".  It is a hash chain — a well-established
    cryptographic technique.  The distinction matters for technical credibility.

Hash formula:
    current_hash = SHA256(
        canonical_json(record_fields_excluding_current_hash)
        + "|"
        + previous_hash
    )

Canonical JSON: keys sorted, no extra whitespace, datetime → ISO-8601 string.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any


GENESIS_HASH = "GENESIS"


def _serialise_value(v: Any) -> Any:
    """Recursively prepare a value for canonical JSON serialisation."""
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _serialise_value(val) for k, val in sorted(v.items())}
    if isinstance(v, list):
        return [_serialise_value(i) for i in v]
    return v


def canonical_json(data: dict[str, Any]) -> str:
    """
    Produce a deterministic JSON string from `data`.

    - Keys are sorted recursively.
    - datetime values are converted to ISO-8601.
    - No extra whitespace (separators=(',', ':')).
    """
    prepared = _serialise_value(data)
    return json.dumps(prepared, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_record_hash(record_data: dict[str, Any], previous_hash: str) -> str:
    """
    Compute the current_hash for a new audit record.

    Parameters
    ----------
    record_data:
        All record fields EXCEPT current_hash.  The previous_hash field
        must already be set correctly in record_data before calling this.
    previous_hash:
        The current_hash of the immediately preceding record,
        or GENESIS_HASH for the very first record.

    Returns
    -------
    Hex-encoded SHA-256 digest string.
    """
    canonical = canonical_json(record_data)
    payload = canonical + "|" + previous_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_record_hash(record_data: dict[str, Any], previous_hash: str, claimed_hash: str) -> bool:
    """
    Re-derive the hash and compare it to the claimed value.

    Returns True if the record is unmodified.
    """
    expected = compute_record_hash(record_data, previous_hash)
    return expected == claimed_hash
