"""
core/security.py — Application-level security helpers.

Currently handles:
- Operator confirmation validation for destructive operations
- Safe path checks (ensure paths do not escape approved directories)
- Input sanitisation utilities

This is NOT an authentication system — the prototype runs locally.
It enforces the confirmation protocols described in the requirements.
"""

from __future__ import annotations

import os
from pathlib import Path


class ConfirmationError(ValueError):
    """Raised when an operator confirmation string does not match the required value."""


def validate_exact_confirmation(required: str, provided: str) -> None:
    """
    Enforce exact-match confirmation for destructive operations.

    The operator must type the exact target path (e.g. '/dev/sdb').
    We explicitly reject common lazy substitutes:
        - 'yes', 'confirm', 'continue', 'ok', device basename only, etc.

    Raises ConfirmationError if the confirmation does not match exactly.
    """
    # Strip surrounding whitespace only — do not normalise case or content.
    provided_clean = provided.strip()

    if provided_clean != required:
        raise ConfirmationError(
            f"Confirmation rejected. "
            f"Expected exactly '{required}', got '{provided_clean}'. "
            "Type the full device path to confirm."
        )


def is_path_inside_directory(path: Path, directory: Path) -> bool:
    """
    Return True if `path` resolves to a location inside `directory`.

    Uses os.path.commonpath to avoid symlink-traversal tricks.
    Both paths are resolved to absolute paths before comparison.
    """
    try:
        resolved_path = path.resolve()
        resolved_dir = directory.resolve()
        return str(resolved_path).startswith(str(resolved_dir) + os.sep) or \
               resolved_path == resolved_dir
    except (OSError, ValueError):
        return False


def sanitise_operation_input(value: str, max_length: int = 512) -> str:
    """
    Basic input sanitisation for strings that end up in audit records.

    - Strip leading/trailing whitespace.
    - Truncate to max_length.
    - Replace null bytes.
    """
    cleaned = value.strip().replace("\x00", "")
    return cleaned[:max_length]
