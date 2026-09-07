"""
audit/database.py — SQLite persistence for the audit hash chain.

Uses SQLite from the application event-loop thread. The schema is intentionally
simple — one table, append-mostly, never updated in place. Each database call
is deliberately short; long-running erase and carving work never holds a DB
connection.

IMPORTANT: Audit records are NEVER modified after insertion.
           The hash chain depends on immutability.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.core.config import get_settings

logger = logging.getLogger("forensiwipe.audit.database")

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_records (
    sequence          INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id      TEXT    NOT NULL,
    timestamp         TEXT    NOT NULL,
    operator_id       TEXT    NOT NULL,
    module            TEXT    NOT NULL,
    action            TEXT    NOT NULL,
    target            TEXT    NOT NULL,
    device_identifier TEXT,
    standard          TEXT,
    operation_started_at  TEXT,
    operation_finished_at TEXT,
    result            TEXT    NOT NULL,
    verification_result TEXT,
    previous_hash     TEXT    NOT NULL,
    current_hash      TEXT    NOT NULL,
    metadata          TEXT    NOT NULL DEFAULT '{}'
);
"""

_CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_audit_operation_id ON audit_records(operation_id);
"""


def _db_path() -> Path:
    return get_settings().audit_db_path


async def init_db() -> None:
    """Create database tables if they do not exist."""
    # These small, local SQLite operations intentionally remain on the event
    # loop. They do not perform network I/O, and keeping connections in this
    # thread avoids passing SQLite connection state between threads.
    _init_db_sync(_db_path())
    logger.info("audit_db_ready path=%s", _db_path())


def _connect(path: Path) -> sqlite3.Connection:
    """Open a short-lived SQLite connection in its owning worker thread."""
    return sqlite3.connect(str(path), timeout=10)


def _init_db_sync(path: Path) -> None:
    with _connect(path) as db:
        db.execute(_CREATE_TABLE_SQL)
        db.execute(_CREATE_INDEX_SQL)


async def insert_record(record: dict) -> int:
    """
    Insert a new audit record row.
    Returns the assigned sequence number (ROWID).
    """
    return _insert_record_sync(_db_path(), record)


def _insert_record_sync(path: Path, record: dict) -> int:
    with _connect(path) as db:
        cursor = db.execute(
            """
            INSERT INTO audit_records (
                operation_id, timestamp, operator_id, module, action,
                target, device_identifier, standard,
                operation_started_at, operation_finished_at,
                result, verification_result,
                previous_hash, current_hash, metadata
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                record["operation_id"],
                _to_iso(record.get("timestamp")),
                record["operator_id"],
                record["module"],
                record["action"],
                record["target"],
                record.get("device_identifier"),
                record.get("standard"),
                _to_iso(record.get("operation_started_at")),
                _to_iso(record.get("operation_finished_at")),
                record["result"],
                record.get("verification_result"),
                record["previous_hash"],
                record["current_hash"],
                json.dumps(record.get("metadata", {})),
            ),
        )
        seq = cursor.lastrowid
    if seq is None:
        raise RuntimeError("SQLite did not return an audit sequence number")
    logger.debug("audit_record_inserted sequence=%s op=%s", seq, record["operation_id"])
    return seq


async def get_latest_hash() -> str:
    """Return the current_hash of the most recent record, or 'GENESIS' if none."""
    from backend.audit.hash_chain import GENESIS_HASH

    row = _get_latest_hash_sync(_db_path())
    return row[0] if row else GENESIS_HASH


def _get_latest_hash_sync(path: Path) -> Optional[tuple[str]]:
    with _connect(path) as db:
        return db.execute(
            "SELECT current_hash FROM audit_records ORDER BY sequence DESC LIMIT 1"
        ).fetchone()


async def get_all_records() -> list[dict]:
    """Return all audit records ordered by sequence (oldest first)."""
    return _get_all_records_sync(_db_path())


def _get_all_records_sync(path: Path) -> list[dict]:
    with _connect(path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM audit_records ORDER BY sequence ASC").fetchall()
    return [dict(row) for row in rows]


async def get_records_for_operation(operation_id: str) -> list[dict]:
    """Return audit records for a specific operation_id."""
    return _get_records_for_operation_sync(_db_path(), operation_id)


def _get_records_for_operation_sync(path: Path, operation_id: str) -> list[dict]:
    with _connect(path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM audit_records WHERE operation_id = ? ORDER BY sequence ASC",
            (operation_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _to_iso(value: object) -> Optional[str]:
    """Convert datetime → ISO-8601 string, pass through None and strings."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
