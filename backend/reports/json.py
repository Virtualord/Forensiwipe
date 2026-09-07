"""Machine-readable operation report generation."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def write_json_report(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return path

def base_report(operation: dict[str, Any] | None, audit_records: list[dict[str, Any]], audit_verification: dict[str, Any]) -> dict[str, Any]:
    return {"report_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
            "product": "ForensiWipe — Digital Forensics & Secure Sanitization", "operation": operation,
            "audit_records": audit_records, "audit_verification": audit_verification,
            "limitations": ["Audit verification assesses the recorded hash chain.", "Physical-media sanitization guarantees depend on media and method."]}
