# ForensiWipe — Scope and Capability Matrix

**SIH 2026 — PS 26149 | Organisation: NTRO | Theme: Cybersecurity**

This document is the authoritative statement of what ForensiWipe implements,
what it demonstrates, and what it explicitly does not do.
Honest capability reporting is a design requirement, not optional.

---

## Phase 1 — Module 1: Secure Drive Eraser

| Feature | Status | Notes |
|---|---|---|
| Safe loopback image erase | ✅ Fully implemented | Tested against `.img` files in `demo/` |
| Physical HDD erase | 🔒 Restricted | Requires `SAFE_MODE=false` + `ALLOW_PHYSICAL_ERASE=true` |
| Physical SSD/NVMe erase | 🔒 Restricted | Same config; overwrite only — see SSD note below |
| ATA Security Erase | ❌ Not implemented | Hardware-dependent; requires ATA command layer |
| NVMe Format / Sanitize | ❌ Not implemented | Hardware-dependent; requires NVMe command layer |
| SSD Cryptographic Erase | 🔬 Interface/simulation | Controller-level key destruction not executed |
| Zero Fill (NIST Clear) | ✅ Implemented | Single-pass 0x00; NIST SP 800-88 applicable for HDD |
| Random Fill | ✅ Implemented | Single-pass PRNG; not a standalone NIST method |
| DoD 5220.22-M 3-pass | ✅ Implemented | Historical; not current NIST recommendation |
| Gutmann 35-pass | ✅ Implemented | Historical; excessive for modern drives |
| NIST SP 800-88 Clear | ✅ Implemented | Software overwrite; SSD limitations disclosed |
| NIST SP 800-88 Purge | 🔬 Interface only | Hardware commands not issued in this prototype |
| Post-erase verification | ✅ Implemented | Random-sample sector verification with evidence hash |
| Before/after SHA-256 | ✅ Implemented | For image files only; block device hashing caveats disclosed |
| Target validation (12 checks) | ✅ Fully implemented | Single choke point; no bypass possible |
| Safe mode enforcement | ✅ Fully implemented | Default `SAFE_MODE=true`; loopback-only in safe mode |
| Cancellation | ✅ Implemented | Best-effort; checked between write blocks |
| Linux device discovery | ✅ Implemented | `lsblk`, `/sys/block`, `/proc/mounts`, `psutil` |
| Windows device discovery | 🔬 Stub | Interface present; enumeration not implemented |

---

## Phase 1 — Audit & Hash Chain

| Feature | Status | Notes |
|---|---|---|
| Tamper-evident hash chain | ✅ Fully implemented | SHA-256 chain; GENESIS anchor |
| Chain integrity verification | ✅ Fully implemented | Detects modify / delete / reorder |
| SQLite audit database | ✅ Implemented | Append-only; records never updated |
| Operator ID in every record | ✅ Implemented | Configurable via `OPERATOR_ID` env var |
| Per-operation audit trail | ✅ Implemented | START + COMPLETE records per operation |

---

## Module 3 — File Carving

| Feature | Status | Notes |
|---|---|---|
| JPEG carving + validation | ✅ Implemented | Signature, markers, and decoder validation |
| PNG carving + validation | ✅ Implemented | Signature and structural check |
| PDF carving + validation | ✅ Implemented | Header/footer and basic structural checks |
| ZIP / DOCX / XLSX carving | ✅ Implemented | ZIP structure distinguishes Office formats |
| JPEG fragment reconstruction | 🔬 Prototype | Heuristic only; saved only after validation |
| Entropy analysis | ✅ Implemented | Corruption/noise indicator, not proof |
| Confidence scoring | ✅ Implemented | Deterministic heuristic; not ML-based |
| Evidence integrity (SHA-256) | ✅ Implemented | Read-only source; before/after hash |
| Chunked scanner (RAM-safe) | ✅ Implemented | No full-image RAM load |

---

## Module 2 — File & Folder Eraser

| Feature | Status | Notes |
|---|---|---|
| Individual file erasure (ext4) | ✅ Implemented | Overwrite + unlink |
| Recursive folder erasure | ✅ Implemented | Files first, directories last |
| Glob / batch selection | ✅ Implemented | Preview before execution |
| Metadata sanitisation (JPEG) | ✅ Best effort | Pillow temporary working copy |
| Metadata sanitisation (DOCX) | ✅ Best effort | Uses python-docx when installed |
| Metadata sanitisation (PDF) | 🔬 Partial | Requires optional pikepdf dependency |
| Residual trace scan (Linux) | ✅ Best effort | Recent files and thumbnails where accessible |
| Residual trace scan (Windows) | 🔬 Partial | Recent Items and thumbnail interface |
| NTFS sanitisation | 🔬 Partial | Detection/interface; advanced sanitisation limited |
| APFS sanitisation | 🔬 Stub | Detection/interface only |
| ext4 | ✅ Primary target | Prototype tested on ext4 |

---

## Reports & Dashboard

| Feature | Status | Notes |
|---|---|---|
| PDF report generation | ✅ Implemented | ReportLab, operation and audit evidence |
| JSON report export | ✅ Implemented | Machine-readable |
| Report integrity verification | ✅ Implemented | Recomputes chain through audit UI/API |
| React dashboard | ✅ Implemented | Professional forensic operator UI |
| Live progress | ✅ Implemented | WebSocket backend; polling UI fallback |
| Operation history | ✅ Implemented | Unified dashboard monitor and audit history |

---

## Explicit Non-Claims

- This prototype does **not** certify media as sanitised for classified disposal.
- Overwrite-based methods applied to SSD/NVMe via this software **do not** guarantee
  erasure of data in overprovisioned areas, wear-levelled cells, or controller caches.
- Repeated overwriting is **not** equivalent to ATA Security Erase or NVMe Sanitize.
- Fragment reconstruction is a **heuristic** — unsuccessful reconstruction is reported
  honestly rather than silently omitted.
- Confidence scores are **heuristic forensic scores**, not machine-learning probabilities.
- Audit hash chain is a **hash-chain** (not a blockchain). The distinction matters.
- Verification samples sectors — it does **not** prove every physical cell was sanitised.

---

## SSD / NVMe Sanitisation Note

Software overwrite (including all multi-pass methods in this prototype) is
**not the recommended purge mechanism for SSD or NVMe** media because:

1. Flash Translation Layer (FTL) may redirect writes, leaving old data in
   unmapped cells.
2. Overprovisioned areas are not reachable by normal write commands.
3. Wear-levelling distributes writes across cells, bypassing targeted overwrite.

For SSD/NVMe purge, appropriate mechanisms include:
- ATA Security Erase Enhanced (HDDs with SE support, some SSDs)
- NVMe Format NVM with Secure Erase Setting
- NVMe Sanitize command
- TCG Opal Cryptographic Erase (if hardware FDE is present)
- Physical destruction where required

This prototype provides the **interface and workflow** for these standards
and clearly labels them as hardware-dependent.
