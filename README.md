# ForensiWipe

**Secure Erasure • Intelligent Recovery • Evidential Audit**

> SIH 2026 — Problem Statement 26149
> Organisation: NTRO
> Theme: Cybersecurity / Blockchain & Cybersecurity

---

## What is ForensiWipe?

ForensiWipe is a professional digital-forensics and data-sanitisation tool that
integrates three capabilities into one coherent application:

| Module | Capability |
|---|---|
| **Module 1** — Secure Drive Eraser | Erase storage devices using NIST SP 800-88, DoD 5220.22-M, Gutmann, and crypto-erase workflows with tamper-evident audit logging |
| **Module 2** — Secure File & Folder Eraser | Selectively erase files/folders, sanitise metadata, and scan for residual traces |
| **Module 3** — Advanced File Carving | Recover deleted files from raw disk images using signature-based carving, structural validation, confidence scoring, and JPEG fragment reconstruction |

All modules share a single hash-chained audit database, PDF/JSON report system,
and WebSocket-based live progress layer.

---

## Key Design Principles

**Safety by architecture, not by warning message.**
Every destructive operation passes through a single target validator with 12 checks.
Safe mode (`SAFE_MODE=true`) is the default and cannot be bypassed by the frontend.

**Forensic honesty.**
The application distinguishes clearly between what is implemented, what is simulated,
and what is hardware-dependent. It does not claim that overwriting an SSD constitutes
a hardware-level secure erase.

**Tamper-evident audit trail.**
Every operation produces a hash-chained audit record. The chain can be verified
with one API call — a broken chain is immediately visible on the dashboard.

**Evidence preservation.**
Source disk images are always opened read-only. Recovered files are written to a
separate output directory. Evidence SHA-256 is computed before and after every scan.

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│              React Dashboard             │
│  Safe Mode Banner │ Progress │ Audit UI  │
└──────────────────┬──────────────────────┘
                   │ HTTP / WebSocket
┌──────────────────▼──────────────────────┐
│           FastAPI Backend (Python)       │
│                                         │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ target_     │  │  audit/          │  │
│  │ validator   │  │  hash_chain      │  │
│  │ (12 checks) │  │  service         │  │
│  └──────┬──────┘  └──────────────────┘  │
│         │                               │
│  ┌──────▼──────┐  ┌──────────────────┐  │
│  │ erase/      │  │  carve/          │  │
│  │ engine      │  │  scanner         │  │
│  └─────────────┘  └──────────────────┘  │
└─────────────────────────────────────────┘
                   │
       ┌───────────▼───────────┐
       │  SQLite Audit DB      │
       │  (hash-chained log)   │
       └───────────────────────┘
```

---

## Quick Start

```bash
# 1. Set up virtual environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

# 2. Configure
cp .env.example .env
# Edit SAFE_DEMO_DIR to your absolute path

# 3. Run tests
PYTHONPATH=. pytest tests/ -v --asyncio-mode=auto

# 4. Create demo image
sudo python demo/create_demo_image.py

# 5. Attach loopback
sudo losetup --find --show demo/sample_disk.img
# → /dev/loop10

# 6. Start backend
PYTHONPATH=. uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# 7. In another terminal, start dashboard
cd frontend && npm install && npm run dev
```

Full instructions: see [SETUP.md](SETUP.md)

---

## API Endpoints (Phase 1)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Liveness check |
| `GET` | `/api/status` | Safety state and mode |
| `GET` | `/api/devices` | Discovered storage devices |
| `GET` | `/api/erase/standards` | Available erasure standards |
| `POST` | `/api/erase/validate` | Validate a target (dry run) |
| `POST` | `/api/erase/start` | Start erase operation |
| `GET` | `/api/operations` | List all operations |
| `GET` | `/api/operations/{id}` | Operation status and progress |
| `POST` | `/api/operations/{id}/cancel` | Cancel running operation |
| `GET` | `/api/audit/history` | Audit record history |
| `POST` | `/api/audit/verify` | Verify hash chain integrity |
| `GET` | `/api/audit/latest-hash` | Current chain head |
| `POST` | `/api/reports/{operation_id}/generate` | Generate JSON/PDF operation report |
| `GET` | `/api/reports/{operation_id}?format=pdf` | Download operation report |
| `WS` | `/ws/operations/{id}` | Real-time progress stream |

Interactive docs: http://127.0.0.1:8000/docs

---

## Hackathon Demo Scenario (5–7 minutes)

| Scene | What to show |
|---|---|
| **1. Dashboard** | `SAFE MODE ENABLED`, device list, system-disk protection |
| **2. Drive Erase** | Select `/dev/loop10`, DoD 3-pass, live progress, verification PASSED |
| **3. Carving** | Open `sample_disk.img`, scan, recover JPEG/PNG/PDF in real time |
| **4. Evidence Integrity** | SHA-256 before/after → `Evidence unchanged` |
| **5. Audit** | Hash chain display → `✓ HASH CHAIN VERIFIED` |
| **6. Tamper Demo** | Alter a TEST audit record → `✕ TAMPERING DETECTED` at record N |

---

## Safety Guarantees

- `SAFE_MODE=true` is the hard default — no physical disk access without explicit config change
- Physical erase requires **both** `SAFE_MODE=false` **and** `ALLOW_PHYSICAL_ERASE=true`
- Physical targets require the operator to type the exact device path — twice
- All destructive calls pass through `target_validator.py` — no bypass path exists
- Demo images must reside inside `SAFE_DEMO_DIR` — path traversal is checked

---

## Development Phases

| Phase | Status | Contents |
|---|---|---|
| **Phase 1** | ✅ Complete | Module 1 (drive eraser) + audit system + backend + tests |
| **Phase 2** | ✅ Complete | Module 3 (file carving) |
| **Phase 3** | ✅ Complete | Module 2 (file/folder eraser) |
| **Phase 4** | ✅ Complete | React dashboard + PDF/JSON reports + unified monitoring |
| **Phase 5** | ✅ Complete | Integration tests, documentation, demo workflow, compatibility review |

---

## Capability Scope

See [SCOPE.md](SCOPE.md) for a full feature/status matrix, including explicit
statements of what is not implemented and why.

---

## License

Built for Smart India Hackathon 2026 — demonstration prototype.
