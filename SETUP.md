# ForensiWipe — Setup Guide

**SIH 2026 — PS 26149 | NTRO | Cybersecurity**

This guide covers everything needed to run ForensiWipe on Ubuntu 22.04 / 24.04
from a clean checkout. Windows instructions are in the [Windows section](#windows).

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Python | 3.11+ | 3.13 tested |
| Node.js | 18+ | For the React frontend (Phase 4) |
| npm | 9+ | Bundled with Node.js |
| losetup | Any recent | Part of `util-linux` |
| mkfs.ext4 | Any recent | Part of `e2fsprogs` |
| sudo | — | Required only for demo image mount/unmount |

---

## Ubuntu / Linux Setup

### 1. System packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
    util-linux e2fsprogs psmisc
```

### 2. Clone / extract the project

```bash
# If using git:
git clone <repo-url> forensiwipe
cd forensiwipe

# Or extract the archive:
unzip forensiwipe.zip
cd forensiwipe
```

### 3. Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

Verify the key packages installed:

```bash
python -c "import fastapi, pydantic, psutil, PIL, sqlite3; print('OK')"
# Expected: OK
```

### 5. Configure environment

```bash
cp .env.example .env
```

Edit `.env` if needed. The defaults are correct for local development.
The critical setting is:

```
SAFE_MODE=true          # MUST remain true for demos
ALLOW_PHYSICAL_ERASE=false
SAFE_DEMO_DIR=/absolute/path/to/forensiwipe/demo
```

Update `SAFE_DEMO_DIR` to the absolute path of your `demo/` directory:

```bash
# Replace with your actual path:
sed -i "s|SAFE_DEMO_DIR=.*|SAFE_DEMO_DIR=$(pwd)/demo|" .env
sed -i "s|AUDIT_DB_PATH=.*|AUDIT_DB_PATH=$(pwd)/forensiwipe_audit.db|" .env
sed -i "s|RECOVERED_DIR=.*|RECOVERED_DIR=$(pwd)/recovered|" .env
sed -i "s|REPORTS_DIR=.*|REPORTS_DIR=$(pwd)/reports_output|" .env
```

### 6. Run tests

```bash
PYTHONPATH=. .venv/bin/pytest tests/ -v --asyncio-mode=auto
```

Expected output: `157 passed`.

### 7. Start the backend server

```bash
PYTHONPATH=. .venv/bin/uvicorn backend.main:app \
    --host 127.0.0.1 --port 8000 --reload
```

Verify:

```bash
curl http://127.0.0.1:8000/api/health
# {"status":"ok","timestamp":"..."}

curl http://127.0.0.1:8000/api/status
# {"app_name":"ForensiWipe","safety":{"safe_mode":true,...}}
```

OpenAPI docs are available at: http://127.0.0.1:8000/docs

### 8. Start the React dashboard

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite (normally http://127.0.0.1:5173). The dashboard
uses polling as its safe fallback for operation updates; it never runs shell
commands or destructive actions directly.

---

## Demo Image Setup (Required for hackathon demo)

The demo image creates a controlled loopback disk for Module 1 and Module 3.
**It never touches a physical disk.**

### Create the demo image

```bash
# Requires sudo for mount/losetup — only during image creation
sudo python demo/create_demo_image.py
```

Expected output:

```
ForensiWipe Demo Image Creator
SAFETY: Only operates on files inside ./demo/
...
[2/8] Creating 64 MB sparse image at /path/to/demo/sample_disk.img...
[3/8] Formatting image as ext4...
[4/8] Attaching loopback device...
  Attached: /dev/loop10 → .../demo/sample_disk.img
[5/8] Mounting /dev/loop10 at .../demo/mnt...
[6/8] Seeding sample files...
  Created sample_photo_001.jpg    SHA-256: abc123...  (319 bytes)
  Created sample_photo_002.jpg    SHA-256: def456...  (319 bytes)
  Created sample_diagram.png      SHA-256: ...
  Created sample_report.pdf       SHA-256: ...
  Created sample_document.docx    SHA-256: ...
[7/8] Deleting planted files...
[8/8] Unmounting and detaching...

Demo image ready!
  Image:    .../demo/sample_disk.img
  Manifest: .../demo/demo_manifest.json

To attach for the erase demo:
  sudo losetup --find --show demo/sample_disk.img
```

### Attach for the erase demo

```bash
sudo losetup --find --show demo/sample_disk.img
# Output: /dev/loop10  (your number may differ)
```

The backend will list `/dev/loop10` in `GET /api/devices` with:
- `safety_status: "SAFE"`
- `is_loopback: true`
- `backing_file: ".../demo/sample_disk.img"`

### Erase the demo image via API

```bash
# Validate the target first:
curl -s -X POST http://127.0.0.1:8000/api/erase/validate \
  -H 'Content-Type: application/json' \
  -d '{"target": "/dev/loop10"}' | python3 -m json.tool

# Start erasure (DoD 3-pass demo):
curl -s -X POST http://127.0.0.1:8000/api/erase/start \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "/dev/loop10",
    "standard": "DOD_3PASS",
    "demo_mode": false
  }' | python3 -m json.tool

# Monitor progress (replace OP-... with the returned operation_id):
curl http://127.0.0.1:8000/api/operations/OP-20260902-...

# Verify audit chain:
curl -s -X POST http://127.0.0.1:8000/api/audit/verify | python3 -m json.tool
```

### Teardown demo

```bash
sudo python demo/create_demo_image.py --teardown
```

---

## Privilege Requirements

| Task | Privileges needed |
|---|---|
| Run backend server | Normal user |
| Run tests | Normal user |
| Create demo image | sudo (mount, losetup) |
| Attach loopback device | sudo |
| Erase loopback device | sudo (or device permission) |
| Read-only carving | Normal user |
| Audit log / reports | Normal user |

**The backend server itself does not need to run as root.**
Only `losetup` and `mount` commands (for image setup) require elevation.
Grant your user loopback device write permission with `chmod` if preferred.

---

## Windows

Windows support covers backend startup, audit, reports, carving, and the web
dashboard. Device discovery and residual-trace handling remain partial and are
explicitly labelled as such in the UI/scope document.

```powershell
# Python 3.11+
python -m venv .venv
.venv\Scripts\activate
pip install -r backend\requirements.txt

# Tests (device-specific tests are skipped on Windows automatically)
$env:PYTHONPATH = "."
pytest tests\ -v --asyncio-mode=auto

# Server
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

```powershell
cd frontend
npm install
npm run dev
```

---

## Directory Structure After Setup

```
forensiwipe/
├── .env                        ← Your local config (never commit)
├── .env.example                ← Template
├── .venv/                      ← Python virtual environment
├── forensiwipe_audit.db        ← SQLite audit log (created on first run)
├── recovered/                  ← Carved files output (Module 3)
├── reports_output/             ← Generated PDF/JSON reports (Module 4)
│
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   ├── api/          ← Route handlers
│   ├── core/         ← Config, models, tasks, events
│   ├── erase/        ← Module 1: drive eraser
│   ├── audit/        ← Hash-chain audit log
│   ├── carve/        ← Module 3: file carving (Phase 2)
│   ├── fileerase/    ← Module 2: file/folder eraser (Phase 3)
│   └── reports/      ← Report generation (Phase 4)
│
├── demo/
│   ├── create_demo_image.py
│   ├── sample_disk.img         ← Created by setup script
│   └── demo_manifest.json      ← Planted file hashes
│
└── tests/
    ├── conftest.py
    ├── test_target_validator.py
    ├── test_erase.py
    └── test_audit.py
```

---

## Troubleshooting

**`losetup: cannot open /dev/loop10: No such file or directory`**
```bash
sudo modprobe loop
```

**`mkfs.ext4: command not found`**
```bash
sudo apt install e2fsprogs
```

**`PermissionError: [Errno 13] Permission denied: '/dev/loop10'`**
The backend user needs write access to the loopback device:
```bash
sudo chmod 666 /dev/loop10
# Or run the erase operation with sudo (not recommended for the whole server)
```

**`sqlite3.OperationalError: no such table: audit_records`**
The audit DB is initialised at startup. Ensure `AUDIT_DB_PATH` is writable
and the server has completed its startup sequence before sending requests.

**Tests fail with `no such table`**
This should not happen after the conftest autouse fixture. If it does:
```bash
# Clear any stale test DB
rm -f /tmp/pytest-*/test_audit.db
PYTHONPATH=. .venv/bin/pytest tests/ -v --asyncio-mode=auto --cache-clear
```
