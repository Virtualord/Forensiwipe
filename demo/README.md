# ForensiWipe Demo Environment

## Overview

The demo directory contains scripts to create controlled test environments
that operate **only** on loopback image files — never on physical disks.

---

## Demo Image (`sample_disk.img`)

Created by `create_demo_image.py`. This is a 64 MB ext4 image that:

1. Has sample files planted on it (JPEG, PNG, PDF, DOCX)
2. Has those files deleted (leaving recoverable data for Module 3)
3. Can be attached as `/dev/loopX` for the drive-erase demo (Module 1)

---

## Quick Start

```bash
cd /path/to/forensiwipe

# Create the demo image (requires sudo for mount/losetup)
sudo python demo/create_demo_image.py

# Attach the image as a loopback device for the erase demo
sudo losetup --find --show demo/sample_disk.img
# → /dev/loop10  (your number may differ)

# The backend will discover /dev/loop10 in the device list
# and confirm it is backed by demo/sample_disk.img (SAFE)

# Teardown when finished
sudo python demo/create_demo_image.py --teardown
```

---

## Safety Contract

- `SAFE_MODE=true` (default): only loopback devices backed by `.img` files
  inside this directory are permitted as erase targets.
- The `target_validator.py` checks the backing file path before allowing
  any write operation.
- The validator rejects targets whose backing file is outside `SAFE_DEMO_DIR`.

---

## What Each Demo Scene Uses

| Scene | Script / Image | Purpose |
|-------|---------------|---------|
| Module 1 (Erase) | `sample_disk.img` via `/dev/loopX` | Drive erase demo |
| Module 3 (Carve) | `sample_disk.img` directly (read-only) | File carving demo |
| Audit tamper demo | SQLite audit DB (test record) | Hash chain integrity |
