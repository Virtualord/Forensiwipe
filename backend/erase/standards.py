"""
erase/standards.py — Erasure standard definitions and metadata.

IMPORTANT: These descriptions are technically accurate.
We do NOT claim overwrite-based methods are equivalent to hardware-level
sanitisation for SSDs/NVMe.  Every standard is labelled honestly.
"""

from __future__ import annotations

from backend.core.models import EraseStandard
from backend.erase.models import StandardInfo


STANDARDS: dict[EraseStandard, StandardInfo] = {

    EraseStandard.ZERO_FILL: StandardInfo(
        id=EraseStandard.ZERO_FILL,
        name="Zero Fill",
        description=(
            "Single-pass overwrite with 0x00 bytes. "
            "Satisfies NIST SP 800-88 Clear criteria for some media. "
            "Simple and fast. Does not guarantee physical cell overwrite on SSD/NVMe."
        ),
        passes=1,
        hdd_applicable=True,
        ssd_applicable=False,
        hardware_dependent=False,
        nist_approved=True,
        notes=[
            "NIST SP 800-88: suitable for Clear on ATA/magnetic media.",
            "Not recommended as the sole mechanism for SSD/NVMe purge.",
        ],
    ),

    EraseStandard.RANDOM_FILL: StandardInfo(
        id=EraseStandard.RANDOM_FILL,
        name="Random Fill",
        description=(
            "Single-pass overwrite with cryptographically random data. "
            "Useful for obfuscating data content. "
            "Same physical limitations as Zero Fill on SSD/NVMe."
        ),
        passes=1,
        hdd_applicable=True,
        ssd_applicable=False,
        hardware_dependent=False,
        nist_approved=False,
        notes=[
            "Not a standalone NIST-approved clear/purge method.",
            "Suitable for demo and as part of multi-pass sequences.",
        ],
    ),

    EraseStandard.DOD_3PASS: StandardInfo(
        id=EraseStandard.DOD_3PASS,
        name="DoD 5220.22-M — 3 Pass",
        description=(
            "U.S. Department of Defense 5220.22-M three-pass overwrite: "
            "Pass 1: 0x00, Pass 2: 0xFF, Pass 3: random. "
            "Historically significant. No longer a current NIST recommendation. "
            "Not meaningful for SSD/NVMe flash storage."
        ),
        passes=3,
        hdd_applicable=True,
        ssd_applicable=False,
        hardware_dependent=False,
        nist_approved=False,
        warning=(
            "DoD 5220.22-M is NOT a current NIST recommendation. "
            "NIST SP 800-88 Rev 1 (2014) supersedes overwrite-based methods "
            "for modern media. This is provided for historical reference and demonstration."
        ),
        notes=[
            "Pattern: 0x00 → 0xFF → random",
            "Not recommended for production SSD sanitisation.",
            "Included for demonstration and historical reference.",
        ],
    ),

    EraseStandard.GUTMANN_35: StandardInfo(
        id=EraseStandard.GUTMANN_35,
        name="Gutmann — 35 Pass",
        description=(
            "Peter Gutmann's 1996 35-pass overwrite algorithm. "
            "Designed for older MFM/RLL disk encoding. "
            "Excessive for modern drives. Not effective on SSD/NVMe. "
            "Included for demonstration only."
        ),
        passes=35,
        hdd_applicable=True,
        ssd_applicable=False,
        hardware_dependent=False,
        nist_approved=False,
        warning=(
            "Gutmann 35-pass is historically significant but generally considered "
            "excessive for modern hard drives (post-2001 perpendicular recording). "
            "It is NOT recommended for SSDs or NVMe. "
            "Gutmann himself noted in 1996 that some passes only apply to specific "
            "older encoding schemes."
        ),
        notes=[
            "35 passes: specific patterns + random fills.",
            "Included for demonstration and educational reference.",
            "For modern drives, NIST SP 800-88 Clear/Purge is preferred.",
        ],
    ),

    EraseStandard.NIST_CLEAR: StandardInfo(
        id=EraseStandard.NIST_CLEAR,
        name="NIST SP 800-88 Clear",
        description=(
            "NIST SP 800-88 Rev 1 Clear: logical overwrite using the native "
            "write command to all user-addressable locations. "
            "Appropriate for media to be reused within the same security domain. "
            "Not effective on SSD overprovisioned areas via software writes alone."
        ),
        passes=1,
        hdd_applicable=True,
        ssd_applicable=False,
        hardware_dependent=False,
        nist_approved=True,
        notes=[
            "NIST SP 800-88 Rev 1 (December 2014).",
            "Software overwrite — does not reach all SSD physical cells.",
            "Suitable for drives being reused within the same organisation.",
        ],
    ),

    EraseStandard.NIST_PURGE: StandardInfo(
        id=EraseStandard.NIST_PURGE,
        name="NIST SP 800-88 Purge",
        description=(
            "NIST SP 800-88 Rev 1 Purge: hardware-dependent sanitisation. "
            "For ATA drives: ATA Security Erase command. "
            "For NVMe: NVMe Format or Sanitize command. "
            "For SSD: device-supported cryptographic erase or controller sanitise. "
            "This prototype does NOT execute hardware Purge commands."
        ),
        passes=1,
        hdd_applicable=True,
        ssd_applicable=True,
        hardware_dependent=True,
        nist_approved=True,
        warning=(
            "Hardware-dependent Purge — NOT executed by this prototype. "
            "Actual ATA Security Erase, NVMe Format/Sanitize, or controller-level "
            "cryptographic erase is required. This interface demonstrates the workflow "
            "and requirements only."
        ),
        notes=[
            "Requires ATA Security Erase / NVMe Sanitize / Crypto Erase.",
            "PROTOTYPE: interface demonstration only.",
            "Do not use this prototype to certify media as purged.",
        ],
    ),

    EraseStandard.CRYPTO_ERASE: StandardInfo(
        id=EraseStandard.CRYPTO_ERASE,
        name="Cryptographic Erase",
        description=(
            "Render data unrecoverable by destroying the encryption key "
            "when the target device uses hardware full-disk encryption. "
            "Requires hardware FDE support. "
            "This prototype demonstrates the concept only."
        ),
        passes=1,
        hdd_applicable=False,
        ssd_applicable=True,
        hardware_dependent=True,
        nist_approved=True,
        warning=(
            "SIMULATION / DEMONSTRATION ONLY. "
            "Real cryptographic erase requires hardware FDE (Full Disk Encryption). "
            "This prototype does not issue controller-level key destruction commands. "
            "Do not use this prototype to certify media as cryptographically erased."
        ),
        notes=[
            "TCG Opal, ATA Crypto Scramble Ext, or NVMe Crypto Erase required.",
            "PROTOTYPE: concept demonstration only.",
        ],
    ),
}


def get_standard_info(standard: EraseStandard) -> StandardInfo:
    return STANDARDS[standard]


def list_standards() -> list[StandardInfo]:
    return list(STANDARDS.values())
