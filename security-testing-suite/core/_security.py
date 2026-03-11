"""Internal runtime integrity module."""

import hashlib
import hmac
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Signing material — XOR-encoded, mask 0xA5
# Do not edit manually.
# ---------------------------------------------------------------------------
_EM = bytes([
    0xC1, 0xCA, 0xC2, 0xCB, 0xC0, 0xD1, 0xFA, 0xC9,
    0xCC, 0xC6, 0xFA, 0x97, 0x95, 0x97, 0x93, 0xFA,
    0xDD, 0xEE, 0x9C, 0x86, 0xC8, 0xF5, 0x96,
])


def _sm() -> bytes:
    return bytes(b ^ 0xA5 for b in _EM)


# ---------------------------------------------------------------------------
# API credentials — XOR-encoded, masks 0x5C / 0x3A
# Do not edit manually.
# ---------------------------------------------------------------------------
_ECK = bytes([
    63, 55, 3, 56, 61, 58, 105, 109, 62, 61, 104, 104, 57, 101, 105,
    58, 107, 63, 111, 61, 58, 100, 104, 61, 56, 61, 109, 100, 63, 62,
    107, 57, 63, 57, 105, 61, 105, 107, 101, 58, 63, 61, 58,
])
_ECS = bytes([
    89, 73, 101, 13, 8, 91, 13, 89, 10, 89, 14, 95, 94, 10, 9, 3,
    12, 91, 89, 12, 8, 94, 15, 94, 94, 94, 15, 92, 9, 8, 9, 8, 14,
    89, 94, 13, 88, 15, 3, 95, 92, 94, 9,
])


def get_api_auth_params() -> dict:
    """Return WooCommerce API auth query params."""
    ck = bytes(b ^ 0x5C for b in _ECK).decode()
    cs = bytes(b ^ 0x3A for b in _ECS).decode()
    return {"consumer_key": ck, "consumer_secret": cs}


# ---------------------------------------------------------------------------
# Expected SHA-256 digest of core/license_manager.py
# Computed at release time — do not edit manually.
# ---------------------------------------------------------------------------
_CORE_DIGEST = "7774b8cdb94dffdbddb08236ff94c6f11bb07187a62314d2faa1c4c4f0a7f85c"


def _module_path() -> Path:
    return Path(__file__).parent / "license_manager.py"


def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def make_tag(data: str) -> str:
    """Return a 32-char HMAC-SHA256 tag for the given data string."""
    return hmac.new(_sm(), data.encode(), hashlib.sha256).hexdigest()[:32]


def tags_equal(a: str, b: str) -> bool:
    """Constant-time comparison of two tag strings."""
    try:
        return hmac.compare_digest(a.encode(), b.encode())
    except Exception:
        return False


def _check_environment() -> bool:
    if _CORE_DIGEST == "PLACEHOLDER":
        return True  # development / first-run mode
    try:
        p = _module_path()
        if not p.exists():
            return False
        return _file_digest(p) == _CORE_DIGEST
    except Exception:
        return False


def runtime_check() -> None:
    """Abort execution if core module integrity verification fails."""
    if not _check_environment():
        print("  [!] Internal error: component verification failed. "
              "Please reinstall the suite.")
        sys.exit(2)
