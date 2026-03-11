#!/usr/bin/env python3
"""
Utility: update the _CORE_DIGEST in core/_security.py after modifying license_manager.py.

Run this script every time license_manager.py is changed:
    python3 tools/update_digest.py
"""

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
LM = ROOT / "core" / "license_manager.py"
SEC = ROOT / "core" / "_security.py"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    digest = sha256_file(LM)
    print(f"license_manager.py SHA256: {digest}")

    text = SEC.read_text()
    new_text = re.sub(
        r'_CORE_DIGEST\s*=\s*"[^"]*"',
        f'_CORE_DIGEST = "{digest}"',
        text,
    )
    if new_text == text:
        if f'_CORE_DIGEST = "{digest}"' in text:
            print("Digest already up to date. Nothing changed.")
            return
        print("ERROR: could not find _CORE_DIGEST pattern in _security.py")
        raise SystemExit(1)

    SEC.write_text(new_text)
    print("Updated _security.py with new digest.")


if __name__ == "__main__":
    main()
