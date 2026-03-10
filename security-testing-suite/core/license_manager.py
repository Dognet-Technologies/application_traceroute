"""
License Manager for Security Testing Suite v4.0

Handles license validation, storage and expiration for:
- Free licenses (30 days trial)
- Monthly licenses (30 days, suffix "mo")
- Annual licenses (365 days, suffix "yr")

License formats:
  Free:    DOGNETDA3-DAD-B3Dfree
  Monthly: AT_XXX_XXX_XXX_XXXmo
  Annual:  AT_XXX_XXX_XXX_XXXyr
  (X = character from: ABCDEFGHILMENOPQRSTUVZXWYJK1234567890)
"""

import os
import re
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# Valid characters for paid license chunks
LICENSE_CHARSET = set("ABCDEFGHILMENOPQRSTUVZXWYJK1234567890")

# Known free license keys
FREE_LICENSE_KEYS = {
    "DOGNETDA3-DAD-B3Dfree",
}

# License file location
LICENSE_DIR = Path.home() / ".application_traceroute"
LICENSE_FILE = LICENSE_DIR / "license.json"

# Regex for paid licenses: AT_XXX_XXX_XXX_XXX followed by yr or mo
PAID_LICENSE_PATTERN = re.compile(
    r'^AT_([ABCDEFGHILMENOPQRSTUVZXWYJK1234567890]{3})_'
    r'([ABCDEFGHILMENOPQRSTUVZXWYJK1234567890]{3})_'
    r'([ABCDEFGHILMENOPQRSTUVZXWYJK1234567890]{3})_'
    r'([ABCDEFGHILMENOPQRSTUVZXWYJK1234567890]{3})(yr|mo)$'
)


class LicenseType:
    FREE = "free"
    MONTHLY = "monthly"
    ANNUAL = "annual"


class LicenseInfo:
    """Holds parsed license information."""

    def __init__(self, key: str, license_type: str, duration_days: int,
                 activation_date: datetime = None, valid: bool = True,
                 error: str = None):
        self.key = key
        self.license_type = license_type
        self.duration_days = duration_days
        self.activation_date = activation_date or datetime.now()
        self.valid = valid
        self.error = error

    @property
    def expiration_date(self) -> datetime:
        return self.activation_date + timedelta(days=self.duration_days)

    @property
    def days_remaining(self) -> int:
        delta = self.expiration_date - datetime.now()
        return max(0, delta.days)

    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expiration_date

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "license_type": self.license_type,
            "duration_days": self.duration_days,
            "activation_date": self.activation_date.isoformat(),
            "checksum": self._checksum(),
        }

    def _checksum(self) -> str:
        """Simple integrity checksum for stored license data."""
        data = f"{self.key}:{self.license_type}:{self.activation_date.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    @classmethod
    def from_dict(cls, data: dict) -> 'LicenseInfo':
        """Restore license info from stored dict."""
        activation = datetime.fromisoformat(data["activation_date"])
        info = cls(
            key=data["key"],
            license_type=data["license_type"],
            duration_days=data["duration_days"],
            activation_date=activation,
        )
        # Verify checksum integrity
        stored_checksum = data.get("checksum", "")
        if stored_checksum and stored_checksum != info._checksum():
            info.valid = False
            info.error = "License file has been tampered with"
        return info

    def __repr__(self):
        status = "VALID" if self.valid and not self.is_expired else "EXPIRED"
        return (f"LicenseInfo(type={self.license_type}, status={status}, "
                f"days_remaining={self.days_remaining})")


def validate_license_key(key: str) -> LicenseInfo:
    """
    Validate a license key and return LicenseInfo.

    Supported formats:
    - Free:    DOGNETDA3-DAD-B3Dfree  (30 days)
    - Monthly: AT_XXX_XXX_XXX_XXXmo   (30 days)
    - Annual:  AT_XXX_XXX_XXX_XXXyr   (365 days)
    """
    key = key.strip()

    # Check free license
    if key in FREE_LICENSE_KEYS:
        return LicenseInfo(
            key=key,
            license_type=LicenseType.FREE,
            duration_days=30,
        )

    # Check paid license format
    match = PAID_LICENSE_PATTERN.match(key)
    if match:
        suffix = match.group(5)
        if suffix == "yr":
            return LicenseInfo(
                key=key,
                license_type=LicenseType.ANNUAL,
                duration_days=365,
            )
        elif suffix == "mo":
            return LicenseInfo(
                key=key,
                license_type=LicenseType.MONTHLY,
                duration_days=30,
            )

    # Invalid format
    return LicenseInfo(
        key=key,
        license_type="unknown",
        duration_days=0,
        valid=False,
        error="Invalid license key format",
    )


def save_license(info: LicenseInfo) -> None:
    """Save activated license to disk."""
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    with open(LICENSE_FILE, 'w') as f:
        json.dump(info.to_dict(), f, indent=2)


def load_license() -> LicenseInfo | None:
    """Load saved license from disk, returns None if not found."""
    if not LICENSE_FILE.exists():
        return None
    try:
        with open(LICENSE_FILE, 'r') as f:
            data = json.load(f)
        return LicenseInfo.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def activate_license(key: str) -> LicenseInfo:
    """Validate and activate a license key, saving it to disk."""
    info = validate_license_key(key)
    if info.valid:
        save_license(info)
    return info


def check_license() -> LicenseInfo | None:
    """
    Check the current license status.
    Returns LicenseInfo if a valid, non-expired license exists, None otherwise.
    """
    info = load_license()
    if info is None:
        return None
    if not info.valid:
        return None
    if info.is_expired:
        info.valid = False
        info.error = "License has expired"
        return info
    return info


def require_license() -> LicenseInfo:
    """
    Enforce license check at application startup.
    Returns valid LicenseInfo or prompts for activation.
    Exits if no valid license is provided.
    """
    info = check_license()

    if info is not None and info.valid and not info.is_expired:
        _print_license_status(info)
        return info

    # Show expired message if applicable
    if info is not None and info.is_expired:
        print("\n" + "=" * 60)
        print("  LICENSE EXPIRED")
        print(f"  Your {info.license_type} license expired on "
              f"{info.expiration_date.strftime('%Y-%m-%d')}")
        print("=" * 60)

    # Prompt for license key
    print("\n" + "=" * 60)
    print("  SECURITY TESTING SUITE v4.0 - LICENSE REQUIRED")
    print("=" * 60)
    print()
    print("  License types:")
    print("    - Free trial (30 days)")
    print("    - Monthly   (30 days)  - suffix 'mo'")
    print("    - Annual    (365 days) - suffix 'yr'")
    print()

    while True:
        try:
            key = input("  Enter license key: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            raise SystemExit(1)

        if not key:
            print("  No key entered. Exiting.")
            raise SystemExit(1)

        info = activate_license(key)

        if info.valid:
            print(f"\n  License activated successfully!")
            _print_license_status(info)
            return info
        else:
            print(f"  Invalid license key: {info.error}")
            print("  Please try again.\n")


def _print_license_status(info: LicenseInfo) -> None:
    """Print license status banner."""
    type_label = {
        LicenseType.FREE: "FREE TRIAL",
        LicenseType.MONTHLY: "MONTHLY",
        LicenseType.ANNUAL: "ANNUAL",
    }.get(info.license_type, info.license_type.upper())

    print(f"\n  License: {type_label} | "
          f"Expires: {info.expiration_date.strftime('%Y-%m-%d')} | "
          f"Days remaining: {info.days_remaining}")
