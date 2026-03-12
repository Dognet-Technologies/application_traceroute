"""
License Manager for Security Testing Suite v4.0

Handles license validation, storage and expiration for:
- Free licenses (30 days trial)
- Monthly licenses (30 days, suffix "mo")
- Annual licenses (365 days, suffix "yr")

License formats:
  Free:    DOGNETxxxx-xxxx-xxxx-xxxxfree  (x = alphanumeric uppercase)
  Monthly: ATXXX_XXX_XXX_XXXmo
  Annual:  ATXXX_XXX_XXX_XXXyr
  (X = character from: ABCDEFGHILMENOPQRSTUVZXWYJK1234567890)

Online validation via dognet.tech REST API:
  Activate:   GET /wp-json/lmfwc/v1/licenses/activate/{license_key}
  Validate:   GET /wp-json/lmfwc/v1/licenses/validate/{activation_token}
  Deactivate: GET /wp-json/lmfwc/v1/licenses/deactivate/{activation_token}
"""

import os
import re
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    from ._security import (
        make_tag as _make_tag,
        tags_equal as _tags_equal,
        runtime_check as _runtime_check,
        get_api_auth_params as _get_api_auth_params,
    )
except ImportError:
    try:
        from core._security import (
            make_tag as _make_tag,
            tags_equal as _tags_equal,
            runtime_check as _runtime_check,
            get_api_auth_params as _get_api_auth_params,
        )
    except ImportError:
        print("  [!] Internal error: required component missing. Please reinstall.")
        import sys; sys.exit(2)

# Valid characters for paid license chunks
LICENSE_CHARSET = set("ABCDEFGHILMENOPQRSTUVZXWYJK1234567890")

# Regex for free licenses: DOGNET + 4 chunks of 4 alphanumeric chars separated by - + free
FREE_LICENSE_PATTERN = re.compile(
    r'^DOGNET[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}free$'
)

# License file location
LICENSE_DIR = Path.home() / ".application_traceroute"
LICENSE_FILE = LICENSE_DIR / "license.json"

# Online API base URL
API_BASE_URL = "https://dognet.tech/wp-json/dlm/v1"
API_TIMEOUT = 10  # seconds

# Regex for paid licenses: AT_XXX_XXX_XXX_XXX followed by yr or mo
PAID_LICENSE_PATTERN = re.compile(
    r'^AT([ABCDEFGHILMENOPQRSTUVZXWYJK1234567890]{3})_'
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
                 error: str = None, activation_token: str = None,
                 expires_at: datetime = None):
        self.key = key
        self.license_type = license_type
        self.duration_days = duration_days
        self.activation_date = activation_date or datetime.now()
        self.valid = valid
        self.error = error
        self.activation_token = activation_token
        self._expires_at_override = expires_at

    @property
    def expiration_date(self) -> datetime:
        if self._expires_at_override:
            return self._expires_at_override
        return self.activation_date + timedelta(days=self.duration_days)

    @property
    def days_remaining(self) -> int:
        delta = self.expiration_date - datetime.now()
        return max(0, delta.days)

    @property
    def is_expired(self) -> bool:
        return datetime.now() > self.expiration_date

    def to_dict(self) -> dict:
        d = {
            "key": self.key,
            "license_type": self.license_type,
            "duration_days": self.duration_days,
            "activation_date": self.activation_date.isoformat(),
            "checksum": self._checksum(),
        }
        if self.activation_token:
            d["activation_token"] = self.activation_token
        if self._expires_at_override:
            d["expires_at"] = self._expires_at_override.isoformat()
        return d

    def _checksum(self) -> str:
        """HMAC-SHA256 tag for stored license data."""
        data = f"{self.key}:{self.license_type}:{self.activation_date.isoformat()}"
        return _make_tag(data)

    @classmethod
    def from_dict(cls, data: dict) -> 'LicenseInfo':
        """Restore license info from stored dict."""
        activation = datetime.fromisoformat(data["activation_date"])
        expires_at = None
        if "expires_at" in data:
            try:
                expires_at = datetime.fromisoformat(data["expires_at"])
            except (ValueError, TypeError):
                pass
        info = cls(
            key=data["key"],
            license_type=data["license_type"],
            duration_days=data["duration_days"],
            activation_date=activation,
            activation_token=data.get("activation_token"),
            expires_at=expires_at,
        )
        # Verify HMAC tag integrity (timing-safe)
        stored_checksum = data.get("checksum", "")
        if stored_checksum and not _tags_equal(stored_checksum, info._checksum()):
            info.valid = False
            info.error = "License file has been tampered with"
        return info

    def __repr__(self):
        status = "VALID" if self.valid and not self.is_expired else "EXPIRED"
        return (f"LicenseInfo(type={self.license_type}, status={status}, "
                f"days_remaining={self.days_remaining})")


# ---------------------------------------------------------------------------
# Online API helpers
# ---------------------------------------------------------------------------

def _parse_api_expires_at(value: str | None) -> datetime | None:
    """Parse expiresAt from API response (handles multiple formats)."""
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _online_activate(key: str) -> dict | None:
    """
    Call online activation API.
    Returns the parsed 'data' dict on success, None on failure.
    """
    if not _REQUESTS_AVAILABLE:
        return None
    try:
        url = f"{API_BASE_URL}/licenses/activate/{key}"
        resp = _requests.get(url, params=_get_api_auth_params(), timeout=API_TIMEOUT)
        if resp.status_code == 200:
            body = resp.json()
            if body.get("success"):
                return body.get("data", {})
    except Exception:
        pass
    return None


def _online_validate(token: str) -> dict | None:
    """
    Validate license online using activation token.
    Returns the parsed 'data' dict on success, None on failure.
    """
    if not _REQUESTS_AVAILABLE:
        return None
    try:
        url = f"{API_BASE_URL}/licenses/validate/{token}"
        resp = _requests.get(url, params=_get_api_auth_params(), timeout=API_TIMEOUT)
        if resp.status_code == 200:
            body = resp.json()
            if body.get("success"):
                return body.get("data", {})
    except Exception:
        pass
    return None


def _online_deactivate(token: str) -> bool:
    """
    Deactivate license online using activation token.
    Returns True on success, False otherwise.
    """
    if not _REQUESTS_AVAILABLE:
        return False
    try:
        url = f"{API_BASE_URL}/licenses/deactivate/{token}"
        resp = _requests.get(url, params=_get_api_auth_params(), timeout=API_TIMEOUT)
        if resp.status_code == 200:
            body = resp.json()
            return bool(body.get("success"))
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Core license functions
# ---------------------------------------------------------------------------

def validate_license_key(key: str) -> LicenseInfo:
    """
    Validate a license key format and return LicenseInfo.
    Does NOT perform online validation — use activate_license() for that.

    Supported formats:
    - Free:    DOGNETxxxx-xxxx-xxxx-xxxxfree  (30 days)
    - Monthly: ATXXX_XXX_XXX_XXXmo            (30 days)
    - Annual:  ATXXX_XXX_XXX_XXXyr            (365 days)
    """
    key = key.strip()

    # Check free license
    if FREE_LICENSE_PATTERN.match(key):
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


def load_license() -> 'LicenseInfo | None':
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
    """
    Validate and activate a license key.

    For all license types (free, monthly, annual):
      1. Validates the key format locally.
      2. Calls the online activation API to obtain an activation token.
      3. Stores the token and API-provided expiration date locally.

    Returns LicenseInfo (check .valid and .error for outcome).
    """
    info = validate_license_key(key)
    if not info.valid:
        return info

    # Deactivate any previously stored license before activating the new one
    existing = load_license()
    if existing and existing.activation_token:
        _online_deactivate(existing.activation_token)

    api_data = _online_activate(key)
    if api_data is not None:
        token = api_data.get("token") or api_data.get("activationToken")
        expires_raw = api_data.get("expiresAt") or api_data.get("expires_at")
        expires_at = _parse_api_expires_at(expires_raw)

        if token:
            info.activation_token = token
        if expires_at:
            info._expires_at_override = expires_at
    else:
        # Network unavailable — accept local format validation but mark as offline
        print("  [WARNING] Could not reach license server. "
              "License activated locally (offline mode).")

    save_license(info)
    return info


def check_license() -> 'LicenseInfo | None':
    """
    Check the current license status.

    For licenses with an activation token:
      - Calls the online validate API.
      - On network failure, falls back to local expiration check.

    Returns LicenseInfo if a valid, non-expired license exists, None otherwise.
    """
    info = load_license()
    if info is None:
        return None
    if not info.valid:
        return None

    # Online validation for all licenses that have a token
    if info.activation_token:
        api_data = _online_validate(info.activation_token)
        if api_data is not None:
            # API responded — trust it
            # Status: 2=delivered/active, 3=active; anything else = invalid
            status = api_data.get("status")
            expires_raw = api_data.get("expiresAt") or api_data.get("expires_at")
            expires_at = _parse_api_expires_at(expires_raw)

            if expires_at:
                info._expires_at_override = expires_at
                # Persist updated expiry
                save_license(info)

            if status is not None and status not in (2, 3):
                info.valid = False
                info.error = f"License is not active (status={status})"
                return None

            if info.is_expired:
                info.valid = False
                info.error = "License has expired"
                return info

            return info
        else:
            # Network unavailable — fall back to local expiration check
            pass

    # Local expiration check (offline fallback)
    if info.is_expired:
        info.valid = False
        info.error = "License has expired"
        return info

    return info


def deactivate_license() -> bool:
    """
    Deactivate the current license.

    Calls the online deactivation API if a token is available,
    then removes the local license file.

    Returns True if successfully deactivated, False otherwise.
    """
    info = load_license()
    if info is None:
        return False

    online_ok = False
    if info.activation_token:
        online_ok = _online_deactivate(info.activation_token)

    # Always remove local file regardless of online result
    if LICENSE_FILE.exists():
        LICENSE_FILE.unlink()

    return online_ok or info.activation_token is None


def require_license() -> LicenseInfo:
    """
    Enforce license check at application startup.
    Returns valid LicenseInfo or prompts for activation.
    Exits if no valid license is provided.
    """
    _runtime_check()
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

    if info.license_type == LicenseType.FREE:
        online = " [local]"
    elif info.activation_token:
        online = " [online]"
    else:
        online = " [offline]"
    print(f"\n  License: {type_label}{online} | "
          f"Expires: {info.expiration_date.strftime('%Y-%m-%d')} | "
          f"Days remaining: {info.days_remaining}")
