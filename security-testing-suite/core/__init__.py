"""
Core security testing modules
"""

from .license_manager import (
    require_license,
    check_license,
    activate_license,
    validate_license_key,
    LicenseInfo,
    LicenseType,
)

__version__ = "4.0.0"
