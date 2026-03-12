"""
Core security testing modules
"""

from .license_manager import (
    require_license,
    check_license,
    activate_license,
    deactivate_license,
    validate_license_key,
    LicenseInfo,
    LicenseType,
)
from ._security import runtime_check

__version__ = "4.0.1"
