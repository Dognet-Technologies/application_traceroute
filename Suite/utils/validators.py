"""
validators.py - Input validation utilities for security-suite

Provides validation functions for URLs, domains, ports, and other inputs.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# Compiled regex patterns for performance
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
)

IP_V4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

IP_V6_PATTERN = re.compile(
    r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'
    r':(?::[0-9a-fA-F]{1,4}){1,7}|::)$'
)

PATH_PATTERN = re.compile(r'^[a-zA-Z0-9/_\-\.~%]+$')


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


def validate_url(url: str, require_https: bool = False) -> str:
    """
    Validate and normalize a URL.

    Args:
        url: URL to validate
        require_https: If True, reject non-HTTPS URLs

    Returns:
        Normalized URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url:
        raise ValidationError("URL cannot be empty")

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}' if require_https else f'http://{url}'

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Failed to parse URL: {e}")

    # Validate scheme
    if parsed.scheme not in ('http', 'https'):
        raise ValidationError(f"Invalid scheme: {parsed.scheme}")

    if require_https and parsed.scheme != 'https':
        raise ValidationError("HTTPS required")

    # Validate host
    if not parsed.netloc:
        raise ValidationError("URL must have a host")

    # Extract host without port
    host = parsed.netloc.split(':')[0]

    if not validate_domain(host) and not validate_ip(host):
        raise ValidationError(f"Invalid host: {host}")

    return url


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name.

    Args:
        domain: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
    if not domain:
        return False

    if len(domain) > 253:
        return False

    # Check for localhost
    if domain == 'localhost':
        return True

    return bool(DOMAIN_PATTERN.match(domain))


def validate_ip(ip: str) -> bool:
    """
    Validate an IP address (v4 or v6).

    Args:
        ip: IP address to validate

    Returns:
        True if valid, False otherwise
    """
    if not ip:
        return False

    return bool(IP_V4_PATTERN.match(ip) or IP_V6_PATTERN.match(ip))


def validate_port(port: int) -> bool:
    """
    Validate a port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid (1-65535), False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_path(path: str) -> bool:
    """
    Validate a URL path component.

    Args:
        path: Path to validate

    Returns:
        True if valid, False otherwise
    """
    if not path:
        return True  # Empty path is valid

    # Path must start with /
    if not path.startswith('/'):
        return False

    # Check for path traversal
    if '..' in path:
        return False

    return bool(PATH_PATTERN.match(path[1:]) or path == '/')


def parse_url(url: str) -> Tuple[str, str, Optional[int], str]:
    """
    Parse a URL into components.

    Args:
        url: URL to parse

    Returns:
        Tuple of (scheme, host, port, path)

    Raises:
        ValidationError: If URL is invalid
    """
    validated_url = validate_url(url)
    parsed = urlparse(validated_url)

    scheme = parsed.scheme
    host = parsed.hostname or ''
    port = parsed.port
    path = parsed.path or '/'

    return (scheme, host, port, path)


def extract_domain(url: str) -> str:
    """
    Extract domain from URL.

    Args:
        url: URL to extract domain from

    Returns:
        Domain name

    Raises:
        ValidationError: If URL is invalid
    """
    _, host, _, _ = parse_url(url)
    return host


def sanitize_filename(name: str, max_length: int = 255) -> str:
    """
    Sanitize a string for use as a filename.

    Args:
        name: String to sanitize
        max_length: Maximum filename length

    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)

    # Collapse multiple underscores
    sanitized = re.sub(r'_+', '_', sanitized)

    # Trim and limit length
    sanitized = sanitized.strip('_')[:max_length]

    return sanitized or 'unnamed'
