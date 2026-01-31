"""
logging_config.py - Logging configuration for security-suite

Provides structured logging with file and console handlers.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

# Module-level logger
_configured = False


def setup_logging(
    level: str = 'INFO',
    log_file: Optional[str] = None,
    log_format: Optional[str] = None
) -> logging.Logger:
    """
    Configure logging for the security suite.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        log_format: Custom format string (optional)

    Returns:
        Root logger for security_suite
    """
    global _configured

    # Default format
    if log_format is None:
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Get numeric level
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Get root logger for security_suite
    root_logger = logging.getLogger('security_suite')
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers on reconfiguration
    if _configured:
        return root_logger

    # Create formatter
    formatter = logging.Formatter(log_format)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        log_path = Path(log_file).resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    _configured = True
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Module name (will be prefixed with security_suite.)

    Returns:
        Logger instance
    """
    if not name.startswith('security_suite'):
        name = f'security_suite.{name}'

    return logging.getLogger(name)


class LogContext:
    """
    Context manager for temporary log level changes.

    Usage:
        with LogContext('security_suite.module', logging.DEBUG):
            # Detailed logging here
    """

    def __init__(self, logger_name: str, level: int):
        self.logger = logging.getLogger(logger_name)
        self.level = level
        self.old_level: Optional[int] = None

    def __enter__(self):
        self.old_level = self.logger.level
        self.logger.setLevel(self.level)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.old_level is not None:
            self.logger.setLevel(self.old_level)
        return False


def reset_logging() -> None:
    """Reset logging configuration (useful for testing)."""
    global _configured

    logger = logging.getLogger('security_suite')
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    _configured = False
