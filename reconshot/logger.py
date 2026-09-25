"""
Logging, security masking, and success/failure file manager for ReconShot.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Logger name for the application
LOGGER_NAME = "reconshot"
logger = logging.getLogger(LOGGER_NAME)

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "token",
    "bearer",
    "secret",
    "private-key",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
}


def mask_sensitive_value(value: str) -> str:
    """Mask a sensitive string leaving only initial and trailing chars if long enough."""
    if not value:
        return "[EMPTY]"
    if len(value) <= 6:
        return "******"
    return f"{value[:3]}...{value[-3:]}"


def mask_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Mask sensitive HTTP header values for secure logging/reporting."""
    if not headers:
        return {}
    masked: Dict[str, str] = {}
    for key, val in headers.items():
        lower_key = key.lower()
        if any(sensitive in lower_key for sensitive in SENSITIVE_HEADER_KEYS):
            masked[key] = mask_sensitive_value(str(val))
        else:
            masked[key] = str(val)
    return masked


def mask_cookie(cookie: Dict[str, Any]) -> Dict[str, Any]:
    """Mask cookie values for secure logging/reporting."""
    masked = dict(cookie)
    if "value" in masked and masked["value"]:
        masked["value"] = mask_sensitive_value(str(masked["value"]))
    return masked


def mask_cookies(cookies: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Mask list of cookies."""
    if not cookies:
        return []
    return [mask_cookie(c) for c in cookies]


def setup_logging(
    log_file: Optional[Path] = None,
    verbose: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """
    Configure ReconShot application logger.
    Logs to file if provided, with detailed timestamp and level.
    """
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # Formatter for file logs
    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # Console stream handler for debugging if verbose and not quiet
    if verbose and not quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(
            logging.Formatter("[dim][DEBUG] %(message)s[/dim]")
        )
        logger.addHandler(console_handler)

    return logger


def log_success(success_file: Path, url: str, status_code: Optional[int] = None) -> None:
    """Append a successfully captured target URL to success.txt."""
    try:
        success_file.parent.mkdir(parents=True, exist_ok=True)
        with open(success_file, "a", encoding="utf-8") as f:
            status_str = f" [{status_code}]" if status_code else ""
            f.write(f"{url}{status_str}\n")
    except Exception as e:
        logger.debug(f"Failed to write to {success_file}: {e}")


def log_failure(failed_file: Path, url: str, reason: str = "") -> None:
    """Append a failed target URL and error reason to failed.txt."""
    try:
        failed_file.parent.mkdir(parents=True, exist_ok=True)
        with open(failed_file, "a", encoding="utf-8") as f:
            reason_str = f" - {reason}" if reason else ""
            f.write(f"{url}{reason_str}\n")
    except Exception as e:
        logger.debug(f"Failed to write to {failed_file}: {e}")
