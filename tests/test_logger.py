"""
Unit tests for logger, sensitive header masking, and success/failed loggers.
"""

from pathlib import Path
import pytest
from reconshot.logger import (
    log_failure,
    log_success,
    mask_cookie,
    mask_cookies,
    mask_headers,
    mask_sensitive_value,
    setup_logging,
)


def test_mask_sensitive_value():
    assert mask_sensitive_value("123456") == "******"
    assert mask_sensitive_value("my_super_secret_token_12345") == "my_...345"
    assert mask_sensitive_value("") == "[EMPTY]"


def test_mask_headers():
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "X-API-KEY": "secret_api_key_value",
        "User-Agent": "ReconShot/1.0",
    }
    masked = mask_headers(headers)
    assert masked["Content-Type"] == "application/json"
    assert masked["User-Agent"] == "ReconShot/1.0"
    assert "Bearer" not in masked["Authorization"] or "..." in masked["Authorization"]
    assert "..." in masked["X-API-KEY"]


def test_mask_cookies():
    cookies = [
        {"name": "session", "value": "secret_cookie_payload_12345", "domain": ".example.com"}
    ]
    masked = mask_cookies(cookies)
    assert masked[0]["name"] == "session"
    assert "..." in masked[0]["value"]


def test_log_success_and_failure(tmp_path: Path):
    success_file = tmp_path / "success.txt"
    failed_file = tmp_path / "failed.txt"

    log_success(success_file, "https://example.com", 200)
    log_failure(failed_file, "https://dead.example.com", "Connection refused")

    assert success_file.exists()
    assert "https://example.com [200]" in success_file.read_text()

    assert failed_file.exists()
    assert "https://dead.example.com - Connection refused" in failed_file.read_text()
