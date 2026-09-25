"""
Unit tests for browser manager configuration, error classification, and options.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from reconshot.browser import (
    BrowserError,
    BrowserManager,
    BrowserNotInstalledError,
    DEFAULT_DESKTOP_UA,
    DEFAULT_MOBILE_UA,
)
from reconshot.models import ScanOptions, ViewportConfig
from reconshot.screenshot import classify_error


def test_classify_error_messages():
    e1 = Exception("net::ERR_NAME_NOT_RESOLVED at https://dead.test")
    assert classify_error(e1) == "DNS resolution failed"

    e2 = Exception("net::ERR_CONNECTION_REFUSED at https://127.0.0.1:9999")
    assert classify_error(e2) == "Connection refused"

    e3 = Exception("Timeout 30000ms exceeded while navigating to https://slow.test")
    assert classify_error(e3) == "Connection timed out"

    e4 = Exception("net::ERR_CERT_AUTHORITY_INVALID")
    assert classify_error(e4) == "SSL/TLS handshake error"

    e5 = Exception("Custom unexpected internal error message")
    assert classify_error(e5) == "Custom unexpected internal error message"


def test_browser_manager_context_args():
    opts = ScanOptions(
        viewport=ViewportConfig.mobile(),
        headers={"X-Custom": "test"},
        cookies=[{"name": "sess", "value": "123"}],
        timeout=15,
    )
    bm = BrowserManager(opts)
    assert bm.options.viewport.is_mobile is True
    assert bm.options.timeout == 15


def test_browser_manager_launch_not_installed():
    async def _test():
        opts = ScanOptions()
        bm = BrowserManager(opts)

        mock_pw = MagicMock()
        mock_pw.chromium.launch = AsyncMock(
            side_effect=Exception("Executable doesn't exist at /root/.cache/ms-playwright/chromium")
        )

        with patch("reconshot.browser.async_playwright") as mock_apw:
            mock_start = AsyncMock(return_value=mock_pw)
            mock_apw.return_value.start = mock_start

            with pytest.raises(BrowserNotInstalledError) as exc_info:
                await bm.initialize()

            assert "playwright install chromium" in str(exc_info.value)

    asyncio.run(_test())
