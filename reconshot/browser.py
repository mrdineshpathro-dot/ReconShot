"""
Browser management, Playwright lifecycle, and context generation for ReconShot.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Playwright,
    Route,
    async_playwright,
)

from reconshot.logger import logger
from reconshot.models import ScanOptions, ViewportConfig
from reconshot.stealth import encode_basic_auth, get_random_user_agent, is_resource_blocked

DEFAULT_DESKTOP_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 ReconShot/1.0"
)
DEFAULT_MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 ReconShot/1.0"
)


class BrowserError(Exception):
    """Base exception for ReconShot browser errors."""
    pass


class BrowserNotInstalledError(BrowserError):
    """Raised when Chromium or its system dependencies are not installed."""
    pass


class BrowserManager:
    """Manages the Playwright Chromium browser lifecycle."""

    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None

    async def initialize(self) -> None:
        """Launch the shared Chromium browser instance."""
        try:
            self._playwright = await async_playwright().start()
        except Exception as e:
            raise BrowserError(f"Failed to start Playwright driver: {e}") from e

        # Prepare launch arguments
        launch_args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--ignore-certificate-errors",
            "--disable-blink-features=AutomationControlled",
            "--disable-web-security",
            "--allow-running-insecure-content",
        ]

        proxy_dict: Optional[Dict[str, str]] = None
        if self.options.proxy:
            proxy_dict = {"server": self.options.proxy}

        try:
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=launch_args,
                proxy=proxy_dict,
                timeout=30000,
            )
            logger.debug("Chromium browser successfully initialized.")
        except Exception as e:
            err_msg = str(e)
            if "Executable doesn't exist" in err_msg or "playwright install" in err_msg:
                raise BrowserNotInstalledError(
                    "Playwright Chromium browser is not installed.\n"
                    "Please run: \n"
                    "  playwright install chromium\n"
                    "Or on Kali Linux / Debian:\n"
                    "  playwright install --with-deps chromium"
                ) from e
            raise BrowserError(f"Failed to launch Chromium browser: {e}") from e

    async def create_context(self) -> BrowserContext:
        """Create an isolated, pre-configured browser context."""
        if not self._browser:
            raise BrowserError("Browser is not initialized.")

        vp = self.options.viewport
        
        # Determine User-Agent
        if self.options.random_user_agent:
            user_agent = get_random_user_agent()
        elif self.options.user_agent:
            user_agent = self.options.user_agent
        else:
            user_agent = DEFAULT_MOBILE_UA if vp.is_mobile else DEFAULT_DESKTOP_UA

        context_kwargs: Dict[str, Any] = {
            "viewport": {"width": vp.width, "height": vp.height},
            "user_agent": user_agent,
            "is_mobile": vp.is_mobile,
            "has_touch": vp.has_touch,
            "device_scale_factor": vp.device_scale_factor,
            "ignore_https_errors": self.options.ignore_https_errors,
            "java_script_enabled": True,
            "bypass_csp": True,
        }

        # Add custom headers if configured
        headers_to_set = dict(self.options.headers or {})
        if self.options.basic_auth:
            auth_val = encode_basic_auth(self.options.basic_auth)
            if auth_val:
                headers_to_set["Authorization"] = auth_val

        if headers_to_set:
            context_kwargs["extra_http_headers"] = headers_to_set

        context = await self._browser.new_context(**context_kwargs)

        # Inject authorized cookies if configured
        if self.options.cookies:
            try:
                await context.add_cookies(self.options.cookies)
            except Exception as e:
                logger.warning(f"Could not inject some cookies: {e}")

        # Set default timeout
        context.set_default_navigation_timeout(self.options.timeout * 1000)
        context.set_default_timeout(self.options.timeout * 1000)

        # Intercept and block unnecessary media if block_media is enabled
        if self.options.block_media:
            async def route_interceptor(route: Route) -> None:
                req = route.request
                if is_resource_blocked(req.url, req.resource_type):
                    await route.abort()
                else:
                    await route.continue_()

            await context.route("**/*", route_interceptor)

        return context

    async def close(self) -> None:
        """Gracefully terminate browser and playwright driver."""
        if self._browser:
            try:
                await self._browser.close()
            except Exception as e:
                logger.debug(f"Error closing browser: {e}")
            finally:
                self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception as e:
                logger.debug(f"Error stopping Playwright: {e}")
            finally:
                self._playwright = None
        logger.debug("Browser resources cleaned up.")
