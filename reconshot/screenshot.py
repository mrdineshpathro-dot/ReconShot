"""
Target navigation, comprehensive metadata extraction, security auditing,
DOM analysis, and visual capture for ReconShot.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from playwright.async_api import BrowserContext, Error as PlaywrightError, Page, Response

from reconshot.dns_recon import resolve_target_dns
from reconshot.dom_analyzer import analyze_dom_content
from reconshot.logger import logger
from reconshot.models import DOMFindings, ScanOptions, SecurityAudit, TargetResult
from reconshot.naming import url_to_filename
from reconshot.security_analyzer import analyze_security_headers
from reconshot.tech_detector import calculate_favicon_hash, detect_technologies
from reconshot.visual_engine import COOKIE_DISMISS_SCRIPT, compute_bytes_dhash


def classify_error(error: Exception) -> str:
    """Classify error messages into concise, readable categories."""
    msg = str(error).strip()
    msg_lower = msg.lower()

    if "net::err_name_not_resolved" in msg_lower or "getaddrinfo" in msg_lower:
        return "DNS resolution failed"
    if "net::err_connection_refused" in msg_lower:
        return "Connection refused"
    if "net::err_connection_timed_out" in msg_lower or "timeouterror" in msg_lower or "timeout" in msg_lower or "timed out" in msg_lower:
        return "Connection timed out"
    if "net::err_cert" in msg_lower or "ssl" in msg_lower:
        return "SSL/TLS handshake error"
    if "net::err_connection_reset" in msg_lower:
        return "Connection reset by peer"
    if "net::err_empty_response" in msg_lower:
        return "Empty response received"
    if "net::err_too_many_redirects" in msg_lower:
        return "Too many redirects"
    if "target closed" in msg_lower:
        return "Browser page closed unexpectedly"

    first_line = msg.split("\n")[0]
    return first_line[:120] if len(first_line) > 120 else first_line


async def capture_target_page(
    url: str,
    context: BrowserContext,
    options: ScanOptions,
    screenshot_path: Path,
) -> TargetResult:
    """
    Navigate to a single target URL, extract multi-layered intelligence, and capture screenshot.
    """
    page: Optional[Page] = None
    start_time = time.monotonic()
    timestamp_str = datetime.now(timezone.utc).astimezone().isoformat()
    vp_dict = {
        "width": options.viewport.width,
        "height": options.viewport.height,
    }

    try:
        page = await context.new_page()

        response: Optional[Response] = None
        redirect_count = 0

        def on_response(res: Response) -> None:
            nonlocal redirect_count
            if res.status in (301, 302, 303, 307, 308):
                redirect_count += 1

        page.on("response", on_response)

        timeout_ms = options.timeout * 1000
        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
        except PlaywrightError as pe:
            err_str = str(pe).lower()
            if "timeout" in err_str:
                logger.debug(f"domcontentloaded timeout for {url}, attempting capture anyway")
            else:
                raise

        duration_ms = (time.monotonic() - start_time) * 1000.0

        final_url = page.url or url
        status_code = response.status if response else None
        content_type = None
        all_headers: Dict[str, str] = {}
        headers_received: Dict[str, str] = {}

        if response:
            try:
                all_headers = await response.all_headers()
                content_type = all_headers.get("content-type")
                headers_received = {
                    k: v
                    for k, v in all_headers.items()
                    if k.lower() in ("server", "content-type", "content-length", "x-powered-by", "via", "strict-transport-security", "content-security-policy")
                }
            except Exception:
                pass

        # Extract title & HTML content
        page_title = ""
        html_content = ""
        try:
            page_title = (await page.title() or "").strip()
            html_content = await page.content()
        except Exception:
            pass

        # 1. Advanced Technology Stack Detection
        tech_stack = []
        if options.detect_tech:
            try:
                cookies = await context.cookies()
                tech_stack = detect_technologies(all_headers, html_content, cookies)
            except Exception as e:
                logger.debug(f"Tech detection error for {url}: {e}")

        # 2. Security Headers & Posture Audit
        sec_audit = None
        if options.analyze_security:
            try:
                sec_audit = analyze_security_headers(all_headers)
            except Exception as e:
                logger.debug(f"Security header analysis error for {url}: {e}")

        # 3. DOM & Secret Analysis
        dom_findings = None
        if options.analyze_dom:
            try:
                dom_findings = analyze_dom_content(html_content, base_url=final_url)
            except Exception as e:
                logger.debug(f"DOM analysis error for {url}: {e}")

        # 4. DNS Reconnaissance
        dns_info = None
        if options.resolve_dns:
            try:
                dns_info = resolve_target_dns(url)
            except Exception as e:
                logger.debug(f"DNS resolution error for {url}: {e}")

        # Check status code filter
        if options.status_filter and not options.matches_status(status_code):
            return TargetResult(
                url=url,
                final_url=final_url,
                status_code=status_code,
                page_title=page_title,
                timestamp=timestamp_str,
                viewport=vp_dict,
                full_page=options.full_page,
                screenshot=None,
                screenshot_path=None,
                response_time_ms=duration_ms,
                content_type=content_type,
                redirect_count=redirect_count,
                browser_profile=options.viewport.name,
                success=True,
                error="Filtered by status code",
                headers_received=headers_received,
                technologies=tech_stack,
                security=sec_audit,
                dom=dom_findings,
                dns=dns_info,
            )

        # Auto-dismiss cookie popups if enabled
        if options.auto_dismiss_popups:
            try:
                await page.evaluate(COOKIE_DISMISS_SCRIPT)
            except Exception:
                pass

        # Custom JS injection if configured
        if options.inject_js:
            try:
                await page.evaluate(options.inject_js)
            except Exception as e:
                logger.debug(f"Custom JS injection error on {url}: {e}")

        # Configurable render delay
        if options.delay > 0:
            await asyncio.sleep(options.delay)

        # Capture screenshot bytes & save to disk
        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        screenshot_bytes: bytes = b""

        if options.selector:
            # Capture specific CSS selector
            elem = await page.query_selector(options.selector)
            if elem:
                screenshot_bytes = await elem.screenshot(path=str(screenshot_path), type="png")
            else:
                screenshot_bytes = await page.screenshot(path=str(screenshot_path), full_page=options.full_page, type="png")
        else:
            screenshot_bytes = await page.screenshot(
                path=str(screenshot_path),
                full_page=options.full_page,
                type="png",
            )

        # Compute perceptual difference hash
        dhash_str = compute_bytes_dhash(screenshot_bytes)
        relative_screenshot = screenshot_path.name

        return TargetResult(
            url=url,
            final_url=final_url,
            status_code=status_code,
            page_title=page_title,
            timestamp=timestamp_str,
            viewport=vp_dict,
            full_page=options.full_page,
            screenshot=relative_screenshot,
            screenshot_path=str(screenshot_path),
            response_time_ms=duration_ms,
            content_type=content_type,
            redirect_count=redirect_count,
            browser_profile=options.viewport.name,
            success=True,
            error=None,
            headers_received=headers_received,
            technologies=tech_stack,
            security=sec_audit,
            dom=dom_findings,
            dns=dns_info,
            dhash=dhash_str,
        )

    except Exception as exc:
        duration_ms = (time.monotonic() - start_time) * 1000.0
        error_msg = classify_error(exc)
        logger.debug(f"Error capturing {url}: {exc}")
        return TargetResult(
            url=url,
            final_url=url,
            status_code=None,
            page_title="",
            timestamp=timestamp_str,
            viewport=vp_dict,
            full_page=options.full_page,
            screenshot=None,
            screenshot_path=None,
            response_time_ms=duration_ms,
            content_type=None,
            redirect_count=0,
            browser_profile=options.viewport.name,
            success=False,
            error=error_msg,
        )
    finally:
        if page:
            try:
                await page.close()
            except Exception:
                pass


async def capture_target_with_retry(
    url: str,
    context: BrowserContext,
    options: ScanOptions,
    screenshot_path: Path,
) -> TargetResult:
    """
    Execute screenshot capture with automatic retry logic for temporary failures.
    """
    retries_left = max(0, options.retries)
    attempts = 0

    while True:
        attempts += 1
        result = await capture_target_page(url, context, options, screenshot_path)
        if result.success or retries_left <= 0:
            result.retries_used = attempts - 1
            return result

        retries_left -= 1
        backoff = 1.0 * attempts
        logger.debug(f"Retrying {url} (attempt {attempts + 1}/{options.retries + 1}) after {backoff}s...")
        await asyncio.sleep(backoff)
