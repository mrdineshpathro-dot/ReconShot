"""
Input parsing, URL normalization, deduplication, and credential/header loading for ReconShot.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from reconshot.logger import logger


def normalize_url(raw_url: str) -> Optional[str]:
    """
    Safely clean, parse, and normalize a URL string.
    Automatically prepends 'https://' if no protocol is present.
    Returns normalized URL string, or None if the input is invalid.
    """
    if not raw_url:
        return None

    # Strip whitespace, zero-width chars, and surrounding quotes
    cleaned = raw_url.strip().strip("'\"").strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    # Check for basic invalid characters like whitespace in the middle
    if re.search(r"\s", cleaned):
        return None

    # If scheme is missing, default to https://
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
        # Handle cases like //example.com
        if cleaned.startswith("//"):
            cleaned = f"https:{cleaned}"
        else:
            cleaned = f"https://{cleaned}"

    try:
        parsed = urlparse(cleaned)
        # Scheme must be http or https
        if parsed.scheme.lower() not in ("http", "https"):
            return None

        # Netloc (host + optional port) must be non-empty
        if not parsed.netloc:
            return None

        # Lowercase scheme and netloc for consistency
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Reconstruct normalized URL
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""

        normalized = f"{scheme}://{netloc}{path}{query}{fragment}"
        return normalized
    except Exception as e:
        logger.debug(f"Failed to normalize URL '{raw_url}': {e}")
        return None


def deduplicate_urls(urls: Iterable[str]) -> List[str]:
    """Deduplicate normalized URLs while strictly preserving original order."""
    seen: Set[str] = set()
    result: List[str] = []
    for raw in urls:
        normalized = normalize_url(raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def load_urls_from_file(file_path: Path) -> List[str]:
    """Load target URLs from a text file (one URL per line)."""
    if not file_path.exists():
        raise FileNotFoundError(f"Target list file does not exist: {file_path}")

    urls: List[str] = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    return deduplicate_urls(urls)


def load_urls_from_stdin() -> List[str]:
    """Read target URLs from standard input if piped."""
    if sys.stdin.isatty():
        return []

    urls: List[str] = []
    try:
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    except Exception as e:
        logger.debug(f"Error reading from stdin: {e}")

    return deduplicate_urls(urls)


def load_cookies_file(cookies_path: Path) -> List[Dict[str, Any]]:
    """
    Load authorized cookies from a JSON file.
    Supports either a list of cookies or an object with a 'cookies' key.
    """
    if not cookies_path.exists():
        raise FileNotFoundError(f"Cookies file not found: {cookies_path}")

    with open(cookies_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "cookies" in data:
        data = data["cookies"]

    if not isinstance(data, list):
        raise ValueError(
            f"Invalid cookies format in {cookies_path}. Expected a JSON array of cookie objects."
        )

    valid_cookies: List[Dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict) and "name" in item and "value" in item:
            cookie_dict: Dict[str, Any] = {
                "name": str(item["name"]),
                "value": str(item["value"]),
            }
            if "domain" in item and item["domain"]:
                cookie_dict["domain"] = str(item["domain"])
            if "path" in item and item["path"]:
                cookie_dict["path"] = str(item["path"])
            if "url" in item and item["url"]:
                cookie_dict["url"] = str(item["url"])
            if "secure" in item:
                cookie_dict["secure"] = bool(item["secure"])
            if "httpOnly" in item:
                cookie_dict["httpOnly"] = bool(item["httpOnly"])
            if "sameSite" in item:
                cookie_dict["sameSite"] = str(item["sameSite"])
            valid_cookies.append(cookie_dict)

    return valid_cookies


def load_headers_file(headers_path: Path) -> Dict[str, str]:
    """
    Load custom HTTP headers from a JSON file.
    Expects a JSON object with header name-value pairs.
    """
    if not headers_path.exists():
        raise FileNotFoundError(f"Headers file not found: {headers_path}")

    with open(headers_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid headers format in {headers_path}. Expected a JSON object with key-value pairs."
        )

    headers: Dict[str, str] = {}
    for k, v in data.items():
        if k:
            headers[str(k)] = str(v)

    return headers


def parse_status_filter(status_str: Optional[str]) -> Optional[Set[int]]:
    """
    Parse a status code filter expression into a set of integer status codes.
    Supports:
      - "200"
      - "200,301,302,403,500"
      - "2xx" or "2XX"
      - "2xx,3xx,4xx"
      - "200-204"
    """
    if not status_str or not status_str.strip():
        return None

    result: Set[int] = set()
    tokens = [t.strip().lower() for t in status_str.split(",") if t.strip()]

    for token in tokens:
        # Wildcard classes: 2xx, 3xx, 4xx, 5xx
        if token.endswith("xx") and len(token) == 3 and token[0].isdigit():
            hundred = int(token[0]) * 100
            for code in range(hundred, hundred + 100):
                result.add(code)
        # Range: 200-205
        elif "-" in token:
            parts = token.split("-")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start, end = int(parts[0]), int(parts[1])
                for code in range(min(start, end), max(start, end) + 1):
                    result.add(code)
        # Single code: 200
        elif token.isdigit():
            result.add(int(token))
        else:
            logger.warning(f"Unrecognized status code filter token: '{token}'")

    return result if result else None
