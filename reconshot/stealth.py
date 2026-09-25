"""
Stealth, User-Agent Rotation, Media Interception, and Performance Optimization for ReconShot.
"""

from __future__ import annotations

import base64
import random
from typing import List, Optional

USER_AGENT_POOL: List[str] = [
    # Chrome on Windows / Mac / Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox on Windows / Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}
BLOCKED_EXTENSIONS = (
    ".mp4", ".mkv", ".webm", ".avi", ".mov",
    ".mp3", ".wav", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf"
)


def get_random_user_agent() -> str:
    """Return a randomly selected modern browser User-Agent."""
    return random.choice(USER_AGENT_POOL)


def encode_basic_auth(auth_str: str) -> Optional[str]:
    """Encode user:pass string into Authorization header value."""
    if not auth_str or ":" not in auth_str:
        return None
    encoded = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


def is_resource_blocked(url: str, resource_type: str) -> bool:
    """Check if an incoming network request should be aborted to accelerate visual recon."""
    if resource_type in BLOCKED_RESOURCE_TYPES:
        return True
    lower_url = url.lower()
    return any(lower_url.endswith(ext) for ext in BLOCKED_EXTENSIONS)
