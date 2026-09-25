"""
Deterministic, filesystem-safe filename generator and sanitization for ReconShot.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse


def sanitize_string(text: str) -> str:
    """
    Sanitize arbitrary text for safe filesystem usage.
    Removes traversal patterns, replaces unsafe characters with underscores,
    and strips leading/trailing dashes and underscores.
    """
    if not text:
        return "unnamed"

    # Remove null bytes and path traversal patterns
    cleaned = text.replace("\x00", "").replace("..", "_")

    # Replace all non-alphanumeric characters with underscores
    cleaned = re.sub(r"[^\w]", "_", cleaned)

    # Collapse consecutive underscores
    cleaned = re.sub(r"_+", "_", cleaned)

    # Strip leading/trailing underscores
    cleaned = cleaned.strip("_")

    return cleaned or "unnamed"


def url_to_base_slug(url: str) -> str:
    """
    Generate a readable base slug from a URL.
    Examples:
      https://example.com -> https_example_com
      https://admin.example.com:8443/api/v1 -> https_admin_example_com_8443_api_v1
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() or "http"
    netloc = parsed.netloc.lower() or "target"
    path = parsed.path.strip("/")
    query = parsed.query

    parts = [scheme, netloc]
    if path:
        parts.append(path)
    if query:
        parts.append(query)

    combined = "_".join(parts)
    return sanitize_string(combined)


def url_to_filename(url: str, ext: str = ".png", max_stem_len: int = 160) -> str:
    """
    Generate a deterministic, collision-resistant, filesystem-safe filename for a URL.
    If the base slug is long, truncates the stem and appends an 8-character sha256 hash
    to prevent collisions and guarantee filesystem compatibility.
    """
    if not ext.startswith("."):
        ext = f".{ext}"

    slug = url_to_base_slug(url)

    # Compute a short deterministic hash of the full normalized URL
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]

    if len(slug) > max_stem_len:
        stem = slug[: max_stem_len - 9].rstrip("_")
        filename = f"{stem}_{url_hash}{ext}"
    else:
        filename = f"{slug}{ext}"

    # Final safety check against traversal / invalid names
    stem_clean = sanitize_string(filename[:-len(ext)])
    return f"{stem_clean}{ext}"


def url_to_metadata_filename(url: str) -> str:
    """Generate the matching .json metadata filename for a URL."""
    return url_to_filename(url, ext=".json")


def is_safe_filename(filename: str) -> bool:
    """
    Check if a filename is strictly safe (no directory traversal, no path separators).
    """
    if not filename or "\x00" in filename:
        return False
    if "/" in filename or "\\" in filename or ".." in filename:
        return False
    if filename.startswith(".") or filename.startswith("-"):
        return False
    return True
