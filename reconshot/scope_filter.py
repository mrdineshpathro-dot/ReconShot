"""
Scope Filtering, Target Prioritization, and Port Expansion for ReconShot.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Set
from urllib.parse import urlparse

# High-priority subdomain prefixes scanned first
PRIORITY_KEYWORDS = [
    "admin", "portal", "vpn", "dev", "staging", "api", "auth",
    "login", "corp", "internal", "dashboard", "jenkins", "gitlab",
    "grafana", "kibana", "monitor", "vault", "sso"
]

# Unsafe paths to automatically avoid during authenticated scans
DANGEROUS_PATH_PATTERNS = [
    r"/logout",
    r"/signout",
    r"/log-out",
    r"/sign-out",
    r"/auth/logout",
]


def is_in_scope(url: str, blacklist_patterns: Iterable[str]) -> bool:
    """Check if a URL matches any exclusion blacklist rule."""
    if not blacklist_patterns:
        return True
    for pat in blacklist_patterns:
        if pat and re.search(pat, url, re.IGNORECASE):
            return False
    return True


def is_dangerous_auth_path(url: str) -> bool:
    """Check if URL is a logout endpoint that could invalidate authenticated sessions."""
    for pat in DANGEROUS_PATH_PATTERNS:
        if re.search(pat, url, re.IGNORECASE):
            return True
    return False


def sort_targets_by_priority(urls: List[str]) -> List[str]:
    """Sort target URLs putting high-value assets (admin, vpn, api) first."""
    def priority_score(u: str) -> int:
        u_lower = u.lower()
        score = 100
        for idx, kw in enumerate(PRIORITY_KEYWORDS):
            if kw in u_lower:
                score = idx
                break
        return score

    return sorted(urls, key=priority_score)


def expand_common_web_ports(hosts_or_urls: List[str], ports: List[int]) -> List[str]:
    """Expand list of hostnames to multiple HTTP/HTTPS port combinations."""
    expanded: List[str] = []
    for target in hosts_or_urls:
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
        else:
            host = target.split("/")[0].split(":")[0]

        for p in ports:
            scheme = "https" if p in (443, 8443, 9443) else "http"
            if (scheme == "https" and p == 443) or (scheme == "http" and p == 80):
                expanded.append(f"{scheme}://{host}/")
            else:
                expanded.append(f"{scheme}://{host}:{p}/")

    return expanded
