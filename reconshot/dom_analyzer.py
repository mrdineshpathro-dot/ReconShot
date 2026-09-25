"""
DOM Analysis, Form Extraction, API Endpoint Discovery, and Secret Leakage Scanner for ReconShot.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from reconshot.models import DOMFindings

# Regex patterns for high-risk secrets & tokens
SECRET_PATTERNS = [
    ("AWS Access Key", r"\b(AKIA[0-9A-Z]{16})\b"),
    ("Google API Key", r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    ("GitHub Token", r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    ("Slack Token", r"\b(xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{24,})\b"),
    ("JWT Token", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
    ("Generic Private Key", r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"),
]

ENDPOINT_PATTERNS = [
    r"['\"](/api/v[0-9]+/[a-zA-Z0-9_\-/]+)['\"]",
    r"['\"](/v[0-9]+/[a-zA-Z0-9_\-/]+)['\"]",
    r"['\"](/graphql[a-zA-Z0-9_\-/]*)['\"]",
    r"['\"](/rest/[a-zA-Z0-9_\-/]+)['\"]",
    r"['\"](/oauth/[a-zA-Z0-9_\-/]+)['\"]",
    r"['\"](/admin/[a-zA-Z0-9_\-/]+)['\"]",
    r"['\"](/[a-zA-Z0-9_\-/]+\.json)['\"]",
]


def analyze_dom_content(html: str, base_url: str = "") -> DOMFindings:
    """
    Parse HTML content to detect forms, endpoints, developer comments,
    external domains, and potential leaked secrets.
    """
    if not html:
        return DOMFindings()

    # 1. Form & Input Analysis
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE)
    forms_count = len(forms)

    has_password = bool(re.search(r"<input\b[^>]*type=[\"']password[\"']", html, re.IGNORECASE))
    has_file_upload = bool(re.search(r"<input\b[^>]*type=[\"']file[\"']", html, re.IGNORECASE))
    
    # Login form indicator
    has_login = has_password or bool(
        re.search(r"(?:action|id|class|name)=[\"'][^\"']*(?:login|signin|auth|session)[^\"']*[\"']", html, re.IGNORECASE)
    )

    input_types: Set[str] = set()
    for inp_match in re.finditer(r"<input\b[^>]*type=[\"']([a-zA-Z0-9_-]+)[\"']", html, re.IGNORECASE):
        input_types.add(inp_match.group(1).lower())

    # 2. API Endpoint Extraction
    endpoints_set: Set[str] = set()
    for ep_pat in ENDPOINT_PATTERNS:
        for m in re.finditer(ep_pat, html, re.IGNORECASE):
            ep = m.group(1).strip()
            if len(ep) > 3 and not ep.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2")):
                endpoints_set.add(ep)

    # 3. Secret & Token Detection
    potential_secrets: List[Dict[str, str]] = []
    for secret_type, pat in SECRET_PATTERNS:
        for m in re.finditer(pat, html):
            raw_match = m.group(1)
            # Mask the secret for safety
            masked = f"{raw_match[:4]}...{raw_match[-4:]}" if len(raw_match) > 10 else "******"
            potential_secrets.append({
                "type": secret_type,
                "preview": masked,
            })

    # 4. HTML Developer Comments
    comments: List[str] = []
    for c_match in re.finditer(r"<!--(.*?)-->", html, re.DOTALL):
        c_text = c_match.group(1).strip()
        # Filter out trivial boilerplate comments
        if c_text and not c_text.startswith(("[if ", "<![endif]")):
            if len(c_text) < 300:
                comments.append(c_text)

    # 5. External Links
    external_links: Set[str] = set()
    base_domain = urlparse(base_url).netloc.lower() if base_url else ""

    for link_match in re.finditer(r"<a\b[^>]*href=[\"']([^\"'#]+)[\"']", html, re.IGNORECASE):
        href = link_match.group(1).strip()
        if href.startswith(("http://", "https://")):
            parsed_href = urlparse(href)
            href_domain = parsed_href.netloc.lower()
            if href_domain and href_domain != base_domain:
                external_links.add(href_domain)

    return DOMFindings(
        forms_count=forms_count,
        has_login_form=has_login,
        has_password_field=has_password,
        has_file_upload=has_file_upload,
        input_types=sorted(list(input_types)),
        endpoints=sorted(list(endpoints_set)),
        potential_secrets=potential_secrets,
        comments=comments[:20],
        external_links=sorted(list(external_links))[:30],
    )
