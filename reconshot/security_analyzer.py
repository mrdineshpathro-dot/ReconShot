"""
Security Header Analyzer, Grading Engine, and CORS/Info Leak Detector for ReconShot.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from reconshot.models import SecurityAudit

SECURITY_HEADERS_WEIGHTS: Dict[str, Tuple[int, str]] = {
    "strict-transport-security": (25, "HSTS (Strict-Transport-Security)"),
    "content-security-policy": (30, "Content-Security-Policy (CSP)"),
    "x-frame-options": (15, "X-Frame-Options (Clickjacking Protection)"),
    "x-content-type-options": (15, "X-Content-Type-Options (MIME Sniffing)"),
    "referrer-policy": (10, "Referrer-Policy"),
    "permissions-policy": (5, "Permissions-Policy"),
}

INFO_LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-version",
]


def analyze_security_headers(headers: Optional[Dict[str, str]]) -> SecurityAudit:
    """
    Evaluate HTTP response headers for missing security controls,
    information disclosure, and calculate a security letter grade (A+ to F).
    """
    if not headers:
        return SecurityAudit(
            grade="F",
            score=0,
            missing_headers=list(SECURITY_HEADERS_WEIGHTS.keys()),
            present_headers=[],
            info_leaks=[],
            cors_issues=[],
        )

    headers_lower = {k.lower(): str(v) for k, v in headers.items()}

    score = 0
    missing: List[str] = []
    present: List[str] = []
    info_leaks: List[str] = []
    cors_issues: List[str] = []

    # 1. Evaluate Security Headers
    for header_name, (weight, label) in SECURITY_HEADERS_WEIGHTS.items():
        if header_name in headers_lower and headers_lower[header_name].strip():
            score += weight
            present.append(header_name)
        else:
            missing.append(header_name)

    # 2. Information Disclosure Checks
    for leak_hdr in INFO_LEAK_HEADERS:
        if leak_hdr in headers_lower:
            val = headers_lower[leak_hdr]
            # If server header contains version numbers or detailed components
            if leak_hdr == "server":
                if re.search(r"[\d.]+", val):
                    info_leaks.append(f"Server header exposes version: '{val}'")
            else:
                info_leaks.append(f"{leak_hdr.title()} header leaks technology: '{val}'")

    # 3. CORS Misconfiguration Checks
    acao = headers_lower.get("access-control-allow-origin")
    acac = headers_lower.get("access-control-allow-credentials")

    if acao == "*":
        if acac and acac.lower() == "true":
            cors_issues.append("Wildcard CORS origin with Allow-Credentials enabled")
        else:
            cors_issues.append("Wildcard CORS (Access-Control-Allow-Origin: *)")

    # Penalties for leaks / CORS
    score -= min(15, len(info_leaks) * 5)
    score -= min(10, len(cors_issues) * 5)
    score = max(0, min(100, score))

    # Calculate Letter Grade
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return SecurityAudit(
        grade=grade,
        score=score,
        missing_headers=missing,
        present_headers=present,
        info_leaks=info_leaks,
        cors_issues=cors_issues,
    )
