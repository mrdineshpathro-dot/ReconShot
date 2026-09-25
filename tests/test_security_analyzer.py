"""
Unit tests for security header analyzer, grading, and info disclosure detection.
"""

from reconshot.security_analyzer import analyze_security_headers


def test_security_headers_perfect_grade():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    audit = analyze_security_headers(headers)

    assert audit.grade in ("A+", "A")
    assert audit.score >= 90
    assert len(audit.missing_headers) == 0


def test_security_headers_poor_grade_and_leaks():
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    audit = analyze_security_headers(headers)

    assert audit.grade in ("D", "F")
    assert len(audit.info_leaks) >= 2
    assert len(audit.cors_issues) >= 1
    assert "strict-transport-security" in audit.missing_headers


def test_security_headers_empty():
    audit = analyze_security_headers({})
    assert audit.grade == "F"
    assert audit.score == 0
