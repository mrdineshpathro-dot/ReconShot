"""
Unit tests for URL normalization and deduplication.
"""

import pytest
from reconshot.input_handler import deduplicate_urls, normalize_url


def test_normalize_standard_https():
    assert normalize_url("https://example.com") == "https://example.com/"
    assert normalize_url("https://example.com/path") == "https://example.com/path"
    assert normalize_url("https://example.com/app?tab=1") == "https://example.com/app?tab=1"


def test_normalize_standard_http():
    assert normalize_url("http://example.com") == "http://example.com/"
    assert normalize_url("http://example.com:8080/admin") == "http://example.com:8080/admin"


def test_normalize_missing_scheme():
    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url("admin.example.com:8443/login") == "https://admin.example.com:8443/login"
    assert normalize_url("//example.org/test") == "https://example.org/test"


def test_normalize_casing_and_whitespace():
    assert normalize_url("  HTTPS://EXAMPLE.COM/PATH  ") == "https://example.com/PATH"
    assert normalize_url("'https://example.com'") == "https://example.com/"
    assert normalize_url('"https://example.com"') == "https://example.com/"


def test_normalize_invalid_urls():
    assert normalize_url("") is None
    assert normalize_url("   ") is None
    assert normalize_url("# comment line") is None
    assert normalize_url("ftp://example.com") is None
    assert normalize_url("file:///etc/passwd") is None
    assert normalize_url("https://example .com") is None  # space inside host


def test_deduplicate_urls():
    raw_list = [
        "https://example.com",
        "http://target.com",
        "https://example.com/",
        "example.com",
        "target.com",
        "https://unique.com",
    ]
    deduped = deduplicate_urls(raw_list)
    assert deduped == [
        "https://example.com/",
        "http://target.com/",
        "https://target.com/",
        "https://unique.com/",
    ]
