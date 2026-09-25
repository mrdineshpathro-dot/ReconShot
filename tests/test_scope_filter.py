"""
Unit tests for scope filtering, target prioritization, and port expansion.
"""

from reconshot.scope_filter import (
    expand_common_web_ports,
    is_dangerous_auth_path,
    is_in_scope,
    sort_targets_by_priority,
)


def test_is_in_scope():
    blacklist = [r"\.gov$", r"out-of-scope\.com"]
    assert is_in_scope("https://target.com", blacklist) is True
    assert is_in_scope("https://out-of-scope.com", blacklist) is False


def test_is_dangerous_auth_path():
    assert is_dangerous_auth_path("https://example.com/api/v1/logout") is True
    assert is_dangerous_auth_path("https://example.com/auth/sign-out") is True
    assert is_dangerous_auth_path("https://example.com/dashboard/home") is False


def test_sort_targets_by_priority():
    urls = [
        "https://blog.example.com",
        "https://admin.example.com",
        "https://vpn.example.com",
        "https://about.example.com",
    ]
    sorted_urls = sort_targets_by_priority(urls)
    assert sorted_urls[0] == "https://admin.example.com"
    assert sorted_urls[1] == "https://vpn.example.com"


def test_expand_common_web_ports():
    hosts = ["example.com"]
    expanded = expand_common_web_ports(hosts, [80, 443, 8080, 8443])
    assert "http://example.com/" in expanded
    assert "https://example.com/" in expanded
    assert "http://example.com:8080/" in expanded
    assert "https://example.com:8443/" in expanded
