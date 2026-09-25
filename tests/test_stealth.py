"""
Unit tests for stealth, random user agent, basic auth, and media blocking.
"""

from reconshot.stealth import encode_basic_auth, get_random_user_agent, is_resource_blocked


def test_get_random_user_agent():
    ua1 = get_random_user_agent()
    assert "Mozilla" in ua1
    assert len(ua1) > 20


def test_encode_basic_auth():
    encoded = encode_basic_auth("admin:P@ssw0rd123!")
    assert encoded.startswith("Basic ")
    assert encode_basic_auth("invalid_no_colon") is None


def test_is_resource_blocked():
    assert is_resource_blocked("https://example.com/video.mp4", "media") is True
    assert is_resource_blocked("https://example.com/font.woff2", "font") is True
    assert is_resource_blocked("https://example.com/app.js", "script") is False
    assert is_resource_blocked("https://example.com/styles.css", "stylesheet") is False
