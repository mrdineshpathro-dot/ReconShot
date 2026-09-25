"""
Unit tests for input handling: files, cookies, headers, status filters.
"""

import json
from pathlib import Path
import pytest
from reconshot.input_handler import (
    load_cookies_file,
    load_headers_file,
    load_urls_from_file,
    parse_status_filter,
)


def test_load_urls_from_file(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("""
# Internal reconnaissance list
https://app.example.com
https://admin.example.com/login

http://legacy.example.com:8080
# repeated entry:
https://app.example.com
""")
    urls = load_urls_from_file(target_file)
    assert len(urls) == 3
    assert "https://app.example.com/" in urls
    assert "https://admin.example.com/login" in urls
    assert "http://legacy.example.com:8080/" in urls


def test_load_cookies_file(tmp_path: Path):
    cookie_file = tmp_path / "cookies.json"
    cookie_file.write_text(json.dumps([
        {"name": "sess_id", "value": "xyz123", "domain": "example.com", "path": "/", "secure": True},
        {"name": "token", "value": "secret999"}
    ]))

    cookies = load_cookies_file(cookie_file)
    assert len(cookies) == 2
    assert cookies[0]["name"] == "sess_id"
    assert cookies[0]["value"] == "xyz123"
    assert cookies[0]["domain"] == "example.com"
    assert cookies[1]["name"] == "token"


def test_load_cookies_file_dict_wrapped(tmp_path: Path):
    cookie_file = tmp_path / "cookies_dict.json"
    cookie_file.write_text(json.dumps({
        "cookies": [
            {"name": "auth", "value": "demo"}
        ]
    }))
    cookies = load_cookies_file(cookie_file)
    assert len(cookies) == 1
    assert cookies[0]["name"] == "auth"


def test_load_headers_file(tmp_path: Path):
    header_file = tmp_path / "headers.json"
    header_file.write_text(json.dumps({
        "X-Security-Test": "ReconShot",
        "X-Custom-Auth": "Token123"
    }))

    headers = load_headers_file(header_file)
    assert headers["X-Security-Test"] == "ReconShot"
    assert headers["X-Custom-Auth"] == "Token123"


def test_parse_status_filter():
    assert parse_status_filter("200") == {200}
    assert parse_status_filter("200, 301, 302, 403") == {200, 301, 302, 403}
    assert 200 in parse_status_filter("2xx")
    assert 299 in parse_status_filter("2xx")
    assert 300 not in parse_status_filter("2xx")
    assert {200, 201, 202, 203} <= parse_status_filter("200-203")
    assert parse_status_filter("") is None
    assert parse_status_filter(None) is None
