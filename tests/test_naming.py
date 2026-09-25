"""
Unit tests for deterministic safe filename generation.
"""

import pytest
from reconshot.naming import is_safe_filename, sanitize_string, url_to_filename, url_to_metadata_filename


def test_sanitize_string():
    assert sanitize_string("hello world") == "hello_world"
    assert sanitize_string("../../../etc/passwd") == "etc_passwd"
    assert sanitize_string("test$$;rm -rf /") == "test_rm_rf"
    assert sanitize_string("\x00dangerous") == "dangerous"
    assert sanitize_string("") == "unnamed"


def test_url_to_filename_basic():
    name = url_to_filename("https://example.com")
    assert name == "https_example_com.png"
    assert is_safe_filename(name)


def test_url_to_filename_with_ports_and_paths():
    name = url_to_filename("https://admin.example.com:8443/login/auth?user=admin&redirect=1")
    assert name.startswith("https_admin_example_com_8443_login_auth_user_admin_redirect_1")
    assert name.endswith(".png")
    assert is_safe_filename(name)


def test_url_to_filename_long_url():
    long_query = "&param=" + ("a" * 250)
    url = f"https://example.com/api?debug=true{long_query}"
    name = url_to_filename(url)
    assert len(name) <= 180
    assert name.endswith(".png")
    assert is_safe_filename(name)


def test_url_to_metadata_filename():
    meta_name = url_to_metadata_filename("https://example.com")
    assert meta_name == "https_example_com.json"
    assert is_safe_filename(meta_name)


def test_is_safe_filename_validation():
    assert is_safe_filename("valid_name.png") is True
    assert is_safe_filename("../traversal.png") is False
    assert is_safe_filename("sub/folder.png") is False
    assert is_safe_filename("sub\\folder.png") is False
    assert is_safe_filename(".hidden") is False
    assert is_safe_filename("") is False
