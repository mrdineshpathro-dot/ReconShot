"""
Unit tests for DNS reconnaissance and takeover detection.
"""

from unittest.mock import patch
from reconshot.dns_recon import resolve_target_dns


def test_resolve_target_dns_with_takeover():
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("192.168.1.50", 80))]):
        with patch("socket.gethostbyname_ex", return_value=("sub.example.com", ["my-app.s3.amazonaws.com"], ["192.168.1.50"])):
            dns_info = resolve_target_dns("https://sub.example.com")

            assert "192.168.1.50" in dns_info.ip_addresses
            assert "my-app.s3.amazonaws.com" in dns_info.cname_records
            assert dns_info.takeover_indicator is not None
            assert "AWS S3 Bucket" in dns_info.takeover_indicator
