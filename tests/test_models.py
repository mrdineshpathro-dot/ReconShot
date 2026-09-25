"""
Unit tests for data models and status matching.
"""

import pytest
from reconshot.models import ScanOptions, ScanSummary, TargetResult, ViewportConfig


def test_viewport_config_factory_methods():
    desktop = ViewportConfig.desktop()
    assert desktop.width == 1920
    assert desktop.height == 1080
    assert desktop.is_mobile is False

    mobile = ViewportConfig.mobile()
    assert mobile.width == 390
    assert mobile.height == 844
    assert mobile.is_mobile is True
    assert mobile.has_touch is True

    laptop = ViewportConfig.laptop()
    assert laptop.width == 1366
    assert laptop.height == 768

    custom = ViewportConfig.custom(1600, 900)
    assert custom.width == 1600
    assert custom.height == 900
    assert custom.name == "custom"


def test_target_result_serialization():
    result = TargetResult(
        url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        page_title="Example Domain",
        viewport={"width": 1920, "height": 1080},
        screenshot="https_example_com.png",
        response_time_ms=124.567,
        success=True,
    )
    d = result.to_dict()
    assert d["url"] == "https://example.com"
    assert d["status_code"] == 200
    assert d["response_time_ms"] == 124.57
    assert d["screenshot"] == "https_example_com.png"

    reconstructed = TargetResult.from_dict(d)
    assert reconstructed.url == result.url
    assert reconstructed.status_code == 200
    assert reconstructed.page_title == "Example Domain"
    assert reconstructed.success is True


def test_scan_options_status_filtering():
    options = ScanOptions(status_filter={200, 204, 301, 302})
    assert options.matches_status(200) is True
    assert options.matches_status(301) is True
    assert options.matches_status(404) is False
    assert options.matches_status(500) is False
    assert options.matches_status(None) is False

    # When no filter is set, all codes match
    no_filter_options = ScanOptions()
    assert no_filter_options.matches_status(200) is True
    assert no_filter_options.matches_status(404) is True
    assert no_filter_options.matches_status(None) is True


def test_scan_summary_serialization():
    summary = ScanSummary(
        scan_id="test-123",
        start_time="2026-09-25T10:00:00",
        end_time="2026-09-25T10:01:00",
        duration_seconds=60.0,
        total_targets=10,
        successful=8,
        failed=2,
        skipped=0,
        results=[],
    )
    data = summary.to_dict()
    assert data["scan_id"] == "test-123"
    assert data["tool"] == "ReconShot"
    assert data["author"] == "Mr Dinesh Pathro"
    assert data["total_targets"] == 10
    assert data["successful"] == 8
