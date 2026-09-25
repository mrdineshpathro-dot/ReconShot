"""
Unit tests for HTML report generator.
"""

from pathlib import Path
import pytest
from reconshot.models import ScanSummary, TargetResult
from reconshot.reporter import escape, generate_html_report


def test_escape():
    assert escape("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert escape("Clean Text") == "Clean Text"
    assert escape(None) == ""


def test_generate_html_report(tmp_path: Path):
    report_file = tmp_path / "reports" / "report.html"

    results = [
        TargetResult(
            url="https://example.com",
            final_url="https://example.com/",
            status_code=200,
            page_title="Example Domain",
            screenshot="https_example_com.png",
            response_time_ms=150.0,
            success=True,
        ),
        TargetResult(
            url="https://admin.example.com",
            final_url="https://admin.example.com/login",
            status_code=403,
            page_title="Forbidden Portal",
            screenshot="https_admin_example_com.png",
            response_time_ms=210.0,
            success=True,
        ),
        TargetResult(
            url="https://dead.example.com",
            final_url=None,
            status_code=None,
            page_title="",
            screenshot=None,
            success=False,
            error="DNS resolution failed",
        ),
    ]

    summary = ScanSummary(
        scan_id="report-test",
        start_time="2026-09-25T12:00:00",
        end_time="2026-09-25T12:01:00",
        duration_seconds=60.0,
        total_targets=3,
        successful=2,
        failed=1,
        skipped=0,
        results=results,
    )

    out_path = generate_html_report(summary, report_file)
    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")

    # Assert brand and elements
    assert "ReconShot" in content
    assert "Mr Dinesh Pathro" in content
    assert "https://example.com" in content
    assert "Example Domain" in content
    assert "Forbidden Portal" in content
    assert "DNS resolution failed" in content
    assert "2xx Success" in content
    assert "4xx Client Errors" in content
