"""
Unit tests for multi-format exporters: CSV, Markdown, SQLite, and webhooks.
"""

from pathlib import Path
from unittest.mock import patch
from reconshot.exporter import (
    export_to_csv,
    export_to_markdown,
    export_to_sqlite,
    send_webhook_notification,
)
from reconshot.models import ScanSummary, TargetResult, TechItem


def test_export_to_csv_and_markdown(tmp_path: Path):
    csv_file = tmp_path / "results.csv"
    md_file = tmp_path / "summary.md"

    results = [
        TargetResult(
            url="https://example.com",
            status_code=200,
            page_title="Example",
            technologies=[TechItem(name="Nginx", category="Web Server")],
            success=True,
        )
    ]
    summary = ScanSummary(
        scan_id="test-exp",
        start_time="2026-09-25T12:00:00",
        end_time="2026-09-25T12:01:00",
        duration_seconds=60.0,
        total_targets=1,
        successful=1,
        failed=0,
        skipped=0,
        results=results,
    )

    out_csv = export_to_csv(results, csv_file)
    assert out_csv.exists()
    assert "https://example.com" in out_csv.read_text()
    assert "Nginx" in out_csv.read_text()

    out_md = export_to_markdown(summary, md_file)
    assert out_md.exists()
    assert "ReconShot Reconnaissance Summary" in out_md.read_text()


def test_export_to_sqlite(tmp_path: Path):
    db_file = tmp_path / "reconshot.db"
    results = [
        TargetResult(
            url="https://admin.example.com",
            status_code=403,
            page_title="Forbidden",
            success=True,
        )
    ]
    out_db = export_to_sqlite(results, db_file)
    assert out_db.exists()


def test_send_webhook_notification():
    summary = ScanSummary(
        scan_id="w-1",
        start_time="",
        end_time="",
        duration_seconds=1.0,
        total_targets=1,
        successful=1,
        failed=0,
        skipped=0,
        results=[],
    )
    with patch("urllib.request.urlopen") as mock_open:
        mock_open.return_value.__enter__.return_value.status = 200
        ok = send_webhook_notification("https://discord.com/api/webhooks/test", summary)
        assert ok is True
