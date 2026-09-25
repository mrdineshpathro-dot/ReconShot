"""
Integration and mock execution tests for ReconShotEngine and resume workflow.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from reconshot.crawler import ReconShotEngine
from reconshot.metadata import load_resume_state
from reconshot.models import ScanOptions, TargetResult, ViewportConfig


def test_crawler_mocked_run(tmp_path: Path):
    async def _run():
        output_dir = tmp_path / "recon_results"
        options = ScanOptions(
            urls=["https://example.com/", "https://app.example.com/"],
            output_dir=output_dir,
            workers=2,
            generate_report=True,
            quiet=True,
        )

        engine = ReconShotEngine(options)

        # Mock BrowserManager and capture_target_with_retry
        fake_result_1 = TargetResult(
            url="https://example.com/",
            final_url="https://example.com/",
            status_code=200,
            page_title="Example Domain",
            screenshot="https_example_com.png",
            success=True,
        )
        fake_result_2 = TargetResult(
            url="https://app.example.com/",
            final_url="https://app.example.com/login",
            status_code=403,
            page_title="Access Forbidden",
            screenshot="https_app_example_com.png",
            success=True,
        )

        with patch("reconshot.crawler.BrowserManager") as mock_bm_cls:
            mock_bm = MagicMock()
            mock_bm.initialize = AsyncMock()
            mock_bm.create_context = AsyncMock()
            mock_bm.close = AsyncMock()
            mock_bm_cls.return_value = mock_bm

            with patch("reconshot.crawler.capture_target_with_retry", side_effect=[fake_result_1, fake_result_2]):
                summary = await engine.run()

                assert summary.total_targets == 2
                assert summary.successful == 2
                assert summary.failed == 0
                assert len(summary.results) == 2

                # Check that files were created
                assert (output_dir / "reports" / "report.html").exists()
                assert (output_dir / "metadata" / "summary.json").exists()
                assert (output_dir / "logs" / "success.txt").exists()
                assert (output_dir / ".reconshot_state.json").exists()

    asyncio.run(_run())


def test_crawler_resume_workflow(tmp_path: Path):
    async def _run():
        output_dir = tmp_path / "resume_test_results"
        urls = ["https://example.com/", "https://second.example.com/", "https://third.example.com/"]

        options_1 = ScanOptions(
            urls=urls,
            output_dir=output_dir,
            workers=1,
            generate_report=False,
            quiet=True,
        )

        engine_1 = ReconShotEngine(options_1)

        fake_res = TargetResult(
            url="https://example.com/",
            status_code=200,
            page_title="Example",
            screenshot="https_example_com.png",
            success=True,
        )

        mock_bm = MagicMock()
        mock_bm.initialize = AsyncMock()
        mock_bm.create_context = AsyncMock()
        mock_bm.close = AsyncMock()
        engine_1.browser_manager = mock_bm

        with patch("reconshot.crawler.capture_target_with_retry", return_value=fake_res):
            # Manually trigger process for 1 target
            sem = asyncio.Semaphore(1)
            mock_progress = MagicMock()
            await engine_1._process_single_target("https://example.com/", sem, mock_progress, 1)

        # State file should now record https://example.com/ as completed
        scan_id, completed, results = load_resume_state(output_dir / ".reconshot_state.json")
        assert "https://example.com/" in completed
        assert len(results) == 1

        # Now run second scan with --resume enabled
        options_2 = ScanOptions(
            urls=urls,
            output_dir=output_dir,
            workers=1,
            resume=True,
            generate_report=False,
            quiet=True,
        )

        engine_2 = ReconShotEngine(options_2)

        fake_res_2 = TargetResult(
            url="https://second.example.com/",
            status_code=200,
            screenshot="https_second_example_com.png",
            success=True,
        )
        fake_res_3 = TargetResult(
            url="https://third.example.com/",
            status_code=200,
            screenshot="https_third_example_com.png",
            success=True,
        )

        with patch("reconshot.crawler.BrowserManager") as mock_bm_cls:
            mock_bm_2 = MagicMock()
            mock_bm_2.initialize = AsyncMock()
            mock_bm_2.create_context = AsyncMock()
            mock_bm_2.close = AsyncMock()
            mock_bm_cls.return_value = mock_bm_2

            with patch("reconshot.crawler.capture_target_with_retry", side_effect=[fake_res_2, fake_res_3]):
                summary_2 = await engine_2.run()

                # All 3 targets should now be in final summary
                assert len(summary_2.results) == 3
                assert summary_2.successful == 3

    asyncio.run(_run())
