"""
Unit tests for CLI execution and entry point behaviors.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from reconshot.cli import async_main, build_parser, parse_arguments_to_options
from reconshot.models import ScanSummary


def test_cli_help():
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0


def test_cli_version():
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0


def test_async_main_no_targets():
    async def _test():
        ret = await async_main(["--quiet"])
        assert ret == 1

    asyncio.run(_test())


def test_async_main_with_url_mocked(tmp_path: Path):
    async def _test():
        out_dir = tmp_path / "cli_out"
        fake_summary = ScanSummary(
            scan_id="test",
            start_time="",
            end_time="",
            duration_seconds=1.0,
            total_targets=1,
            successful=1,
            failed=0,
            skipped=0,
            results=[],
        )

        with patch("reconshot.cli.ReconShotEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.run = AsyncMock(return_value=fake_summary)
            mock_engine_cls.return_value = mock_engine

            ret = await async_main(["-u", "https://example.com", "-o", str(out_dir), "--quiet"])
            assert ret == 0

    asyncio.run(_test())
