"""
Unit tests for CLI argument parsing and option generation.
"""

from pathlib import Path
import pytest
from reconshot.cli import build_parser, parse_arguments_to_options


def test_cli_single_url():
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com", "--workers", "8", "--timeout", "40", "--full-page"])
    options = parse_arguments_to_options(args)

    assert options.urls == ["https://example.com/"]
    assert options.workers == 8
    assert options.timeout == 40
    assert options.full_page is True
    assert options.viewport.is_mobile is False


def test_cli_mobile_flag():
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com", "--mobile"])
    options = parse_arguments_to_options(args)

    assert options.viewport.is_mobile is True
    assert options.viewport.width == 390
    assert options.viewport.height == 844


def test_cli_custom_dimensions():
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com", "--width", "1600", "--height", "900"])
    options = parse_arguments_to_options(args)

    assert options.viewport.width == 1600
    assert options.viewport.height == 900
    assert options.viewport.name == "custom"


def test_cli_status_and_delay():
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com", "--status", "200,403", "--delay", "2.5", "--retries", "3"])
    options = parse_arguments_to_options(args)

    assert options.status_filter == {200, 403}
    assert options.delay == 2.5
    assert options.retries == 3


def test_cli_no_report():
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com", "--no-report"])
    options = parse_arguments_to_options(args)

    assert options.generate_report is False
