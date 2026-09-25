"""
Command-Line Interface and argument parser for ReconShot.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from rich.console import Console
from rich.panel import Panel

from reconshot import __author__, __support__, __tagline__, __title__, __version__
from reconshot.config import DEFAULT_CONFIG, load_config_file
from reconshot.crawler import ReconShotEngine
from reconshot.input_handler import (
    load_cookies_file,
    load_headers_file,
    load_urls_from_file,
    load_urls_from_stdin,
    normalize_url,
    parse_status_filter,
)
from reconshot.models import ScanOptions, ViewportConfig
from reconshot.utils import console, err_console, print_banner, startup_animation


class ReconShotHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter with clean section formatting."""
    pass


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line argument parser for ReconShot."""
    description = f"""
[bold cyan]{__title__}[/bold cyan] [bright_white]v{__version__}[/bright_white] — [italic]{__tagline__}[/italic]
Author : [bright_cyan]{__author__}[/bright_cyan]
Support: [bright_yellow]{__support__}[/bright_yellow]
"""
    parser = argparse.ArgumentParser(
        prog="reconshot",
        description="ReconShot — Automated Web Application Screenshot Reconnaissance",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )

    # Target Input Group
    target_group = parser.add_argument_group("🎯 Target Input")
    target_group.add_argument(
        "-u", "--url",
        type=str,
        metavar="URL",
        help="Capture a single target URL (e.g. -u https://example.com)",
    )
    target_group.add_argument(
        "-l", "--list",
        type=str,
        metavar="FILE",
        help="Read target URLs from a text file (one URL per line)",
    )

    # Performance & Concurrency Group
    perf_group = parser.add_argument_group("⚡ Performance & Timing")
    perf_group.add_argument(
        "-w", "--workers",
        type=int,
        default=None,
        metavar="INT",
        help="Number of concurrent screenshot workers (default: 5)",
    )
    perf_group.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="INT",
        help="Page navigation & load timeout in seconds (default: 30)",
    )
    perf_group.add_argument(
        "--delay",
        type=float,
        default=None,
        metavar="FLOAT",
        help="Delay in seconds before capturing screenshot for JS rendering (e.g. 1.5)",
    )
    perf_group.add_argument(
        "--retries",
        type=int,
        default=None,
        metavar="INT",
        help="Number of retry attempts for temporary failures (default: 0)",
    )

    # Viewport & Browser Mode Group
    browser_group = parser.add_argument_group("🖥️ Viewport & Browser Options")
    browser_group.add_argument(
        "--width",
        type=int,
        default=None,
        metavar="INT",
        help="Custom viewport width in pixels (e.g. 1920)",
    )
    browser_group.add_argument(
        "--height",
        type=int,
        default=None,
        metavar="INT",
        help="Custom viewport height in pixels (e.g. 1080)",
    )
    browser_group.add_argument(
        "--full-page",
        action="store_true",
        default=None,
        help="Capture full scrollable web page screenshot",
    )
    browser_group.add_argument(
        "--mobile",
        action="store_true",
        default=False,
        help="Emulate mobile viewport (390×844 with touch enabled)",
    )
    browser_group.add_argument(
        "--desktop",
        action="store_true",
        default=False,
        help="Use desktop viewport (1920×1080, default)",
    )
    browser_group.add_argument(
        "--laptop",
        action="store_true",
        default=False,
        help="Use laptop viewport (1366×768)",
    )
    browser_group.add_argument(
        "--user-agent",
        type=str,
        default=None,
        metavar="TEXT",
        help="Custom User-Agent header string",
    )

    # Network & Authentication Group
    net_group = parser.add_argument_group("🔒 Network & Authorized Authentication")
    net_group.add_argument(
        "--proxy",
        type=str,
        default=None,
        metavar="URL",
        help="HTTP/HTTPS/SOCKS proxy URL (e.g. http://127.0.0.1:8080)",
    )
    net_group.add_argument(
        "--cookies",
        type=str,
        default=None,
        metavar="FILE",
        help="Load authorized session cookies from a JSON file",
    )
    net_group.add_argument(
        "--headers",
        type=str,
        default=None,
        metavar="FILE",
        help="Load custom HTTP headers from a JSON file",
    )

    # Filter & Resume Group
    filter_group = parser.add_argument_group("🔍 Filtering & Scan Control")
    filter_group.add_argument(
        "--status",
        type=str,
        default=None,
        metavar="CODES",
        help="Screenshot only selected HTTP status codes (e.g. 200 or 200,301,302,403,500 or 2xx)",
    )
    filter_group.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume an interrupted scan from previous state",
    )

    # Output & Reporting Group
    out_group = parser.add_argument_group("📁 Output & Reporting")
    out_group.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        metavar="DIR",
        help="Base output directory (default: ./results)",
    )
    out_group.add_argument(
        "--report",
        dest="report",
        action="store_true",
        default=None,
        help="Generate standalone dark-themed HTML report (default: True)",
    )
    out_group.add_argument(
        "--no-report",
        dest="report",
        action="store_false",
        help="Disable HTML report generation",
    )

    # General Options Group
    gen_group = parser.add_argument_group("⚙️ Configuration & General")
    gen_group.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        metavar="FILE",
        help="Load configuration options from a YAML file",
    )
    gen_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable detailed debugging output in terminal",
    )
    gen_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Quiet mode: suppress banner and non-error output",
    )
    gen_group.add_argument(
        "-V", "--version",
        action="version",
        version=f"{__title__} v{__version__} — {__tagline__}",
        help="Display ReconShot version and exit",
    )
    gen_group.add_argument(
        "-h", "--help",
        action="help",
        help="Show this help message and exit",
    )

    return parser


def parse_arguments_to_options(args: argparse.Namespace) -> ScanOptions:
    """
    Merge configuration file with CLI flags to produce final ScanOptions.
    CLI flags take strict precedence over configuration file values.
    """
    # 1. Start with defaults
    config_dict = dict(DEFAULT_CONFIG)

    # 2. If config file is provided or config.yaml exists locally, merge it
    config_path = None
    if args.config:
        config_path = Path(args.config)
    elif Path("config.yaml").exists():
        config_path = Path("config.yaml")

    if config_path and config_path.exists():
        loaded = load_config_file(config_path)
        if loaded:
            # Shallow/deep merge
            for k, v in loaded.items():
                if isinstance(v, dict) and k in config_dict and isinstance(config_dict[k], dict):
                    config_dict[k].update(v)
                else:
                    config_dict[k] = v

    # 3. Determine Viewport
    b_conf = config_dict.get("browser", {})
    if args.mobile or b_conf.get("mobile"):
        viewport = ViewportConfig.mobile()
    elif args.laptop:
        viewport = ViewportConfig.laptop()
    elif args.width or args.height or b_conf.get("width") or b_conf.get("height"):
        w = args.width if args.width is not None else b_conf.get("width", 1920)
        h = args.height if args.height is not None else b_conf.get("height", 1080)
        viewport = ViewportConfig.custom(w, h)
    else:
        viewport = ViewportConfig.desktop()

    full_page = args.full_page if args.full_page is not None else b_conf.get("full_page", False)
    user_agent = args.user_agent if args.user_agent is not None else b_conf.get("user_agent")

    # 4. Resolve Target URLs
    urls: List[str] = []
    if args.url:
        normalized = normalize_url(args.url)
        if normalized:
            urls.append(normalized)
        else:
            err_console.print(f"[bold red][!] Invalid target URL provided:[/bold red] {args.url}")
            sys.exit(1)
    elif args.list:
        list_path = Path(args.list)
        if not list_path.exists():
            err_console.print(f"[bold red][!] Target list file not found:[/bold red] {args.list}")
            sys.exit(1)
        urls = load_urls_from_file(list_path)
    else:
        # Check stdin
        stdin_urls = load_urls_from_stdin()
        if stdin_urls:
            urls = stdin_urls

    # 5. Resolve Output Directory
    out_dir_str = args.output or config_dict.get("output", {}).get("directory", "./results")
    output_dir = Path(out_dir_str).expanduser()

    # 6. Resolve Workers, Timeout, Delay, Retries
    workers = args.workers if args.workers is not None else int(config_dict.get("workers", 5))
    timeout = args.timeout if args.timeout is not None else int(config_dict.get("timeout", 30))
    delay = args.delay if args.delay is not None else float(config_dict.get("delay", 0.0))
    retries = args.retries if args.retries is not None else int(config_dict.get("retries", 0))

    # 7. Resolve Proxy
    proxy = args.proxy if args.proxy is not None else config_dict.get("network", {}).get("proxy")

    # 8. Resolve Cookies
    cookies = None
    cookies_path_str = args.cookies or config_dict.get("auth", {}).get("cookies_file")
    if cookies_path_str:
        cookies_p = Path(cookies_path_str)
        try:
            cookies = load_cookies_file(cookies_p)
        except Exception as e:
            err_console.print(f"[bold red][!] Error loading cookies file {cookies_p}:[/bold red] {e}")
            sys.exit(1)

    # 9. Resolve Headers
    headers = None
    headers_path_str = args.headers or config_dict.get("auth", {}).get("headers_file")
    if headers_path_str:
        headers_p = Path(headers_path_str)
        try:
            headers = load_headers_file(headers_p)
        except Exception as e:
            err_console.print(f"[bold red][!] Error loading headers file {headers_p}:[/bold red] {e}")
            sys.exit(1)

    # 10. Resolve Status Filter
    status_raw = args.status or config_dict.get("filter", {}).get("status")
    status_filter = parse_status_filter(status_raw)

    # 11. Resolve Report
    if args.report is not None:
        generate_report = args.report
    else:
        generate_report = config_dict.get("report", {}).get("enabled", True)

    return ScanOptions(
        urls=urls,
        output_dir=output_dir,
        workers=max(1, workers),
        viewport=viewport,
        full_page=bool(full_page),
        timeout=max(1, timeout),
        delay=max(0.0, delay),
        retries=max(0, retries),
        proxy=proxy,
        cookies=cookies,
        headers=headers,
        status_filter=status_filter,
        status_raw=str(status_raw) if status_raw else None,
        resume=args.resume,
        generate_report=generate_report,
        verbose=args.verbose,
        quiet=args.quiet,
        user_agent=user_agent,
        config_file=config_path,
    )


async def async_main(argv: Optional[List[str]] = None) -> int:
    """Async CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    options = parse_arguments_to_options(args)

    # Print banner & startup
    print_banner(quiet=options.quiet)
    startup_animation(quiet=options.quiet)

    # Validate target presence
    if not options.urls:
        if not options.quiet:
            err_console.print(
                "[bold red][!] No targets specified.[/bold red]\n"
                "[dim]Use -u <url>, -l <file>, or pipe targets via stdin:\n"
                "  python3 reconshot.py -u https://example.com\n"
                "  python3 reconshot.py -l urls.txt\n"
                "  cat urls.txt | python3 reconshot.py[/dim]\n"
            )
        return 1

    try:
        engine = ReconShotEngine(options)
        summary = await engine.run()
        return 0 if summary.successful > 0 or summary.total_targets == 0 else 1
    except Exception as exc:
        err_console.print(f"[bold red][!] Critical error:[/bold red] {exc}")
        if options.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main() -> None:
    """Synchronous CLI entrypoint."""
    try:
        sys.exit(asyncio.run(async_main()))
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Operation cancelled by user.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
