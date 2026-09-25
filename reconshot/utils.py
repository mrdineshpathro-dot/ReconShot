"""
Utility functions, ASCII banners, and styling helpers for ReconShot.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Shared Rich console
console = Console()
err_console = Console(stderr=True)

ASCII_BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
██████╔╝█████╗  ██║     ██████╔╝██╔██╗ ██║███████╗███████║██║   ██║   ██║   
██╔══██╗██╔══╝  ██║     ██╔══██╗██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║   
██║  ██║███████╗╚██████╗██║  ██║██║ ╚████║███████║██║  ██║╚██████╔╝   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   
"""

BRAND_TITLE = "ReconShot"
BRAND_TAGLINE = "Automated Web Application Screenshot Reconnaissance"
BRAND_AUTHOR = "Mr Dinesh Pathro"
BRAND_SUPPORT = "https://buymeacoffee.com/mrdineshpathro"
BRAND_PLATFORM = "Kali Linux"
BRAND_VERSION = "v1.0.0"


def print_banner(quiet: bool = False, animate: bool = True) -> None:
    """Print the official ReconShot ASCII banner and branding card."""
    if quiet:
        return

    banner_text = Text()
    colors = [
        "bright_cyan",
        "cyan",
        "deep_sky_blue1",
        "dodger_blue1",
        "magenta",
        "dark_magenta",
    ]
    lines = [line for line in ASCII_BANNER.strip("\n").split("\n")]

    for i, line in enumerate(lines):
        color = colors[min(i, len(colors) - 1)]
        banner_text.append(line + "\n", style=f"bold {color}")

    console.print(banner_text)

    # Info card below banner
    info_text = Text()
    info_text.append(f"[ {BRAND_TITLE} {BRAND_VERSION} ]\n", style="bold bright_white")
    info_text.append(f"{BRAND_TAGLINE}\n\n", style="italic cyan")
    info_text.append("Author  : ", style="bold bright_cyan")
    info_text.append(f"{BRAND_AUTHOR}\n", style="bright_white")
    info_text.append("Support : ", style="bold bright_cyan")
    info_text.append(f"{BRAND_SUPPORT}\n", style="underline bright_yellow")
    info_text.append("Platform: ", style="bold bright_cyan")
    info_text.append(f"{BRAND_PLATFORM}", style="green")

    panel = Panel(
        info_text,
        border_style="cyan",
        padding=(0, 2),
        title="[bold cyan]⚡ RECONNAISSANCE TOOL ⚡[/bold cyan]",
        subtitle="[dim]Authorized Security Testing Only[/dim]",
    )
    console.print(panel)
    console.print()


def startup_animation(quiet: bool = False) -> None:
    """Display a subtle, fast cybersecurity startup indicator."""
    if quiet or not sys.stdout.isatty():
        return

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    message = " Initializing ReconShot Engine..."
    for _ in range(2):
        for frame in frames:
            sys.stdout.write(f"\r\033[96m{frame}\033[0m{message}")
            sys.stdout.flush()
            time.sleep(0.02)
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()


def format_duration(seconds: float) -> str:
    """Format seconds into readable 00m 00s or 00s format."""
    total_sec = max(0, int(seconds))
    mins, secs = divmod(total_sec, 60)
    hours, mins = divmod(mins, 60)

    if hours > 0:
        return f"{hours:02d}h {mins:02d}m {secs:02d}s"
    if mins > 0:
        return f"{mins:02d}m {secs:02d}s"
    return f"{seconds:.2f}s" if seconds < 10 else f"{secs:02d}s"


def ensure_output_dirs(base_dir: Path) -> Tuple[Path, Path, Path, Path]:
    """
    Ensure the standard ReconShot directory structure exists safely:
      base_dir/
      ├── screenshots/
      ├── metadata/
      ├── reports/
      └── logs/
    """
    base_dir = base_dir.resolve()
    screenshots_dir = base_dir / "screenshots"
    metadata_dir = base_dir / "metadata"
    reports_dir = base_dir / "reports"
    logs_dir = base_dir / "logs"

    for d in (base_dir, screenshots_dir, metadata_dir, reports_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)

    return screenshots_dir, metadata_dir, reports_dir, logs_dir


def get_status_style(status_code: Optional[int]) -> Tuple[str, str]:
    """
    Return appropriate rich style and symbol for HTTP status code.
    Returns (style_name, status_str).
    """
    if status_code is None:
        return "dim red", "---"
    if 200 <= status_code < 300:
        return "bold green", str(status_code)
    if 300 <= status_code < 400:
        return "bold cyan", str(status_code)
    if 400 <= status_code < 500:
        return "bold yellow", str(status_code)
    if 500 <= status_code < 600:
        return "bold red", str(status_code)
    return "magenta", str(status_code)
