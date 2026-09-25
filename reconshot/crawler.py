"""
Concurrent scan orchestrator, live Rich progress UI, visual clustering,
and export runner for ReconShot.
"""

from __future__ import annotations

import asyncio
from collections import Counter
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import uuid

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from reconshot.browser import BrowserManager
from reconshot.exporter import (
    export_to_csv,
    export_to_markdown,
    export_to_sqlite,
    send_webhook_notification,
)
from reconshot.logger import log_failure, log_success, logger, setup_logging
from reconshot.metadata import (
    load_resume_state,
    save_resume_state,
    save_scan_summary,
    save_target_metadata,
)
from reconshot.models import ScanOptions, ScanSummary, TargetResult
from reconshot.naming import url_to_filename
from reconshot.reporter import generate_html_report
from reconshot.scope_filter import sort_targets_by_priority
from reconshot.screenshot import capture_target_with_retry
from reconshot.utils import (
    console,
    ensure_output_dirs,
    format_duration,
    get_status_style,
)
from reconshot.visual_engine import cluster_target_results


class ReconShotEngine:
    """Core scanning, intelligence extraction, and screenshot orchestration engine."""

    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.scan_id = str(uuid.uuid4())[:8]
        self.start_time: float = 0.0
        self.start_iso: str = ""
        self.completed_urls: Set[str] = set()
        self.results: List[TargetResult] = []
        self.successful_count: int = 0
        self.failed_count: int = 0
        self.interrupted: bool = False
        self.browser_manager: Optional[BrowserManager] = None

        # Output Directories
        self.screenshots_dir, self.metadata_dir, self.reports_dir, self.logs_dir = (
            ensure_output_dirs(self.options.output_dir)
        )
        self.state_file = self.options.output_dir / ".reconshot_state.json"
        self.log_file = self.logs_dir / "reconshot.log"
        self.success_file = self.logs_dir / "success.txt"
        self.failed_file = self.logs_dir / "failed.txt"

        # Setup Logging
        setup_logging(self.log_file, self.options.verbose, self.options.quiet)

    def _print_target_log(self, result: TargetResult) -> None:
        """Print rich formatted terminal log line for each captured target."""
        if self.options.quiet:
            return

        if result.success and result.screenshot:
            status_style, status_text = get_status_style(result.status_code)
            
            # Security Grade Tag
            sec_tag = ""
            if result.security:
                g = result.security.grade
                g_style = "bold green" if g in ("A+", "A") else ("bold yellow" if g in ("B", "C") else "bold red")
                sec_tag = f" [{g_style}][{g}][/{g_style}]"

            console.print(f"[bold green][✓][/bold green] [{status_style}]{status_text:>3}[/{status_style}]{sec_tag}  [bright_white]{result.url}[/bright_white]")
            
            # Title & Technologies Line
            details_items = []
            if result.page_title:
                t_clean = result.page_title.strip()
                if len(t_clean) > 55:
                    t_clean = t_clean[:52] + "..."
                details_items.append(f"[dim italic]{t_clean}[/dim italic]")

            if result.technologies:
                tech_names = ", ".join(t.name for t in result.technologies[:4])
                details_items.append(f"[cyan]Tech: {tech_names}[/cyan]")

            if details_items:
                joined = "  •  ".join(details_items)
                console.print(f"     [cyan]└──[/cyan] {joined}")

            # Forms / Endpoints alert
            if result.dom and result.dom.has_login_form:
                console.print(f"         [yellow]🔑 Login Form Detected[/yellow]")

        elif result.success and not result.screenshot and result.error == "Filtered by status code":
            status_style, status_text = get_status_style(result.status_code)
            console.print(f"[bold yellow][○][/bold yellow] [{status_style}]{status_text:>3}[/{status_style}]  [dim]{result.url} (Status filtered)[/dim]")
        else:
            err_msg = result.error or "Failed"
            if len(err_msg) > 60:
                err_msg = err_msg[:57] + "..."
            console.print(f"[bold red][✗][/bold red] [dim red]---[/dim red]  [white]{result.url}[/white] [dim red]({err_msg})[/dim red]")

    async def _process_single_target(
        self,
        url: str,
        semaphore: asyncio.Semaphore,
        progress: Progress,
        task_id: Any,
    ) -> None:
        """Worker task processing a single target."""
        if self.interrupted or not self.browser_manager:
            return

        async with semaphore:
            if self.interrupted:
                return

            screenshot_filename = url_to_filename(url, ext=".png")
            screenshot_path = self.screenshots_dir / screenshot_filename

            context = None
            try:
                context = await self.browser_manager.create_context()
                result = await capture_target_with_retry(
                    url=url,
                    context=context,
                    options=self.options,
                    screenshot_path=screenshot_path,
                )
            except Exception as e:
                logger.debug(f"Unhandled worker exception for {url}: {e}")
                result = TargetResult(
                    url=url,
                    final_url=url,
                    success=False,
                    error=str(e)[:120],
                )
            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass

            # Update engine state
            self.results.append(result)
            self.completed_urls.add(url)

            if result.success and result.screenshot:
                self.successful_count += 1
                log_success(self.success_file, result.url, result.status_code)
            else:
                self.failed_count += 1
                log_failure(self.failed_file, result.url, result.error or "Failed")

            # Persist individual target metadata
            save_target_metadata(result, self.metadata_dir)

            # Persist atomic resume state
            save_resume_state(
                self.state_file,
                self.scan_id,
                self.completed_urls,
                self.results,
            )

            # Update CLI output & progress bar
            self._print_target_log(result)
            progress.advance(task_id, 1)

    async def run(self) -> ScanSummary:
        """Execute full scanning, clustering, intelligence aggregation, and exports."""
        self.start_time = time.monotonic()
        self.start_iso = datetime.now(timezone.utc).astimezone().isoformat()

        all_urls = self.options.urls
        total_initial = len(all_urls)

        # Handle Resume Mode
        if self.options.resume:
            prev_id, prev_completed, prev_results = load_resume_state(self.state_file)
            if prev_completed:
                self.completed_urls = set(prev_completed)
                self.results = list(prev_results)
                self.successful_count = sum(1 for r in self.results if r.success and r.screenshot)
                self.failed_count = sum(1 for r in self.results if not r.success or not r.screenshot)
                if prev_id:
                    self.scan_id = prev_id
                
                skipped_count = len(self.completed_urls.intersection(set(all_urls)))
                console.print(f"[bold cyan][+][/bold cyan] [bold bright_white]Resuming ReconShot scan...[/bold bright_white]")
                console.print(f"[bold cyan][+][/bold cyan] Skipping [bold green]{skipped_count}[/bold green] already completed targets")
                
                targets_to_scan = [u for u in all_urls if u not in self.completed_urls]
                console.print(f"[bold cyan][+][/bold cyan] Processing [bold yellow]{len(targets_to_scan)}[/bold yellow] remaining targets\n")
            else:
                targets_to_scan = all_urls
        else:
            targets_to_scan = all_urls

        # Sort targets putting high priority assets (admin, vpn, dev) first
        targets_to_scan = sort_targets_by_priority(targets_to_scan)
        total_targets = len(targets_to_scan)

        if not self.options.quiet:
            config_grid = Table.grid(expand=True, padding=(0, 2))
            config_grid.add_column(style="bold cyan", width=14)
            config_grid.add_column(style="bright_white")
            config_grid.add_column(style="bold cyan", width=14)
            config_grid.add_column(style="bright_white")

            vp_str = f"{self.options.viewport.width}x{self.options.viewport.height}"
            if self.options.viewport.is_mobile:
                vp_str += " (Mobile)"

            config_grid.add_row("Targets    :", f"[bold white]{total_targets}[/bold white]", "Workers    :", f"[bold magenta]{self.options.workers}[/bold magenta]")
            config_grid.add_row("Viewport   :", f"[bold white]{vp_str}[/bold white]", "Full Page  :", f"[bold white]{'Yes' if self.options.full_page else 'No'}[/bold white]")
            config_grid.add_row("Timeout    :", f"[bold white]{self.options.timeout}s[/bold white]", "Delay      :", f"[bold white]{self.options.delay}s[/bold white]")
            config_grid.add_row("Output     :", f"[bold white]{self.options.output_dir}[/bold white]", "Report     :", f"[bold white]{'Enabled' if self.options.generate_report else 'Disabled'}[/bold white]")
            if self.options.proxy:
                config_grid.add_row("Proxy      :", f"[bold yellow]{self.options.proxy}[/bold yellow]", "", "")
            if self.options.status_raw:
                config_grid.add_row("Status Filter:", f"[bold green]{self.options.status_raw}[/bold green]", "", "")

            console.print(Panel(config_grid, title="[bold cyan]🎯 ReconShot Configuration[/bold cyan]", border_style="cyan", padding=(0, 1)))
            console.print()

        if total_targets == 0:
            console.print("[yellow][!] No targets to process.[/yellow]")
            duration = time.monotonic() - self.start_time
            return ScanSummary(
                scan_id=self.scan_id,
                start_time=self.start_iso,
                end_time=datetime.now(timezone.utc).astimezone().isoformat(),
                duration_seconds=duration,
                total_targets=total_initial,
                successful=self.successful_count,
                failed=self.failed_count,
                skipped=len(self.completed_urls),
                results=self.results,
            )

        # Initialize Browser
        self.browser_manager = BrowserManager(self.options)
        await self.browser_manager.initialize()

        semaphore = asyncio.Semaphore(self.options.workers)

        progress = Progress(
            SpinnerColumn(spinner_name="dots", style="bold cyan"),
            TextColumn("[bold bright_cyan]{task.description}[/bold bright_cyan]"),
            BarColumn(bar_width=32, style="dim cyan", complete_style="bold bright_cyan"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        )

        try:
            with progress:
                task_id = progress.add_task("Capturing", total=total_targets)
                tasks = [
                    asyncio.create_task(
                        self._process_single_target(url, semaphore, progress, task_id)
                    )
                    for url in targets_to_scan
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

        except (asyncio.CancelledError, KeyboardInterrupt):
            self.interrupted = True
            console.print("\n[bold yellow][!] Interrupt received (CTRL+C)[/bold yellow]")
            console.print("[bold cyan][+][/bold cyan] Saving current progress...")
            save_resume_state(self.state_file, self.scan_id, self.completed_urls, self.results)
            console.print("[bold cyan][+][/bold cyan] Closing browser...")
        finally:
            if self.browser_manager:
                await self.browser_manager.close()

        if self.interrupted:
            console.print("[bold green][+][/bold green] ReconShot stopped safely.")
            console.print("[bold cyan][+][/bold cyan] Resume later with: [bold yellow]--resume[/bold yellow]\n")

        duration = time.monotonic() - self.start_time
        end_iso = datetime.now(timezone.utc).astimezone().isoformat()

        # 1. Visual Clustering Computation
        clusters_count = 0
        if self.options.visual_clustering:
            clusters_count = cluster_target_results(self.results)

        # 2. Tech Stack & Security Statistics Aggregation
        tech_counter: Counter = Counter()
        grade_counter: Counter = Counter()

        for r in self.results:
            if r.technologies:
                for t in r.technologies:
                    tech_counter[t.name] += 1
            if r.security:
                grade_counter[r.security.grade] += 1

        top_techs = [{"name": name, "count": count} for name, count in tech_counter.most_common(10)]
        security_grades = dict(grade_counter)

        # Build Scan Summary
        summary = ScanSummary(
            scan_id=self.scan_id,
            start_time=self.start_iso,
            end_time=end_iso,
            duration_seconds=duration,
            total_targets=total_initial,
            successful=self.successful_count,
            failed=self.failed_count,
            skipped=total_initial - len(self.results),
            results=self.results,
            clusters_count=clusters_count,
            top_technologies=top_techs,
            security_grades=security_grades,
            options={
                "workers": self.options.workers,
                "timeout": self.options.timeout,
                "delay": self.options.delay,
                "viewport": self.options.viewport.to_dict(),
                "full_page": self.options.full_page,
            },
        )

        # Save Summary JSON
        save_scan_summary(summary, self.metadata_dir)

        # 3. Multi-Format Exports
        if self.options.export_csv:
            export_to_csv(self.results, self.options.output_dir / "results.csv")
        if self.options.export_markdown:
            export_to_markdown(summary, self.options.output_dir / "summary.md")
        if self.options.export_sqlite:
            export_to_sqlite(self.results, self.options.output_dir / "reconshot.db")

        # 4. Generate HTML Report
        report_file_path = self.reports_dir / "report.html"
        if self.options.generate_report:
            generate_html_report(summary, report_file_path)

        # 5. Webhook Notification
        if self.options.webhook_url:
            send_webhook_notification(self.options.webhook_url, summary)

        # 6. Print Final Summary UI
        self._print_scan_summary(summary, report_file_path)

        return summary

    def _print_scan_summary(self, summary: ScanSummary, report_path: Path) -> None:
        """Print the polished end-of-scan summary table and card."""
        if self.options.quiet:
            return

        console.print()
        # Summary Box
        summary_grid = Table.grid(expand=True, padding=(0, 2))
        summary_grid.add_column(style="bold cyan", width=16)
        summary_grid.add_column(style="bright_white")
        summary_grid.add_column(style="bold cyan", width=16)
        summary_grid.add_column(style="bright_white")

        summary_grid.add_row("Targets    :", f"[bold white]{summary.total_targets}[/bold white]", "Successful :", f"[bold green]{summary.successful}[/bold green]")
        summary_grid.add_row("Duration   :", f"[bold white]{format_duration(summary.duration_seconds)}[/bold white]", "Failed     :", f"[bold red]{summary.failed}[/bold red]")
        summary_grid.add_row("Visual Clusters:", f"[bold magenta]{summary.clusters_count}[/bold magenta]", "Screenshots:", f"[cyan]{self.screenshots_dir}[/cyan]")
        if self.options.generate_report:
            summary_grid.add_row("HTML Report:", f"[bold green]{report_path}[/bold green]", "CSV Export :", f"[bold cyan]{self.options.output_dir / 'results.csv'}[/bold cyan]")

        console.print(
            Panel(
                summary_grid,
                title="[bold green]🏁 ReconShot Intelligence Summary 🏁[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )

        # Target Results Summary Table
        if summary.results and not self.options.quiet:
            table = Table(
                title="[bold cyan]Discovered Applications & Intelligence[/bold cyan]",
                show_header=True,
                header_style="bold cyan",
                border_style="dim cyan",
                padding=(0, 1),
                expand=True,
            )
            table.add_column("Status", justify="center", width=7)
            table.add_column("Sec", justify="center", width=5)
            table.add_column("Target URL", style="bright_white", ratio=3)
            table.add_column("Page Title / Errors", style="italic cyan", ratio=3)
            table.add_column("Technologies", style="magenta", ratio=2)
            table.add_column("Time", justify="right", width=8)

            for r in summary.results:
                style_name, status_str = get_status_style(r.status_code)
                status_text = Text(status_str, style=style_name)

                sec_grade = r.security.grade if r.security else "-"
                sec_style = "bold green" if sec_grade in ("A+", "A") else ("bold yellow" if sec_grade in ("B", "C") else "bold red")
                sec_text = Text(sec_grade, style=sec_style)

                url_text = Text(r.url, overflow="ellipsis")
                title_text = Text(r.page_title or (r.error or "--"), overflow="ellipsis")
                techs_str = ", ".join(t.name for t in r.technologies[:3]) if r.technologies else "--"
                tech_text = Text(techs_str, overflow="ellipsis")
                time_text = Text(f"{r.response_time_ms:.0f}ms" if r.response_time_ms is not None else "--", style="dim")

                table.add_row(status_text, sec_text, url_text, title_text, tech_text, time_text)

            console.print(table)

        console.print("[bold green][✓] ReconShot completed successfully.[/bold green]\n")
