"""
Multi-Format Export Hub and Webhook Notification Dispatcher for ReconShot.
Exports to CSV, Markdown, SQLite, JSON, and sends alerts to Discord/Slack.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import urllib.request

from reconshot.logger import logger
from reconshot.models import ScanSummary, TargetResult


def export_to_csv(results: List[TargetResult], csv_path: Path) -> Path:
    """Export target scan results to a formatted CSV spreadsheet."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "URL", "Final URL", "Status Code", "Page Title", "Response Time (ms)",
        "Technologies", "Security Grade", "Security Score", "Forms Found",
        "Has Login Form", "IP Addresses", "Screenshot", "Cluster ID", "Error"
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)

        for r in results:
            tech_str = ", ".join(t.name for t in r.technologies) if r.technologies else ""
            sec_grade = r.security.grade if r.security else "N/A"
            sec_score = r.security.score if r.security else "N/A"
            forms_cnt = r.dom.forms_count if r.dom else 0
            has_login = "Yes" if (r.dom and r.dom.has_login_form) else "No"
            ips = ", ".join(r.dns.ip_addresses) if (r.dns and r.dns.ip_addresses) else ""

            writer.writerow([
                r.url,
                r.final_url or r.url,
                r.status_code or "",
                r.page_title or "",
                f"{r.response_time_ms:.1f}" if r.response_time_ms is not None else "",
                tech_str,
                sec_grade,
                sec_score,
                forms_cnt,
                has_login,
                ips,
                r.screenshot or "",
                r.cluster_id or "",
                r.error or "",
            ])

    logger.debug(f"Exported CSV results to {csv_path}")
    return csv_path


def export_to_markdown(summary: ScanSummary, md_path: Path) -> Path:
    """Export executive penetration testing reconnaissance summary in Markdown."""
    md_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# ReconShot Reconnaissance Summary",
        f"",
        f"**Tool:** ReconShot v1.0.0  ",
        f"**Author:** Mr Dinesh Pathro ([buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro))  ",
        f"**Scan Date:** {summary.start_time}  ",
        f"**Duration:** {summary.duration_seconds:.2f}s  ",
        f"",
        f"## 📊 Executive Statistics",
        f"",
        f"| Metric | Count |",
        f"| :--- | :--- |",
        f"| **Total Targets** | `{summary.total_targets}` |",
        f"| **Successful Captures** | `{summary.successful}` |",
        f"| **Failed / Offline** | `{summary.failed}` |",
        f"| **Visual Clusters** | `{summary.clusters_count}` |",
        f"",
        f"## 🎯 Discovered Targets",
        f"",
        f"| Status | Target URL | Page Title | Security Grade | Technologies |",
        f"| :--- | :--- | :--- | :--- | :--- |",
    ]

    for r in summary.results:
        status = str(r.status_code) if r.status_code else "ERR"
        title = r.page_title.replace("|", "-") if r.page_title else "-"
        grade = r.security.grade if r.security else "N/A"
        techs = ", ".join(t.name for t in r.technologies[:3]) if r.technologies else "-"
        lines.append(f"| `{status}` | [{r.url}]({r.url}) | {title} | **{grade}** | {techs} |")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return md_path


def export_to_sqlite(results: List[TargetResult], db_path: Path) -> Path:
    """Export results to a structured SQLite database for relational querying."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            final_url TEXT,
            status_code INTEGER,
            page_title TEXT,
            response_time_ms REAL,
            security_grade TEXT,
            security_score INTEGER,
            technologies TEXT,
            forms_count INTEGER,
            has_login INTEGER,
            ip_addresses TEXT,
            screenshot TEXT,
            cluster_id TEXT,
            error TEXT
        )
    """)

    for r in results:
        tech_str = json.dumps([t.to_dict() for t in r.technologies])
        ips_str = json.dumps(r.dns.ip_addresses if r.dns else [])
        sec_grade = r.security.grade if r.security else None
        sec_score = r.security.score if r.security else None
        forms_cnt = r.dom.forms_count if r.dom else 0
        has_login = 1 if (r.dom and r.dom.has_login_form) else 0

        cursor.execute("""
            INSERT OR REPLACE INTO targets (
                url, final_url, status_code, page_title, response_time_ms,
                security_grade, security_score, technologies, forms_count,
                has_login, ip_addresses, screenshot, cluster_id, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r.url, r.final_url, r.status_code, r.page_title, r.response_time_ms,
            sec_grade, sec_score, tech_str, forms_cnt,
            has_login, ips_str, r.screenshot, r.cluster_id, r.error
        ))

    conn.commit()
    conn.close()
    return db_path


def send_webhook_notification(webhook_url: str, summary: ScanSummary) -> bool:
    """Dispatch a webhook notification to Discord or Slack upon scan completion."""
    if not webhook_url:
        return False

    payload = {
        "content": f"⚡ **ReconShot Scan Completed!** ⚡\n"
                   f"• **Targets:** {summary.total_targets}\n"
                   f"• **Successful:** {summary.successful}\n"
                   f"• **Failed:** {summary.failed}\n"
                   f"• **Duration:** {summary.duration_seconds:.1f}s\n"
                   f"• **Visual Clusters:** {summary.clusters_count}\n"
                   f"Author: Mr Dinesh Pathro (https://buymeacoffee.com/mrdineshpathro)"
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data_bytes,
            headers={"Content-Type": "application/json", "User-Agent": "ReconShot/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        logger.warning(f"Failed to dispatch webhook notification: {e}")
        return False
