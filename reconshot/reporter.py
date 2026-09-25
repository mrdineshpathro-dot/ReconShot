"""
Interactive Dark-Themed Cybersecurity HTML Report Gallery 2.0 for ReconShot.
Zero external dependencies; fully functional offline and air-gapped.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import List, Optional

from reconshot.logger import logger
from reconshot.models import ScanSummary, TargetResult


def escape(val: Optional[str]) -> str:
    """HTML escape string safely."""
    if val is None:
        return ""
    return html.escape(str(val))


def generate_html_report(summary: ScanSummary, report_path: Path) -> Path:
    """
    Generate an ultra-modern, dark-themed, standalone HTML report gallery 2.0
    with interactive filters, tech stack badges, security grades, and DOM insights.
    """
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # Status counts
    c_2xx = sum(1 for r in summary.results if r.status_code and 200 <= r.status_code < 300)
    c_3xx = sum(1 for r in summary.results if r.status_code and 300 <= r.status_code < 400)
    c_4xx = sum(1 for r in summary.results if r.status_code and 400 <= r.status_code < 500)
    c_5xx = sum(1 for r in summary.results if r.status_code and 500 <= r.status_code < 600)
    c_failed = summary.failed

    valid_times = [r.response_time_ms for r in summary.results if r.response_time_ms is not None]
    avg_time = round(sum(valid_times) / len(valid_times), 1) if valid_times else 0

    results_json = json.dumps([r.to_dict() for r in summary.results], ensure_ascii=False)

    cards_html: List[str] = []
    table_rows_html: List[str] = []

    for idx, r in enumerate(summary.results):
        status_cls = "status-other"
        status_category = "failed"
        if r.status_code:
            if 200 <= r.status_code < 300:
                status_cls = "status-2xx"
                status_category = "2xx"
            elif 300 <= r.status_code < 400:
                status_cls = "status-3xx"
                status_category = "3xx"
            elif 400 <= r.status_code < 500:
                status_cls = "status-4xx"
                status_category = "4xx"
            elif 500 <= r.status_code < 600:
                status_cls = "status-5xx"
                status_category = "5xx"

        status_text = str(r.status_code) if r.status_code else "ERR"
        title_disp = escape(r.page_title) if r.page_title else "<span class='dim-text'>No Title</span>"
        final_url_disp = escape(r.final_url) if r.final_url else escape(r.url)
        resp_time_disp = f"{r.response_time_ms:.1f} ms" if r.response_time_ms is not None else "--"
        vp_disp = f"{r.viewport.get('width', 1920)}×{r.viewport.get('height', 1080)}"
        screenshot_rel = f"../screenshots/{r.screenshot}" if r.screenshot else ""

        # Security Grade Badge
        sec_grade = r.security.grade if r.security else "N/A"
        sec_score = r.security.score if r.security else 0
        sec_cls = "grade-good" if sec_grade in ("A+", "A") else ("grade-warn" if sec_grade in ("B", "C") else "grade-bad")

        # Tech Stack Badges
        tech_chips = []
        tech_search_terms = []
        if r.technologies:
            for t in r.technologies:
                ver_str = f" {escape(t.version)}" if t.version else ""
                tech_chips.append(f'<span class="tech-chip">{escape(t.name)}{ver_str}</span>')
                tech_search_terms.append(t.name.lower())
        tech_html = " ".join(tech_chips) if tech_chips else "<span class='dim-text'>No tech detected</span>"

        # DNS IPs
        ip_str = ", ".join(r.dns.ip_addresses[:2]) if (r.dns and r.dns.ip_addresses) else ""

        # Card Image / Placeholder
        card_img_html = ""
        if r.screenshot:
            card_img_html = f"""
            <div class="card-image-wrapper" onclick="openLightbox('{screenshot_rel}', '{escape(r.url)}', '{status_text}', '{sec_grade}')">
                <img src="{screenshot_rel}" alt="Screenshot of {escape(r.url)}" loading="lazy" class="card-img" />
                <div class="image-overlay"><span class="overlay-icon">🔍 Inspect Screen</span></div>
            </div>
            """
        else:
            error_reason = escape(r.error or "Capture failed")
            card_img_html = f"""
            <div class="card-no-image">
                <div class="no-img-icon">⚠️</div>
                <div class="no-img-text">{error_reason}</div>
            </div>
            """

        # Takeover Banner
        takeover_banner = ""
        if r.dns and r.dns.takeover_indicator:
            takeover_banner = f"""
            <div class="takeover-alert">
                ⚡ <strong>Takeover Risk:</strong> {escape(r.dns.takeover_indicator)}
            </div>
            """

        # Secret Leaks Banner
        secrets_banner = ""
        if r.dom and r.dom.potential_secrets:
            secrets_list = ", ".join(f"{s['type']} ({s['preview']})" for s in r.dom.potential_secrets[:3])
            secrets_banner = f"""
            <div class="secret-alert">
                🔑 <strong>Secret Leak Detected:</strong> {escape(secrets_list)}
            </div>
            """

        # Login Form Badge
        login_badge = '<span class="login-badge">🔑 Login Form</span>' if (r.dom and r.dom.has_login_form) else ''
        cluster_badge = f'<span class="cluster-tag" onclick="filterByCluster(\'{r.cluster_id}\')">📦 {r.cluster_id}</span>' if r.cluster_id else ''

        # Search Data
        search_data = f"{r.url.lower()} {r.page_title.lower() if r.page_title else ''} {status_text} {' '.join(tech_search_terms)} {ip_str.lower()} {r.cluster_id or ''}".replace('"', '&quot;')

        cards_html.append(f"""
        <div class="recon-card" data-idx="{idx}" data-category="{status_category}" data-grade="{sec_grade}" data-cluster="{r.cluster_id or ''}" data-search="{search_data}">
            {card_img_html}
            <div class="card-body">
                <div class="card-header-row">
                    <span class="badge {status_cls}">{status_text}</span>
                    <span class="grade-badge {sec_cls}" title="Security Score: {sec_score}/100">Grade {sec_grade}</span>
                    {login_badge}
                    {cluster_badge}
                    <span class="resp-tag">⏱ {resp_time_disp}</span>
                </div>

                <h3 class="card-title" title="{escape(r.page_title or '')}">{title_disp}</h3>

                <div class="card-url-row">
                    <span class="url-label">Target:</span>
                    <a href="{escape(r.url)}" target="_blank" rel="noopener noreferrer" class="card-url" title="{escape(r.url)}">{escape(r.url)}</a>
                </div>
                {f'<div class="card-url-row final-url-row"><span class="url-label">Final:</span><a href="{final_url_disp}" target="_blank" rel="noopener noreferrer" class="card-url dim" title="{final_url_disp}">{final_url_disp}</a></div>' if r.final_url and r.final_url != r.url else ''}
                {f'<div class="ip-row"><span class="url-label">IP:</span> <code>{escape(ip_str)}</code></div>' if ip_str else ''}

                <div class="tech-row">
                    {tech_html}
                </div>

                {takeover_banner}
                {secrets_banner}

                <details class="card-details">
                    <summary>Full Intelligence & DOM Findings</summary>
                    <div class="details-content">
                        <div><strong>Timestamp:</strong> <code>{escape(r.timestamp)}</code></div>
                        {f'<div><strong>Forms Count:</strong> <code>{r.dom.forms_count}</code> (Input Types: {", ".join(r.dom.input_types)})</div>' if r.dom and r.dom.forms_count else ''}
                        {f'<div><strong>Discovered Endpoints ({len(r.dom.endpoints)}):</strong><pre>{escape(chr(10).join(r.dom.endpoints[:10]))}</pre></div>' if r.dom and r.dom.endpoints else ''}
                        {f'<div><strong>Missing Security Headers:</strong> <span class="err-text">{", ".join(r.security.missing_headers)}</span></div>' if r.security and r.security.missing_headers else ''}
                        {f'<div><strong>Information Leaks:</strong> <span class="warn-text">{"; ".join(r.security.info_leaks)}</span></div>' if r.security and r.security.info_leaks else ''}
                        {f'<div><strong>Server Headers:</strong><pre>{escape(json.dumps(r.headers_received or {}, indent=2))}</pre></div>' if r.headers_received else ''}
                    </div>
                </details>
            </div>
        </div>
        """)

        # Table row
        thumb_html = f'<img src="{screenshot_rel}" class="table-thumb" onclick="openLightbox(\'{screenshot_rel}\', \'{escape(r.url)}\', \'{status_text}\', \'{sec_grade}\')">' if r.screenshot else '<span class="dim-text">None</span>'
        table_rows_html.append(f"""
        <tr data-category="{status_category}" data-grade="{sec_grade}" data-cluster="{r.cluster_id or ''}" data-search="{search_data}">
            <td>{thumb_html}</td>
            <td><a href="{escape(r.url)}" target="_blank" rel="noopener noreferrer" class="table-url">{escape(r.url)}</a></td>
            <td><span class="badge {status_cls}">{status_text}</span></td>
            <td><span class="grade-badge {sec_cls}">{sec_grade}</span></td>
            <td>{title_disp}</td>
            <td>{tech_html}</td>
            <td>{resp_time_disp}</td>
        </tr>
        """)

    all_cards_str = "\n".join(cards_html)
    all_table_rows_str = "\n".join(table_rows_html)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconShot Intelligence Gallery 2.0</title>
    <style>
        :root {{
            --bg-primary: #070a12;
            --bg-secondary: #0e1424;
            --bg-card: #121b30;
            --bg-card-hover: #182440;
            --border-color: #1c273c;
            --border-highlight: #00f2fe;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #00f2fe;
            --accent-blue: #38bdf8;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --accent-magenta: #ec4899;
            --accent-purple: #a855f7;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 16px;
            --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6);
            --transition: all 0.2s ease-in-out;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            padding-bottom: 60px;
        }}

        /* Header */
        .header {{
            background: linear-gradient(180deg, #10192e 0%, var(--bg-primary) 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 24px 40px;
            position: sticky;
            top: 0;
            z-index: 50;
            backdrop-filter: blur(12px);
        }}
        .header-content {{
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .brand-title {{
            font-size: 26px;
            font-weight: 800;
            background: linear-gradient(135deg, #00f2fe 0%, #38bdf8 50%, #a855f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand-subtitle {{ font-size: 13px; color: var(--text-secondary); }}
        .brand-author {{ font-size: 13px; color: var(--text-secondary); }}
        .brand-author a {{ color: var(--accent-yellow); text-decoration: none; font-weight: 600; }}
        .brand-author a:hover {{ text-decoration: underline; }}

        /* Main */
        .container {{ max-width: 1600px; margin: 24px auto; padding: 0 30px; }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            box-shadow: var(--shadow);
            transition: var(--transition);
        }}
        .stat-card:hover {{ border-color: var(--accent-cyan); transform: translateY(-2px); }}
        .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); font-weight: 700; margin-bottom: 4px; }}
        .stat-value {{ font-size: 26px; font-weight: 800; }}
        .stat-green {{ color: var(--accent-green); }}
        .stat-blue {{ color: var(--accent-blue); }}
        .stat-yellow {{ color: var(--accent-yellow); }}
        .stat-red {{ color: var(--accent-red); }}
        .stat-cyan {{ color: var(--accent-cyan); }}
        .stat-purple {{ color: var(--accent-purple); }}

        /* Controls Panel */
        .controls-panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 14px;
            box-shadow: var(--shadow);
        }}
        .search-box {{ flex: 1; min-width: 260px; position: relative; }}
        .search-input {{
            width: 100%;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 9px 12px 9px 34px;
            color: var(--text-primary);
            font-size: 13px;
            outline: none;
        }}
        .search-input:focus {{ border-color: var(--accent-cyan); box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.2); }}
        .search-icon {{ position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--text-muted); font-size: 13px; }}

        .filter-pills {{ display: flex; gap: 6px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 5px 12px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            cursor: pointer;
            transition: var(--transition);
        }}
        .filter-btn:hover {{ color: var(--text-primary); border-color: rgba(255, 255, 255, 0.2); }}
        .filter-btn.active {{ background: rgba(0, 242, 254, 0.15); border-color: var(--accent-cyan); color: var(--accent-cyan); }}

        .action-btns {{ display: flex; gap: 8px; }}
        .action-btn {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 7px 12px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            cursor: pointer;
            transition: var(--transition);
        }}
        .action-btn:hover {{ border-color: var(--accent-cyan); color: var(--text-primary); }}

        /* Gallery Grid */
        .gallery-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
            gap: 20px;
        }}
        .recon-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            overflow: hidden;
            display: flex;
            flex-direction: column;
            box-shadow: var(--shadow);
            transition: var(--transition);
        }}
        .recon-card:hover {{
            border-color: rgba(0, 242, 254, 0.4);
            transform: translateY(-3px);
            box-shadow: 0 15px 30px -5px rgba(0, 0, 0, 0.7);
        }}

        .card-image-wrapper {{
            position: relative;
            width: 100%;
            height: 200px;
            background: #000;
            overflow: hidden;
            cursor: pointer;
        }}
        .card-img {{
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: top;
            transition: transform 0.3s ease;
        }}
        .card-image-wrapper:hover .card-img {{ transform: scale(1.03); }}

        .image-overlay {{
            position: absolute;
            inset: 0;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: var(--transition);
        }}
        .card-image-wrapper:hover .image-overlay {{ opacity: 1; }}
        .overlay-icon {{
            background: rgba(14, 20, 36, 0.9);
            padding: 7px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: #fff;
            border: 1px solid var(--accent-cyan);
        }}

        .card-no-image {{
            height: 160px;
            background: rgba(14, 20, 36, 0.6);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 16px;
            text-align: center;
            border-bottom: 1px solid var(--border-color);
        }}
        .no-img-icon {{ font-size: 28px; margin-bottom: 6px; }}
        .no-img-text {{ font-size: 12px; color: var(--accent-red); word-break: break-word; }}

        .card-body {{ padding: 16px; display: flex; flex-direction: column; gap: 8px; flex: 1; }}
        .card-header-row {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }}

        .badge {{ padding: 3px 7px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .status-2xx {{ background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .status-3xx {{ background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); border: 1px solid rgba(56, 189, 248, 0.3); }}
        .status-4xx {{ background: rgba(245, 158, 11, 0.15); color: var(--accent-yellow); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .status-5xx {{ background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .status-other {{ background: rgba(100, 116, 139, 0.15); color: var(--text-muted); border: 1px solid rgba(100, 116, 139, 0.3); }}

        .grade-badge {{ padding: 3px 6px; border-radius: 4px; font-size: 11px; font-weight: 800; }}
        .grade-good {{ background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .grade-warn {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .grade-bad {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}

        .login-badge {{ background: rgba(168, 85, 247, 0.15); color: var(--accent-purple); border: 1px solid rgba(168, 85, 247, 0.3); padding: 3px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .cluster-tag {{ background: rgba(0, 242, 254, 0.1); color: var(--accent-cyan); border: 1px solid rgba(0, 242, 254, 0.2); padding: 3px 6px; border-radius: 4px; font-size: 11px; cursor: pointer; }}
        .resp-tag {{ font-size: 11px; color: var(--text-muted); background: rgba(0, 0, 0, 0.3); padding: 3px 6px; border-radius: 4px; }}

        .card-title {{ font-size: 14px; font-weight: 700; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .card-url-row, .ip-row {{ display: flex; align-items: center; gap: 6px; font-size: 12px; }}
        .url-label {{ font-size: 10px; text-transform: uppercase; font-weight: 800; color: var(--text-muted); }}
        .card-url {{ color: var(--accent-cyan); text-decoration: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; }}
        .card-url:hover {{ text-decoration: underline; }}
        .card-url.dim {{ color: var(--text-secondary); }}

        .tech-row {{ display: flex; flex-wrap: wrap; gap: 4px; margin: 4px 0; }}
        .tech-chip {{ background: #080d1a; border: 1px solid var(--border-color); color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-size: 11px; }}

        .takeover-alert {{ background: rgba(239, 68, 68, 0.15); border: 1px solid var(--accent-red); color: #fca5a5; padding: 6px 10px; border-radius: 6px; font-size: 11px; }}
        .secret-alert {{ background: rgba(245, 158, 11, 0.15); border: 1px solid var(--accent-yellow); color: #fde68a; padding: 6px 10px; border-radius: 6px; font-size: 11px; }}

        .card-details {{ margin-top: auto; border-top: 1px solid var(--border-color); padding-top: 8px; font-size: 11px; color: var(--text-secondary); }}
        .card-details summary {{ cursor: pointer; color: var(--text-muted); outline: none; }}
        .card-details summary:hover {{ color: var(--accent-cyan); }}
        .details-content {{ padding-top: 6px; display: flex; flex-direction: column; gap: 4px; }}
        .details-content code, .details-content pre {{ background: #040711; padding: 4px 6px; border-radius: 4px; font-family: monospace; font-size: 10px; color: #38bdf8; overflow-x: auto; }}
        .err-text {{ color: var(--accent-red); }}
        .warn-text {{ color: var(--accent-yellow); }}
        .dim-text {{ color: var(--text-muted); font-style: italic; }}

        /* Table View */
        .table-view-container {{ display: none; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius-md); overflow-x: auto; box-shadow: var(--shadow); }}
        .recon-table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 12px; }}
        .recon-table th {{ background: #0c1220; padding: 10px 14px; font-size: 11px; text-transform: uppercase; color: var(--text-secondary); border-bottom: 1px solid var(--border-color); }}
        .recon-table td {{ padding: 10px 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.04); vertical-align: middle; }}
        .table-thumb {{ width: 55px; height: 35px; object-fit: cover; border-radius: 4px; cursor: pointer; border: 1px solid var(--border-color); }}
        .table-url {{ color: var(--accent-cyan); text-decoration: none; max-width: 280px; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

        /* Lightbox Modal */
        .modal {{ display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.94); z-index: 1000; align-items: center; justify-content: center; flex-direction: column; padding: 20px; backdrop-filter: blur(8px); }}
        .modal-header {{ width: 100%; max-width: 1200px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .modal-title {{ font-size: 15px; color: #fff; display: flex; align-items: center; gap: 8px; }}
        .modal-close {{ background: none; border: 1px solid var(--border-color); color: #fff; font-size: 18px; cursor: pointer; border-radius: 50%; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; }}
        .modal-img-container {{ max-width: 1200px; max-height: 82vh; overflow: auto; border-radius: var(--radius-md); border: 1px solid var(--border-color); }}
        .modal-img {{ display: block; max-width: 100%; height: auto; }}

        @media (max-width: 768px) {{
            .header {{ padding: 16px; }}
            .container {{ padding: 0 16px; margin: 16px auto; }}
            .gallery-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>

    <header class="header">
        <div class="header-content">
            <div>
                <div class="brand-title">⚡ ReconShot Intelligence 2.0</div>
                <div class="brand-subtitle">Automated Web Application Screenshot & Attack Surface Reconnaissance</div>
            </div>
            <div class="brand-author">
                Author: <strong>Mr Dinesh Pathro</strong> &bull;
                <a href="https://buymeacoffee.com/mrdineshpathro" target="_blank" rel="noopener noreferrer">Support on BuyMeACoffee</a>
            </div>
        </div>
    </header>

    <main class="container">
        <!-- Stats KPI Grid -->
        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Targets</div>
                <div class="stat-value">{summary.total_targets}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Successful</div>
                <div class="stat-value stat-green">{summary.successful}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Failed / Offline</div>
                <div class="stat-value stat-red">{summary.failed}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Visual Clusters</div>
                <div class="stat-value stat-purple">{summary.clusters_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">2xx Success</div>
                <div class="stat-value stat-green">{c_2xx}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">3xx Redirects</div>
                <div class="stat-value stat-blue">{c_3xx}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">4xx Client Errors</div>
                <div class="stat-value stat-yellow">{c_4xx}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">5xx Server Errors</div>
                <div class="stat-value stat-red">{c_5xx}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Response</div>
                <div class="stat-value stat-cyan">{avg_time} ms</div>
            </div>
        </section>

        <!-- Controls Toolbar -->
        <section class="controls-panel">
            <div class="search-box">
                <span class="search-icon">🔍</span>
                <input type="text" id="searchInput" class="search-input" placeholder="Search target URL, technologies, IP, title, or cluster..." oninput="filterResults()">
            </div>
            <div class="filter-pills">
                <button class="filter-btn active" onclick="setFilter('all', this)">All ({summary.total_targets})</button>
                <button class="filter-btn" onclick="setFilter('2xx', this)">2xx ({c_2xx})</button>
                <button class="filter-btn" onclick="setFilter('3xx', this)">3xx ({c_3xx})</button>
                <button class="filter-btn" onclick="setFilter('4xx', this)">4xx ({c_4xx})</button>
                <button class="filter-btn" onclick="setFilter('5xx', this)">5xx ({c_5xx})</button>
                <button class="filter-btn" onclick="setFilter('failed', this)">Failed ({c_failed})</button>
            </div>
            <div class="action-btns">
                <button class="action-btn" id="viewToggleBtn" onclick="toggleView()">📋 List View</button>
                <button class="action-btn" onclick="exportJSON()">💾 Export JSON</button>
                <button class="action-btn" onclick="copyLiveURLs()">📋 Copy Live URLs</button>
            </div>
        </section>

        <!-- Cards Gallery View -->
        <section class="gallery-grid" id="galleryView">
            {all_cards_str}
        </section>

        <!-- Table View -->
        <section class="table-view-container" id="tableView">
            <table class="recon-table">
                <thead>
                    <tr>
                        <th>Preview</th>
                        <th>Target URL</th>
                        <th>Status</th>
                        <th>Grade</th>
                        <th>Page Title</th>
                        <th>Technologies</th>
                        <th>Response</th>
                    </tr>
                </thead>
                <tbody id="tableBody">
                    {all_table_rows_str}
                </tbody>
            </table>
        </section>
    </main>

    <!-- Fullscreen Lightbox Modal -->
    <div id="lightboxModal" class="modal" onclick="closeLightbox(event)">
        <div class="modal-header">
            <div class="modal-title" id="modalTitle"></div>
            <button class="modal-close" onclick="closeLightbox()">&times;</button>
        </div>
        <div class="modal-img-container">
            <img id="modalImg" class="modal-img" src="" alt="Fullscreen Screenshot">
        </div>
    </div>

    <script>
        const rawResults = {results_json};
        let currentFilter = 'all';
        let currentView = 'grid';

        function setFilter(category, btnElement) {{
            currentFilter = category;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            if (btnElement) btnElement.classList.add('active');
            filterResults();
        }}

        function filterByCluster(clusterId) {{
            document.getElementById('searchInput').value = clusterId;
            filterResults();
        }}

        function filterResults() {{
            const searchVal = document.getElementById('searchInput').value.toLowerCase().trim();
            const cards = document.querySelectorAll('.recon-card');
            const rows = document.querySelectorAll('#tableBody tr');

            cards.forEach(card => {{
                const cat = card.getAttribute('data-category');
                const searchData = card.getAttribute('data-search') || '';
                const matchCategory = (currentFilter === 'all') || (cat === currentFilter);
                const matchSearch = !searchVal || searchData.includes(searchVal);

                if (matchCategory && matchSearch) {{
                    card.style.display = 'flex';
                }} else {{
                    card.style.display = 'none';
                }}
            }});

            rows.forEach(row => {{
                const cat = row.getAttribute('data-category');
                const searchData = row.getAttribute('data-search') || '';
                const matchCategory = (currentFilter === 'all') || (cat === currentFilter);
                const matchSearch = !searchVal || searchData.includes(searchVal);

                if (matchCategory && matchSearch) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function toggleView() {{
            const gallery = document.getElementById('galleryView');
            const table = document.getElementById('tableView');
            const btn = document.getElementById('viewToggleBtn');

            if (currentView === 'grid') {{
                gallery.style.display = 'none';
                table.style.display = 'block';
                btn.textContent = '🖼️ Gallery View';
                currentView = 'table';
            }} else {{
                gallery.style.display = 'grid';
                table.style.display = 'none';
                btn.textContent = '📋 List View';
                currentView = 'grid';
            }}
        }}

        function openLightbox(src, url, status, grade) {{
            const modal = document.getElementById('lightboxModal');
            const modalImg = document.getElementById('modalImg');
            const modalTitle = document.getElementById('modalTitle');

            modalImg.src = src;
            modalTitle.innerHTML = `<span class="badge status-2xx">${{status}}</span> <span class="grade-badge grade-good">Grade ${{grade}}</span> <strong>${{url}}</strong>`;
            modal.style.display = 'flex';
        }}

        function closeLightbox(event) {{
            if (!event || event.target.id === 'lightboxModal' || event.target.classList.contains('modal-close')) {{
                document.getElementById('lightboxModal').style.display = 'none';
            }}
        }}

        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') {{
                closeLightbox();
            }}
        }});

        function exportJSON() {{
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(rawResults, null, 2));
            const dlAnchorElem = document.createElement('a');
            dlAnchorElem.setAttribute("href", dataStr);
            dlAnchorElem.setAttribute("download", "reconshot_intelligence.json");
            dlAnchorElem.click();
        }}

        function copyLiveURLs() {{
            const live = rawResults
                .filter(r => r.success && r.status_code)
                .map(r => r.final_url || r.url)
                .join('\\n');
            navigator.clipboard.writeText(live).then(() => {{
                alert('Live target URLs copied to clipboard!');
            }}).catch(() => {{
                alert('Could not copy to clipboard.');
            }});
        }}
    </script>
</body>
</html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.debug(f"Generated HTML report 2.0 at {report_path}")
    return report_path
