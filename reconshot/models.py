"""
Data models and type definitions for ReconShot.
Includes comprehensive models for tech detection, security analysis,
DOM extraction, DNS reconnaissance, visual hashing, and multi-format exports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class ViewportConfig:
    """Browser viewport configuration."""

    width: int = 1920
    height: int = 1080
    is_mobile: bool = False
    device_scale_factor: float = 1.0
    has_touch: bool = False
    is_landscape: bool = True
    name: str = "desktop"

    @classmethod
    def desktop(cls, width: int = 1920, height: int = 1080) -> "ViewportConfig":
        return cls(
            width=width,
            height=height,
            is_mobile=False,
            device_scale_factor=1.0,
            has_touch=False,
            is_landscape=True,
            name="desktop",
        )

    @classmethod
    def laptop(cls, width: int = 1366, height: int = 768) -> "ViewportConfig":
        return cls(
            width=width,
            height=height,
            is_mobile=False,
            device_scale_factor=1.0,
            has_touch=False,
            is_landscape=True,
            name="laptop",
        )

    @classmethod
    def mobile(cls, width: int = 390, height: int = 844) -> "ViewportConfig":
        return cls(
            width=width,
            height=height,
            is_mobile=True,
            device_scale_factor=3.0,
            has_touch=True,
            is_landscape=False,
            name="mobile",
        )

    @classmethod
    def tablet(cls, width: int = 820, height: int = 1180) -> "ViewportConfig":
        return cls(
            width=width,
            height=height,
            is_mobile=True,
            device_scale_factor=2.0,
            has_touch=True,
            is_landscape=False,
            name="tablet",
        )

    @classmethod
    def custom(cls, width: int, height: int) -> "ViewportConfig":
        return cls(
            width=width,
            height=height,
            is_mobile=False,
            device_scale_factor=1.0,
            has_touch=False,
            is_landscape=(width >= height),
            name="custom",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "is_mobile": self.is_mobile,
            "device_scale_factor": self.device_scale_factor,
            "has_touch": self.has_touch,
            "is_landscape": self.is_landscape,
            "name": self.name,
        }


@dataclass
class TechItem:
    """Detected technology entry."""

    name: str
    category: str  # Server, CMS, Frontend, Backend, CDN, Analytics, Security
    version: Optional[str] = None
    confidence: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
        }


@dataclass
class SecurityAudit:
    """HTTP security headers, grading, and information disclosure analysis."""

    grade: str = "F"  # A+, A, B, C, D, F
    score: int = 0    # 0 - 100
    missing_headers: List[str] = field(default_factory=list)
    present_headers: List[str] = field(default_factory=list)
    info_leaks: List[str] = field(default_factory=list)
    cors_issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade,
            "score": self.score,
            "missing_headers": self.missing_headers,
            "present_headers": self.present_headers,
            "info_leaks": self.info_leaks,
            "cors_issues": self.cors_issues,
        }


@dataclass
class DOMFindings:
    """Extracted DOM elements, forms, endpoints, and potential secrets."""

    forms_count: int = 0
    has_login_form: bool = False
    has_password_field: bool = False
    has_file_upload: bool = False
    input_types: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    potential_secrets: List[Dict[str, str]] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "forms_count": self.forms_count,
            "has_login_form": self.has_login_form,
            "has_password_field": self.has_password_field,
            "has_file_upload": self.has_file_upload,
            "input_types": self.input_types,
            "endpoints": self.endpoints[:50],
            "potential_secrets": self.potential_secrets[:20],
            "comments": self.comments[:20],
            "external_links": self.external_links[:50],
        }


@dataclass
class DNSInfo:
    """DNS resolution, IP address mapping, and CNAME takeover indicators."""

    ip_addresses: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    takeover_indicator: Optional[str] = None
    asn: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_addresses": self.ip_addresses,
            "cname_records": self.cname_records,
            "takeover_indicator": self.takeover_indicator,
            "asn": self.asn,
        }


@dataclass
class TargetResult:
    """Result metadata for a single scanned target."""

    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    page_title: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat()
    )
    viewport: Dict[str, int] = field(
        default_factory=lambda: {"width": 1920, "height": 1080}
    )
    full_page: bool = False
    screenshot: Optional[str] = None
    screenshot_path: Optional[str] = None
    response_time_ms: Optional[float] = None
    content_type: Optional[str] = None
    redirect_count: int = 0
    browser_profile: str = "desktop"
    success: bool = False
    error: Optional[str] = None
    retries_used: int = 0
    headers_received: Optional[Dict[str, str]] = None

    # Advanced Analysis Fields
    technologies: List[TechItem] = field(default_factory=list)
    security: Optional[SecurityAudit] = None
    dom: Optional[DOMFindings] = None
    dns: Optional[DNSInfo] = None
    favicon_hash: Optional[str] = None
    dhash: Optional[str] = None  # Perceptual difference hash
    cluster_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to clean dictionary for JSON metadata."""
        data: Dict[str, Any] = {
            "url": self.url,
            "final_url": self.final_url or self.url,
            "status_code": self.status_code,
            "page_title": self.page_title or "",
            "timestamp": self.timestamp,
            "viewport": self.viewport,
            "full_page": self.full_page,
            "screenshot": self.screenshot,
            "screenshot_path": self.screenshot_path,
            "response_time_ms": round(self.response_time_ms, 2)
            if self.response_time_ms is not None
            else None,
            "content_type": self.content_type,
            "redirect_count": self.redirect_count,
            "browser_profile": self.browser_profile,
            "success": self.success,
            "error": self.error,
            "retries_used": self.retries_used,
            "favicon_hash": self.favicon_hash,
            "dhash": self.dhash,
            "cluster_id": self.cluster_id,
        }
        if self.headers_received:
            data["headers_received"] = self.headers_received
        if self.technologies:
            data["technologies"] = [t.to_dict() for t in self.technologies]
        if self.security:
            data["security"] = self.security.to_dict()
        if self.dom:
            data["dom"] = self.dom.to_dict()
        if self.dns:
            data["dns"] = self.dns.to_dict()

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetResult":
        """Reconstruct TargetResult from dictionary."""
        techs = [
            TechItem(
                name=t.get("name", ""),
                category=t.get("category", "Other"),
                version=t.get("version"),
                confidence=t.get("confidence", 100),
            )
            for t in data.get("technologies", [])
            if isinstance(t, dict)
        ]

        sec = None
        if "security" in data and isinstance(data["security"], dict):
            s = data["security"]
            sec = SecurityAudit(
                grade=s.get("grade", "F"),
                score=s.get("score", 0),
                missing_headers=s.get("missing_headers", []),
                present_headers=s.get("present_headers", []),
                info_leaks=s.get("info_leaks", []),
                cors_issues=s.get("cors_issues", []),
            )

        dom = None
        if "dom" in data and isinstance(data["dom"], dict):
            d = data["dom"]
            dom = DOMFindings(
                forms_count=d.get("forms_count", 0),
                has_login_form=d.get("has_login_form", False),
                has_password_field=d.get("has_password_field", False),
                has_file_upload=d.get("has_file_upload", False),
                input_types=d.get("input_types", []),
                endpoints=d.get("endpoints", []),
                potential_secrets=d.get("potential_secrets", []),
                comments=d.get("comments", []),
                external_links=d.get("external_links", []),
            )

        dns_obj = None
        if "dns" in data and isinstance(data["dns"], dict):
            dn = data["dns"]
            dns_obj = DNSInfo(
                ip_addresses=dn.get("ip_addresses", []),
                cname_records=dn.get("cname_records", []),
                takeover_indicator=dn.get("takeover_indicator"),
                asn=dn.get("asn"),
            )

        return cls(
            url=data.get("url", ""),
            final_url=data.get("final_url"),
            status_code=data.get("status_code"),
            page_title=data.get("page_title"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            viewport=data.get("viewport", {"width": 1920, "height": 1080}),
            full_page=data.get("full_page", False),
            screenshot=data.get("screenshot"),
            screenshot_path=data.get("screenshot_path"),
            response_time_ms=data.get("response_time_ms"),
            content_type=data.get("content_type"),
            redirect_count=data.get("redirect_count", 0),
            browser_profile=data.get("browser_profile", "desktop"),
            success=data.get("success", False),
            error=data.get("error"),
            retries_used=data.get("retries_used", 0),
            headers_received=data.get("headers_received"),
            technologies=techs,
            security=sec,
            dom=dom,
            dns=dns_obj,
            favicon_hash=data.get("favicon_hash"),
            dhash=data.get("dhash"),
            cluster_id=data.get("cluster_id"),
        )


@dataclass
class ScanOptions:
    """Runtime options for ReconShot scan execution."""

    urls: List[str] = field(default_factory=list)
    output_dir: Path = field(default_factory=lambda: Path("./results"))
    workers: int = 5
    viewport: ViewportConfig = field(default_factory=ViewportConfig.desktop)
    full_page: bool = False
    timeout: int = 30
    delay: float = 0.0
    retries: int = 0
    proxy: Optional[str] = None
    cookies_file: Optional[Path] = None
    cookies: Optional[List[Dict[str, Any]]] = None
    headers_file: Optional[Path] = None
    headers: Optional[Dict[str, str]] = None
    status_filter: Optional[Set[int]] = None
    status_raw: Optional[str] = None
    resume: bool = False
    generate_report: bool = True
    verbose: bool = False
    quiet: bool = False
    user_agent: Optional[str] = None
    ignore_https_errors: bool = True
    config_file: Optional[Path] = None

    # Advanced Capabilities & Options
    detect_tech: bool = True
    analyze_security: bool = True
    analyze_dom: bool = True
    resolve_dns: bool = True
    visual_clustering: bool = True
    block_media: bool = False          # Intercept & block heavy media for 3-5x scan acceleration
    auto_dismiss_popups: bool = True   # Automatically click cookie/consent buttons
    random_user_agent: bool = False    # Rotate user-agents automatically
    selector: Optional[str] = None     # Element-specific screenshot selector
    inject_js: Optional[str] = None    # Custom JS code injected before screenshot
    basic_auth: Optional[str] = None   # "user:pass" for HTTP basic auth
    export_csv: bool = True
    export_markdown: bool = True
    export_sqlite: bool = False
    webhook_url: Optional[str] = None  # Discord/Slack/Telegram webhook notification
    diff_against: Optional[Path] = None # Compare against previous scan results

    def matches_status(self, code: Optional[int]) -> bool:
        """Check if an HTTP status code satisfies the configured status filter."""
        if not self.status_filter:
            return True
        if code is None:
            return False
        return code in self.status_filter


@dataclass
class ScanSummary:
    """Summary of complete scan execution."""

    scan_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    total_targets: int
    successful: int
    failed: int
    skipped: int
    results: List[TargetResult] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    clusters_count: int = 0
    top_technologies: List[Dict[str, Any]] = field(default_factory=list)
    security_grades: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tool": "ReconShot",
            "version": "1.0.0",
            "author": "Mr Dinesh Pathro",
            "support": "https://buymeacoffee.com/mrdineshpathro",
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_targets": self.total_targets,
            "successful": self.successful,
            "failed": self.failed,
            "skipped": self.skipped,
            "clusters_count": self.clusters_count,
            "top_technologies": self.top_technologies,
            "security_grades": self.security_grades,
            "options": self.options,
            "results": [r.to_dict() for r in self.results],
        }
