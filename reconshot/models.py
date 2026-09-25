"""
Data models for ReconShot.
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

    def matches_status(self, code: Optional[int]) -> bool:
        """Check if an HTTP status code satisfies the configured status filter."""
        if not self.status_filter:
            return True
        if code is None:
            return False
        return code in self.status_filter


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
        }
        if self.headers_received:
            data["headers_received"] = self.headers_received
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetResult":
        """Reconstruct TargetResult from dictionary."""
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
        )


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
            "options": self.options,
            "results": [r.to_dict() for r in self.results],
        }
