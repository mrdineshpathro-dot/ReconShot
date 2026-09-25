"""
Configuration file loader, validator, and merger for ReconShot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from reconshot.logger import logger
from reconshot.models import ScanOptions, ViewportConfig

DEFAULT_CONFIG: Dict[str, Any] = {
    "workers": 5,
    "timeout": 30,
    "delay": 0.0,
    "retries": 0,
    "browser": {
        "width": 1920,
        "height": 1080,
        "full_page": False,
        "mobile": False,
        "desktop": True,
        "user_agent": None,
    },
    "output": {
        "directory": "./results",
    },
    "report": {
        "enabled": True,
    },
    "network": {
        "proxy": None,
        "ignore_https_errors": True,
    },
    "auth": {
        "cookies_file": None,
        "headers_file": None,
    },
    "filter": {
        "status": None,
    },
}


def load_config_file(config_path: Path) -> Dict[str, Any]:
    """
    Load and parse a YAML configuration file safely.
    Returns empty dict on missing or invalid file.
    """
    if not config_path.exists():
        logger.warning(f"Configuration file not found: {config_path}")
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
            logger.warning(f"Config file {config_path} did not contain a valid dictionary.")
            return {}
    except Exception as e:
        logger.warning(f"Error reading configuration file {config_path}: {e}")
        return {}


def create_default_config_yaml() -> str:
    """Generate example configuration file contents."""
    return """# ==============================================================================
# ReconShot — Automated Web Application Screenshot Reconnaissance
# Configuration File
# Author  : Mr Dinesh Pathro
# Support : https://buymeacoffee.com/mrdineshpathro
# ==============================================================================

# Concurrency & Performance
workers: 5               # Number of concurrent screenshot workers (default: 5)
timeout: 30              # Page navigation and loading timeout in seconds (default: 30)
delay: 0.0               # Wait time (seconds) after page load before taking screenshot (e.g. 1.5)
retries: 0               # Number of retry attempts on temporary errors (default: 0)

# Browser & Viewport Settings
browser:
  width: 1920            # Viewport width in pixels (default: 1920)
  height: 1080           # Viewport height in pixels (default: 1080)
  full_page: false       # Capture the complete scrollable page (true/false)
  mobile: false          # Emulate mobile device viewport (390x844 with touch)
  desktop: true          # Use standard desktop viewport (1920x1080)
  user_agent: null       # Custom User-Agent string (optional)

# Output Directory
output:
  directory: "./results" # Base directory for screenshots, metadata, reports, and logs

# Report Generation
report:
  enabled: true          # Automatically generate dark-themed HTML report (true/false)

# Network & Proxy
network:
  proxy: null            # HTTP / SOCKS proxy (e.g. "http://127.0.0.1:8080" or "socks5://127.0.0.1:9050")
  ignore_https_errors: true # Ignore invalid/self-signed SSL certificates (default: true)

# Authenticated Reconnaissance (Authorized scope only)
auth:
  cookies_file: null     # Path to JSON cookies file (optional)
  headers_file: null     # Path to JSON custom headers file (optional)

# Status Code Filtering
filter:
  status: null           # Filter specific HTTP status codes (e.g. "200" or "200,301,302,403,500" or "2xx,3xx")
"""
