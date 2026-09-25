"""
DNS Resolution, IP Mapping, and Subdomain Takeover Fingerprinting for ReconShot.
"""

from __future__ import annotations

import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

from reconshot.models import DNSInfo

# Known takeover target CNAME patterns
TAKEOVER_PATTERNS: Dict[str, str] = {
    "github.io": "GitHub Pages (Check for unclaimed repository/CNAME)",
    "s3.amazonaws.com": "AWS S3 Bucket (Check for unclaimed S3 bucket)",
    "herokuapp.com": "Heroku App (Check for unclaimed Heroku app)",
    "azurewebsites.net": "Azure Web App (Check for deleted Azure service)",
    "cloudapp.net": "Azure CloudApp (Check for unclaimed Azure VM)",
    "zendesk.com": "Zendesk Help Center (Check for unclaimed Zendesk subdomain)",
    "ghost.io": "Ghost.io Blog (Check for unclaimed Ghost instance)",
    "myshopify.com": "Shopify Store (Check for deleted Shopify store)",
    "surge.sh": "Surge.sh (Check for unclaimed Surge project)",
    "wpengine.com": "WPEngine (Check for unclaimed WP instance)",
    "readme.io": "Readme.io (Check for unclaimed documentation project)",
}


def resolve_target_dns(url_or_domain: str) -> DNSInfo:
    """
    Resolve IP addresses and evaluate subdomain takeover vulnerability risks.
    """
    domain = url_or_domain
    if "://" in url_or_domain:
        parsed = urlparse(url_or_domain)
        domain = parsed.hostname or url_or_domain

    ip_addresses: List[str] = []
    cnames: List[str] = []
    takeover_indicator: Optional[str] = None

    try:
        # Resolve A and AAAA addresses
        addr_info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            ip = entry[4][0]
            if ip not in ip_addresses:
                ip_addresses.append(ip)
    except Exception:
        pass

    try:
        # Check canonical name
        host, aliases, _ = socket.gethostbyname_ex(domain)
        for alias in aliases:
            if alias not in cnames and alias != domain:
                cnames.append(alias)
    except Exception:
        pass

    # Check for CNAME takeover risks
    all_names = [domain] + cnames
    for name in all_names:
        for cname_pat, desc in TAKEOVER_PATTERNS.items():
            if cname_pat in name.lower():
                takeover_indicator = f"Potentially vulnerable to Subdomain Takeover ({desc})"
                break
        if takeover_indicator:
            break

    return DNSInfo(
        ip_addresses=ip_addresses,
        cname_records=cnames,
        takeover_indicator=takeover_indicator,
    )
