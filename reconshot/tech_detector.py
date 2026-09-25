"""
Technology Stack Fingerprinting Engine for ReconShot.
Detects 100+ web servers, CMSs, frontend/backend frameworks, CDNs, WAFs, and analytics.
Includes Favicon hashing for Shodan/Censys correlation.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from reconshot.models import TechItem

# Detection Signatures: (Name, Category, Header Rules, HTML Rules, Cookie Rules, Meta Rules)
TECH_RULES: List[Dict[str, Any]] = [
    # --- Web Servers ---
    {
        "name": "Nginx",
        "category": "Web Server",
        "headers": {"server": r"nginx(?:/([\d.]+))?"},
    },
    {
        "name": "Apache HTTP Server",
        "category": "Web Server",
        "headers": {"server": r"apache(?:/([\d.]+))?"},
    },
    {
        "name": "Microsoft IIS",
        "category": "Web Server",
        "headers": {"server": r"microsoft-iis(?:/([\d.]+))?"},
    },
    {
        "name": "LiteSpeed",
        "category": "Web Server",
        "headers": {"server": r"litespeed"},
    },
    {
        "name": "Caddy",
        "category": "Web Server",
        "headers": {"server": r"caddy"},
    },
    {
        "name": "OpenResty",
        "category": "Web Server",
        "headers": {"server": r"openresty(?:/([\d.]+))?"},
    },
    {
        "name": "Traefik",
        "category": "Web Server",
        "headers": {"server": r"traefik"},
    },
    {
        "name": "Apache Tomcat",
        "category": "Application Server",
        "headers": {"server": r"apache-coyote(?:/([\d.]+))?"},
        "html": [r"apache tomcat"],
    },
    {
        "name": "Kestrel",
        "category": "Application Server",
        "headers": {"server": r"kestrel"},
    },

    # --- Cloud & CDN ---
    {
        "name": "Cloudflare",
        "category": "CDN / Proxy",
        "headers": {"server": r"cloudflare", "cf-ray": r".+", "cf-cache-status": r".+"},
    },
    {
        "name": "AWS CloudFront",
        "category": "CDN",
        "headers": {"via": r"cloudfront", "x-amz-cf-id": r".+", "x-amz-cf-pop": r".+"},
    },
    {
        "name": "Fastly",
        "category": "CDN",
        "headers": {"x-served-by": r"cache-.*fastly", "fastly-debug-digest": r".+"},
    },
    {
        "name": "Akamai",
        "category": "CDN",
        "headers": {"server": r"akamaighost", "x-akamai-transformed": r".+"},
    },
    {
        "name": "Vercel",
        "category": "Hosting / CDN",
        "headers": {"server": r"vercel", "x-vercel-id": r".+"},
    },
    {
        "name": "Netlify",
        "category": "Hosting / CDN",
        "headers": {"server": r"netlify", "x-nf-request-id": r".+"},
    },

    # --- CMS & Platforms ---
    {
        "name": "WordPress",
        "category": "CMS",
        "html": [r"name=[\"']generator[\"'] content=[\"']WordPress ([\d.]+)[\"']", r"/wp-content/", r"/wp-includes/"],
        "headers": {"x-pingback": r"/xmlrpc\.php", "link": r"rel=[\"']https://api\.w\.org/\""},
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "headers": {"x-drupal-cache": r".+", "x-generator": r"Drupal ([\d.]+)"},
        "html": [r"Drupal\.settings", r"/sites/default/files/"],
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "html": [r"name=[\"']generator[\"'] content=[\"']Joomla![\"']", r"/media/jui/"],
    },
    {
        "name": "Shopify",
        "category": "E-Commerce",
        "headers": {"x-shopid": r".+", "server": r"cloudflare-shopify"},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    },
    {
        "name": "Ghost",
        "category": "CMS",
        "headers": {"x-ghost-cache-status": r".+"},
        "html": [r"name=[\"']generator[\"'] content=[\"']Ghost ([\d.]+)[\"']", r"ghost-portal"],
    },
    {
        "name": "Jenkins",
        "category": "DevOps / CI-CD",
        "headers": {"x-jenkins": r"([\d.]+)", "x-hudson": r".+"},
        "html": [r"jenkins-header", r"Jenkins\.instance"],
    },
    {
        "name": "GitLab",
        "category": "DevOps / CI-CD",
        "html": [r"gon\.gitlab_url", r"gl-header-logo"],
        "cookies": [r"_gitlab_session"],
    },
    {
        "name": "Grafana",
        "category": "Observability",
        "html": [r"window\.grafanaBootData", r"grafana-app"],
    },
    {
        "name": "Kibana",
        "category": "Observability",
        "headers": {"kbn-name": r".+", "kbn-version": r"([\d.]+)"},
    },

    # --- Frontend Frameworks ---
    {
        "name": "React",
        "category": "Frontend Framework",
        "html": [r"data-reactroot", r"data-reactid", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"_reactListening"],
    },
    {
        "name": "Next.js",
        "category": "Frontend Framework",
        "html": [r"/_next/static/", r"__NEXT_DATA__", r"id=[\"']__next[\"']"],
        "headers": {"x-powered-by": r"Next\.js(?: ([\d.]+))?"},
    },
    {
        "name": "Vue.js",
        "category": "Frontend Framework",
        "html": [r"data-v-[a-f0-9]{8}", r"__vue__", r"Vue\.config"],
    },
    {
        "name": "Nuxt.js",
        "category": "Frontend Framework",
        "html": [r"/_nuxt/", r"__NUXT__", r"id=[\"']__nuxt[\"']"],
    },
    {
        "name": "Angular",
        "category": "Frontend Framework",
        "html": [r"ng-version=[\"']([\d.]+)[\"']", r"ng-app", r"ng-controller"],
    },
    {
        "name": "Svelte",
        "category": "Frontend Framework",
        "html": [r"class=[\"']svelte-[a-z0-9]+[\"']", r"__svelte__"],
    },
    {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "html": [r"class=[\"'][^\"']*(?:flex|grid|gap-|text-|bg-|p-|m-)[^\"']*[\"']", r"tailwindcss"],
    },
    {
        "name": "Bootstrap",
        "category": "CSS Framework",
        "html": [r"bootstrap(?:\.min)?\.(?:css|js)", r"class=[\"'][^\"']*(?:btn-primary|container-fluid|col-md-)[^\"']*[\"']"],
    },
    {
        "name": "jQuery",
        "category": "JavaScript Library",
        "html": [r"jquery(?:-([\d.]+))?(?:\.min)?\.js", r"jQuery v([\d.]+)"],
    },
    {
        "name": "Alpine.js",
        "category": "JavaScript Library",
        "html": [r"x-data=", r"x-init=", r"alpinejs"],
    },

    # --- Backend Frameworks & Languages ---
    {
        "name": "PHP",
        "category": "Programming Language",
        "headers": {"x-powered-by": r"PHP(?:/([\d.]+))?"},
        "cookies": [r"PHPSESSID"],
    },
    {
        "name": "ASP.NET",
        "category": "Backend Framework",
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"([\d.]+)"},
        "cookies": [r"ASP\.NET_SessionId"],
    },
    {
        "name": "ASP.NET Core",
        "category": "Backend Framework",
        "headers": {"server": r"Kestrel", "x-powered-by": r"ASP\.NET Core"},
    },
    {
        "name": "Express",
        "category": "Backend Framework",
        "headers": {"x-powered-by": r"Express"},
    },
    {
        "name": "Django",
        "category": "Backend Framework",
        "cookies": [r"csrftoken", r"sessionid"],
        "html": [r"csrfmiddlewaretoken"],
    },
    {
        "name": "Laravel",
        "category": "Backend Framework",
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
        "headers": {"set-cookie": r"laravel_session"},
    },
    {
        "name": "Ruby on Rails",
        "category": "Backend Framework",
        "headers": {"x-powered-by": r"Phusion Passenger", "x-runtime": r"[\d.]+"},
        "cookies": [r"_session_id"],
    },
    {
        "name": "Spring Boot",
        "category": "Backend Framework",
        "cookies": [r"JSESSIONID"],
        "headers": {"x-application-context": r".+"},
    },

    # --- Security & WAF ---
    {
        "name": "Cloudflare WAF",
        "category": "Security / WAF",
        "headers": {"cf-chl-bypass": r".+", "cf-mitigated": r".+"},
        "html": [r"Attention Required! \| Cloudflare", r"cf-browser-verification"],
    },
    {
        "name": "AWS WAF",
        "category": "Security / WAF",
        "headers": {"x-amzn-waf-action": r".+", "x-amzn-errortype": r".+"},
    },
    {
        "name": "Imperva / Incapsula",
        "category": "Security / WAF",
        "headers": {"x-cdn": r"Incapsula", "x-iinfo": r".+"},
        "cookies": [r"visid_incap_", r"incap_ses_"],
    },
    {
        "name": "F5 BIG-IP",
        "category": "Security / WAF",
        "headers": {"server": r"BigIP"},
        "cookies": [r"BIGipServer", r"TS[0-9a-f]{6,}"],
    },

    # --- Analytics & Tracking ---
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "html": [r"www\.google-analytics\.com/analytics\.js", r"gtag\(['\"]config['\"],", r"ua-[0-9]+-[0-9]+"],
    },
    {
        "name": "Google Tag Manager",
        "category": "Tag Manager",
        "html": [r"googletagmanager\.com/gtm\.js", r"gtm-[a-z0-9]+"],
    },
    {
        "name": "Hotjar",
        "category": "Analytics",
        "html": [r"static\.hotjar\.com", r"_hjSettings"],
    },
    {
        "name": "Sentry",
        "category": "Monitoring",
        "html": [r"browser\.sentry-cdn\.com", r"Sentry\.init"],
    },
]


def detect_technologies(
    headers: Optional[Dict[str, str]] = None,
    html_content: Optional[str] = None,
    cookies: Optional[List[Dict[str, Any]]] = None,
) -> List[TechItem]:
    """
    Fingerprint technology stack from HTTP response headers, HTML DOM body, and cookies.
    """
    detected: Dict[str, TechItem] = {}
    headers_lower = {k.lower(): str(v) for k, v in (headers or {}).items()}
    html_body = html_content or ""
    cookie_names = [c.get("name", "") for c in (cookies or [])]
    cookie_str = "; ".join(cookie_names)

    for rule in TECH_RULES:
        name = rule["name"]
        category = rule["category"]
        version = None
        matched = False

        # 1. Header Checks
        if "headers" in rule:
            for hdr_key, hdr_pattern in rule["headers"].items():
                val = headers_lower.get(hdr_key.lower())
                if val:
                    m = re.search(hdr_pattern, val, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = m.group(1)
                            break

        # 2. HTML Pattern Checks
        if "html" in rule and html_body:
            for pattern in rule["html"]:
                m = re.search(pattern, html_body, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = m.group(1)
                        break

        # 3. Cookie Checks
        if not matched and "cookies" in rule:
            for c_pat in rule["cookies"]:
                if re.search(c_pat, cookie_str, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            detected[name] = TechItem(
                name=name,
                category=category,
                version=version,
                confidence=100,
            )

    return list(detected.values())


def calculate_favicon_hash(favicon_bytes: bytes) -> Dict[str, str]:
    """
    Calculate MD5, SHA256, and standard Shodan/Censys Favicon Base64 hash.
    Standard Shodan Favicon Hash is Murmur3 hash of the base64-encoded string with line breaks every 76 chars.
    """
    if not favicon_bytes:
        return {}

    b64_str = base64.encodebytes(favicon_bytes).decode("utf-8")
    md5_hash = hashlib.md5(favicon_bytes).hexdigest()
    sha256_hash = hashlib.sha256(favicon_bytes).hexdigest()

    def murmur3_shodan(data: bytes, seed: int = 0) -> int:
        length = len(data)
        nblocks = length // 4
        h1 = seed
        c1 = 0xCC9E2D51
        c2 = 0x1B873593

        for i in range(0, nblocks * 4, 4):
            k1 = (
                data[i]
                | (data[i + 1] << 8)
                | (data[i + 2] << 16)
                | (data[i + 3] << 24)
            )
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF

            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

        tail_index = nblocks * 4
        k1 = 0
        tail_len = length & 3
        if tail_len == 3:
            k1 ^= data[tail_index + 2] << 16
        if tail_len >= 2:
            k1 ^= data[tail_index + 1] << 8
        if tail_len >= 1:
            k1 ^= data[tail_index]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        h1 ^= length
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
        h1 ^= h1 >> 13
        h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
        h1 ^= h1 >> 16

        if h1 >= 0x80000000:
            h1 -= 0x100000000
        return h1

    shodan_hash = murmur3_shodan(b64_str.encode("utf-8"))

    return {
        "shodan_hash": str(shodan_hash),
        "md5": md5_hash,
        "sha256": sha256_hash,
    }
