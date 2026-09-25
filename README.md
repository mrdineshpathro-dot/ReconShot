# ReconShot ⚡

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
██████╔╝█████╗  ██║     ██████╔╝██╔██╗ ██║███████╗███████║██║   ██║   ██║   
██╔══██╗██╔══╝  ██║     ██╔══██╗██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║   
██║  ██║███████╗╚██████╗██║  ██║██║ ╚████║███████║██║  ██║╚██████╔╝   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   
```

> **Automated Web Application Screenshot & Attack Surface Reconnaissance**  
> *A high-speed, intelligence-packed, visual reconnaissance and attack-surface discovery powerhouse built for authorized cybersecurity assessments, bug bounty hunters, and red teams.*

---

## 👨‍💻 Author & Support

* **Author:** **Mr Dinesh Pathro**
* **Project:** **ReconShot** (`v1.0.0`)
* **Support:** [buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)
* **Platform:** Kali Linux / Debian / Ubuntu / Linux (Python 3.10+)

---

## 📖 Overview

During authorized security testing, penetration testing, and bug bounty hunting, discovering thousands of active web assets is standard. Manually browsing each host is slow, repetitive, and misses critical low-hanging fruit.

**ReconShot** combines high-fidelity browser automation with deep intelligence extraction:
1. **Asynchronous Visual Capture:** Multi-worker Playwright Chromium engine capturing Desktop, Laptop, Tablet, Mobile, and Full-Page screenshots.
2. **Technology Stack Fingerprinting:** Identifies 100+ web servers, CMSs, frontend/backend frameworks, CDNs, WAFs, and analytics platforms.
3. **Security Posture & Header Auditing:** Evaluates missing security headers (HSTS, CSP, XFO, etc.), detects information disclosure, and assigns letter grades (**A+ to F**).
4. **DOM & Attack Surface Discovery:** Extracts HTML forms, login portals, password fields, file upload forms, API endpoints (`/api/v1/`, `/graphql`), developer comments, and leaked tokens.
5. **DNS & Subdomain Takeover Detection:** Resolves IP addresses and checks CNAME records against known takeover fingerprints (S3, GitHub Pages, Heroku, Azure, Zendesk).
6. **Perceptual Visual Clustering (dHash):** Automatically groups identical or near-identical web applications across thousands of subdomains.
7. **Interactive Dark-Themed Report 2.0:** Standalone, air-gapped HTML gallery with real-time tech stack filtering, lightbox modal, and multi-format exports (CSV, Markdown, SQLite, JSON).

---

## 🚀 Advanced Capabilities Matrix

### 🔍 1. Intelligence & Fingerprinting
* **100+ Technology Detectors:** Nginx, Apache, IIS, LiteSpeed, Caddy, Cloudflare, WordPress, Drupal, Ghost, Shopify, React, Next.js, Vue.js, Nuxt, Angular, Svelte, Tailwind CSS, Bootstrap, PHP, ASP.NET, Express, Django, Laravel, Rails, Spring Boot, Jenkins, GitLab, Grafana, Kibana, etc.
* **Favicon Hash Generator:** Computes standard MD5, SHA256, and **Murmur3 Shodan/Censys Favicon Hashes** for pivot searching.
* **Security Header Grading:** Computes a 0–100 score and letter grade (**A+ to F**) with itemized missing header alerts.
* **Information Disclosure Checks:** Flags leaked software versions in `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, and `X-Runtime`.
* **CORS Misconfiguration Auditor:** Identifies dangerous `Access-Control-Allow-Origin: *` with credentials enabled.

### 🌐 2. Attack Surface & DOM Extraction
* **Form & Input Extractor:** Detects total forms, login interfaces (`🔑 Login Form`), password fields, and file upload endpoints.
* **API Endpoint Harvester:** Scrapes REST and GraphQL endpoints (`/api/v1/`, `/graphql`, `/oauth/`, `.json`) from HTML and inline scripts.
* **Secret & Token Leakage Scanner:** Regex patterns for AWS Access Keys (`AKIA...`), Google API Keys (`AIza...`), GitHub PATs, Slack Tokens, JWTs, and Private Keys.
* **Developer Comments Extractor:** Harvests HTML comments (`<!-- ... -->`) for developer notes, internal IPs, and TODOs.
* **DNS IP & Takeover Fingerprinting:** Detects dangling CNAMEs pointing to unclaimed AWS S3, GitHub Pages, Heroku, Azure, Zendesk, Ghost, and Shopify stores.

### 🖼️ 3. Visual Intelligence & Clustering
* **Perceptual Difference Hashing (dHash):** Computes visual gradient fingerprints from screenshot data.
* **Automated Page Clustering:** Groups identical default pages (e.g. 100 default Nginx 404s or identical SSO portals) into cluster IDs (`cluster-001`).
* **Visual Scan Diffing:** Compares current scan against previous results (`--diff-against`) to highlight newly modified web applications.
* **Element-Specific Capture:** Snap only a target element with CSS selectors (`--selector "#login-form"`).
* **Auto Cookie/Consent Dismissal:** Automatically clicks GDPR/cookie consent popups prior to capturing.

### ⚡ 4. Speed & Stealth Engine
* **Media Request Interception:** `--block-media` aborts video, audio, and webfont downloads to boost scan speed by **300%–500%**.
* **User-Agent Pool Rotation:** `--random-agent` cycles through modern Chrome, Firefox, Safari, and Edge User-Agents.
* **Smart Prioritization:** Automatically scans high-value assets (`admin.*`, `vpn.*`, `dev.*`, `staging.*`, `api.*`) first.
* **Common Port Expander:** `--expand-ports 80,443,8080,8443,8888` expands hostnames into full HTTP/HTTPS URL matrices.

### 📊 5. Reporting & Multi-Format Exports
* **Interactive HTML Report 2.0:** Standalone dark-themed gallery with instant search, tech stack filtering, and lightbox modal.
* **Structured CSV Spreadsheet:** `results.csv` with full tech stacks, grades, and IP mappings.
* **Executive Markdown Report:** `summary.md` ready for penetration testing reports and client deliverables.
* **Relational SQLite Database:** `reconshot.db` for SQL querying across large asset sets.
* **Discord & Slack Webhooks:** Posts completion summaries and stats directly to your team channel.

---

## 🚀 Installation Guide (Kali Linux & Debian)

ReconShot complies with **PEP 668** (Debian/Kali externally managed environments) using a virtual environment:

```bash
# 1. Clone the repository
git clone https://github.com/mrdineshpathro-dot/ReconShot.git
cd ReconShot

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install requirements
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install Playwright Chromium
playwright install chromium

# (Optional: install Linux system dependencies if on minimal OS)
playwright install --with-deps chromium
```

---

## ⚡ CLI Options Reference

```text
usage: reconshot [-u URL] [-l FILE] [--expand-ports PORTS] [-w INT]
                 [--timeout INT] [--delay FLOAT] [--retries INT]
                 [--block-media] [--random-agent] [--width INT] [--height INT]
                 [--full-page] [--mobile] [--desktop] [--laptop] [--tablet]
                 [--selector CSS] [--inject-js CODE] [--user-agent TEXT]
                 [--no-tech] [--no-security] [--no-dom] [--no-dns]
                 [--no-clustering] [--proxy URL] [--basic-auth USER:PASS]
                 [--cookies FILE] [--headers FILE] [--status CODES] [--resume]
                 [-o DIR] [--report] [--no-report] [--sqlite] [--webhook URL]
                 [-c FILE] [-v] [-q] [-V] [-h]
```

### Option Groups

| Group | Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| **Target Input** | `-u`, `--url` | Single target URL | `None` |
| | `-l`, `--list` | URL list file | `None` |
| | `--expand-ports` | Expand hosts to ports (e.g. `80,443,8080,8443`) | `None` |
| **Performance** | `-w`, `--workers` | Number of concurrent screenshot workers | `5` |
| | `--timeout` | Page navigation timeout (seconds) | `30` |
| | `--delay` | Delay before screenshot for JS rendering | `0.0` |
| | `--retries` | Retry attempts on temporary failure | `0` |
| | `--block-media` | Block videos, fonts, and audio (3-5x speedup) | `False` |
| | `--random-agent`| Rotate User-Agent across modern browsers | `False` |
| **Viewports** | `--desktop` | Desktop viewport (1920×1080) | `True` |
| | `--laptop` | Laptop viewport (1366×768) | `False` |
| | `--tablet` | Tablet viewport (820×1180) | `False` |
| | `--mobile` | Mobile viewport (390×844 with touch enabled) | `False` |
| | `--full-page` | Capture full scrollable page | `False` |
| | `--selector` | Capture specific CSS element selector | `None` |
| | `--inject-js` | Inject custom JavaScript before capture | `None` |
| **Intelligence** | `--no-tech` | Disable technology detection | `Enabled` |
| | `--no-security` | Disable security header audit | `Enabled` |
| | `--no-dom` | Disable DOM form/endpoint/secret extraction | `Enabled` |
| | `--no-dns` | Disable DNS IP resolution & takeover checks | `Enabled` |
| | `--no-clustering` | Disable visual perceptual hashing | `Enabled` |
| **Auth & Network** | `--proxy` | HTTP/HTTPS/SOCKS proxy | `None` |
| | `--basic-auth` | HTTP Basic Auth (`user:pass`) | `None` |
| | `--cookies` | JSON cookies file | `None` |
| | `--headers` | JSON custom headers file | `None` |
| **Scan Control** | `--status` | Status code filter (e.g. `200` or `2xx,3xx`) | `All` |
| | `--resume` | Resume interrupted scan | `False` |
| **Export & Webhooks** | `-o`, `--output` | Base output directory | `./results` |
| | `--sqlite` | Export structured SQLite database | `False` |
| | `--webhook` | Discord / Slack webhook endpoint | `None` |

---

## 💡 Practical Recon Workflows

### 1. High-Speed Subdomain Visual Discovery Pipeline

```bash
subfinder -d target.com -silent | httpx -silent | python3 reconshot.py --workers 10 --block-media --report
```

### 2. Full Attack-Surface Audit with Port Expansion & SQLite Export

```bash
python3 reconshot.py -l hosts.txt --expand-ports 80,443,8080,8443 --workers 8 --sqlite --report
```

### 3. Authenticated Internal Security Assessment

```bash
python3 reconshot.py -l internal_apps.txt --cookies cookies.json --headers headers.json --full-page --delay 1.5
```

### 4. Continuous Bug Bounty Monitoring with Discord Webhooks

```bash
python3 reconshot.py -l in_scope_urls.txt --webhook https://discord.com/api/webhooks/YOUR_WEBHOOK_URL
```

---

## 📁 Output Directory Layout

```text
results/
├── screenshots/
│   ├── https_example_com.png
│   ├── https_admin_example_com.png
│   └── https_api_example_com.png
│
├── metadata/
│   ├── summary.json
│   ├── https_example_com.json
│   └── https_admin_example_com.json
│
├── reports/
│   └── report.html
│
├── logs/
│   ├── reconshot.log
│   ├── success.txt
│   └── failed.txt
│
├── results.csv
├── summary.md
├── reconshot.db
└── .reconshot_state.json
```

---

## 🧪 Testing

Run the comprehensive automated test suite (69 tests):

```bash
pytest -v
```

---

## 🛡️ Legal & Ethical Disclaimer

**ReconShot is engineered exclusively for authorized security audits, penetration testing, authorized bug bounty programs, and internal infrastructure reviews.**

* Users are responsible for ensuring explicit written authorization before interacting with any target.
* Do not scan out-of-scope assets.
* The author (**Mr Dinesh Pathro**) assumes no liability for unauthorized usage or damage.

---

## 📄 License

MIT License — Copyright (c) 2026 **Mr Dinesh Pathro**. See [LICENSE](LICENSE) for details.

---

## ☕ Support the Author

If ReconShot powers your security operations, support ongoing development:

👉 **Buy Me a Coffee:** [https://buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)
