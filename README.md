# ReconShot ⚡

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗ ██████╗ ████████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
██████╔╝█████╗  ██║     ██████╔╝██╔██╗ ██║███████╗███████║██║   ██║   ██║   
██╔══██╗██╔══╝  ██║     ██╔══██╗██║╚██╗██║╚════██║██╔══██║██║   ██║   ██║   
██║  ██║███████╗╚██████╗██║  ██║██║ ╚████║███████║██║  ██║╚██████╔╝   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   
```

> **Automated Web Application Screenshot Reconnaissance**  
> *A fast, modular, modern Python CLI reconnaissance utility designed for authorized security testing, bug bounty asset discovery, and internal security assessments.*

---

## 👨‍💻 Author & Support

* **Author:** **Mr Dinesh Pathro**
* **Project:** **ReconShot** (`v1.0.0`)
* **Support:** [buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)
* **Platform:** Kali Linux / Debian / Ubuntu / Linux (Python 3.10+)

---

## 📖 Overview

During authorized penetration testing, red teaming, and bug bounty hunting, discovering hundreds or thousands of active web endpoints is standard. Manually navigating to each host in a browser is slow, repetitive, and error-prone.

**ReconShot** solves this by automating high-fidelity visual reconnaissance. Utilizing an asynchronous **Playwright Chromium** engine, ReconShot rapidly renders discovered web applications, extracts rich response metadata, captures screenshots across multiple viewports (Desktop, Mobile, Full-page), and compiles the results into an interactive dark-themed HTML report and structured JSON datasets.

---

## ✨ Key Features

* **⚡ Ultra-Fast Asynchronous Concurrency:** Multi-worker task processing with Playwright Chromium context isolation.
* **🎨 Premium Hacker Terminal UI:** Built with `rich`, featuring colorful live dashboards, animated spinners, status progress bars, and formatted results tables.
* **📱 Responsive Viewport Modes:**
  * **Desktop:** 1920 × 1080
  * **Laptop:** 1366 × 768
  * **Mobile:** 390 × 844 (touch & mobile user-agent emulation)
  * **Custom:** User-defined `--width` and `--height`
* **📜 Full-Page Capture:** Captures the full scrollable page height (`--full-page`).
* **⏳ Configurable JS Render Delay:** `--delay` allows single-page applications (React, Angular, Vue) to fully settle before snapping.
* **🛡️ Smart URL Normalization:** Automatically standardizes input protocols, ports, subdomains, and paths while removing duplicates.
* **📁 Deterministic Safe Naming:** Generates traversal-safe, sanitized, collision-free screenshot filenames.
* **🔄 Resume Capability:** Gracefully saves state upon `CTRL+C` or completion; resume interrupted large scans with `--resume`.
* **📊 Standalone Dark-Themed HTML Report:** Self-contained offline report gallery with live keyword search, status filters (2xx, 3xx, 4xx, 5xx), fullscreen lightbox modal, and JSON export.
* **🔒 Authorized Authenticated Recon:** Injects custom cookies (`--cookies`) and custom headers (`--headers`) for authenticated scope testing.
* **🌐 Proxy & SOCKS Support:** Route traffic through Burp Suite, OWASP ZAP, Tor, or upstream HTTP/SOCKS proxies (`--proxy`).
* **🎯 HTTP Status Filtering:** Filter screenshots by specific status codes (`--status 200` or `--status 2xx,3xx`).
* **📝 Structured Output & Logging:** Deterministic JSON metadata per target, comprehensive `reconshot.log`, and `success.txt` / `failed.txt` target lists.

---

## 🚀 Kali Linux & Debian Installation

ReconShot is optimized for **Kali Linux** and Debian-based systems adhering to **PEP 668** (externally managed Python environments). We strongly recommend using a dedicated Python virtual environment.

### 1. Clone the Repository

```bash
git clone https://github.com/mrdineshpathro-dot/ReconShot.git
cd ReconShot
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Playwright Chromium

```bash
playwright install chromium
```

> **Kali Linux Tip:** If Chromium requires underlying system libraries, install them with:
> ```bash
> playwright install --with-deps chromium
> ```

---

## ⚡ Quick Start

### Single URL Capture

```bash
python3 reconshot.py -u https://example.com
```

### Multiple URLs from File

```bash
python3 reconshot.py -l urls.txt --workers 8 --report
```

### Stdin Pipeline Workflow

```bash
cat urls.txt | python3 reconshot.py
```

### Realistic Bug Bounty / Recon Pipeline

```bash
# Discover subdomains -> probe live HTTP servers -> capture visual recon in ReconShot
subfinder -d example.com -silent | httpx -silent | python3 reconshot.py --workers 10 --report
```

---

## 📋 CLI Options & Flags

| Flag | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-u`, `--url` | `URL` | Target single URL | `None` |
| `-l`, `--list` | `FILE` | Text file containing target URLs (one per line) | `None` |
| `-w`, `--workers` | `INT` | Number of concurrent screenshot workers | `5` |
| `--timeout` | `INT` | Page navigation & rendering timeout in seconds | `30` |
| `--delay` | `FLOAT` | Wait time (seconds) after DOM load before screenshot | `0.0` |
| `--retries` | `INT` | Number of retries on temporary connection failure | `0` |
| `--width` | `INT` | Viewport width in pixels | `1920` |
| `--height` | `INT` | Viewport height in pixels | `1080` |
| `--full-page` | *Flag* | Capture entire scrollable webpage | `False` |
| `--mobile` | *Flag* | Emulate mobile device (390×844 with touch enabled) | `False` |
| `--desktop` | *Flag* | Use desktop viewport (1920×1080) | `True` |
| `--laptop` | *Flag* | Use laptop viewport (1366×768) | `False` |
| `--user-agent` | `TEXT` | Custom User-Agent header | `ReconShot/1.0` |
| `--proxy` | `URL` | HTTP/HTTPS/SOCKS proxy (e.g. `http://127.0.0.1:8080`) | `None` |
| `--cookies` | `FILE` | Load authorized session cookies from JSON file | `None` |
| `--headers` | `FILE` | Load custom HTTP headers from JSON file | `None` |
| `--status` | `CODES` | Capture only specific status codes (e.g. `200` or `2xx,3xx`) | `All` |
| `--resume` | *Flag* | Resume an interrupted scan from `.reconshot_state.json` | `False` |
| `-o`, `--output` | `DIR` | Base output directory | `./results` |
| `--report` | *Flag* | Generate standalone dark-themed HTML report | `True` |
| `--no-report` | *Flag* | Disable HTML report generation | `False` |
| `-c`, `--config` | `FILE` | Load YAML configuration file | `config.yaml` |
| `-v`, `--verbose`| *Flag* | Enable verbose debug logging | `False` |
| `-q`, `--quiet` | *Flag* | Suppress banner and non-error console output | `False` |
| `-V`, `--version`| *Flag* | Display ReconShot version | `1.0.0` |
| `-h`, `--help` | *Flag* | Show help menu | `False` |

---

## 🖼️ Screenshot Modes & Examples

### 1. Full-Page Screenshot

Captures single-page applications and long landing pages from header to footer:

```bash
python3 reconshot.py -l urls.txt --full-page --delay 1.5
```

### 2. Mobile Viewport Emulation

Simulates mobile browser resolution (390×844), touch event support, and mobile User-Agent:

```bash
python3 reconshot.py -l urls.txt --mobile
```

### 3. Custom Resolution

```bash
python3 reconshot.py -l urls.txt --width 1600 --height 900
```

### 4. Authenticated Reconnaissance (Authorized Scope)

Supply authorized session cookies or custom assessment headers:

```bash
python3 reconshot.py -l internal_apps.txt --cookies cookies.json --headers headers.json
```

**`cookies.json` format:**
```json
[
  {
    "name": "session_id",
    "value": "auth_token_value_here",
    "domain": ".example.com",
    "path": "/",
    "secure": true,
    "httpOnly": true
  }
]
```

**`headers.json` format:**
```json
{
  "X-Security-Assessment": "Authorized-Audit",
  "X-HackerOne-Research": "MrDineshPathro",
  "Authorization": "Bearer YOUR_JWT_TOKEN"
}
```

### 5. Status Code Filtering

```bash
# Capture only successful responses
python3 reconshot.py -l urls.txt --status 200

# Capture only redirects and errors
python3 reconshot.py -l urls.txt --status 301,302,403,500

# Capture using wildcard classes
python3 reconshot.py -l urls.txt --status 2xx,4xx
```

### 6. Interrupted Scan Resumption

If a scan of 10,000 targets is stopped midway (`CTRL+C`), resume seamlessly:

```bash
python3 reconshot.py -l urls.txt --resume
```

Output:
```text
[+] Resuming ReconShot scan...
[+] Skipping 3,420 already completed targets
[+] Processing 6,580 remaining targets
```

---

## 📁 Output Directory Structure

By default, results are stored in `./results/` (customizable via `-o`):

```text
results/
├── screenshots/
│   ├── https_example_com.png
│   ├── https_admin_example_com.png
│   └── https_api_example_com_users.png
│
├── metadata/
│   ├── summary.json
│   ├── https_example_com.json
│   ├── https_admin_example_com.json
│   └── https_api_example_com_users.json
│
├── reports/
│   └── report.html
│
├── logs/
│   ├── reconshot.log
│   ├── success.txt
│   └── failed.txt
│
└── .reconshot_state.json
```

### Sample Target Metadata (`results/metadata/https_example_com.json`)

```json
{
  "url": "https://example.com/",
  "final_url": "https://example.com/",
  "status_code": 200,
  "page_title": "Example Domain",
  "timestamp": "2026-09-25T15:30:00+00:00",
  "viewport": {
    "width": 1920,
    "height": 1080
  },
  "full_page": false,
  "screenshot": "https_example_com.png",
  "screenshot_path": "/path/to/results/screenshots/https_example_com.png",
  "response_time_ms": 142.5,
  "content_type": "text/html; charset=UTF-8",
  "redirect_count": 0,
  "browser_profile": "desktop",
  "success": true,
  "error": null,
  "retries_used": 0,
  "headers_received": {
    "server": "ECS (dcb/7F82)",
    "content-type": "text/html; charset=UTF-8"
  }
}
```

---

## 📊 Interactive HTML Report

ReconShot generates a standalone, zero-dependency, dark-themed HTML report located at `results/reports/report.html`.

### Report Features:
* **Cybersecurity Dark Mode:** High-contrast neon accents and sleek visual hierarchy.
* **Zero External Dependencies:** Built with pure embedded CSS & JavaScript; functions completely offline in air-gapped environments.
* **Instant Live Search:** Real-time filtering by URL, domain, page title, status code, or error.
* **Status Filter Tabs:** One-click toggles for `All`, `2xx`, `3xx`, `4xx`, `5xx`, and `Failed` targets.
* **Dual View Modes:** Switch between visual **Card Gallery** and compact **Table List** views.
* **Fullscreen Lightbox Modal:** Click any screenshot thumbnail to inspect in full resolution with keyboard navigation (`Esc` to close).
* **Export Actions:** One-click "Export JSON" and "Copy Live URLs" directly to clipboard.

---

## ⚙️ Configuration File (`config.yaml`)

ReconShot can be configured using a `config.yaml` file. CLI arguments automatically override configuration file settings:

```yaml
# Concurrency & Performance
workers: 5
timeout: 30
delay: 1.0
retries: 1

# Browser Settings
browser:
  width: 1920
  height: 1080
  full_page: false
  mobile: false
  desktop: true
  user_agent: null

# Output Directory
output:
  directory: "./results"

# Reporting
report:
  enabled: true

# Network & Proxy
network:
  proxy: null
  ignore_https_errors: true
```

---

## 🏗️ Architecture & Project Structure

ReconShot is engineered with modular, clean Python architecture following PEP 8 conventions:

```text
ReconShot/
│
├── reconshot.py            # CLI entry point script
├── requirements.txt        # Python package dependencies
├── pyproject.toml          # Package build configuration
├── pytest.ini              # Pytest testing configuration
├── README.md               # Complete documentation
├── LICENSE                 # MIT License
├── config.yaml.example     # Annotated example configuration
├── .gitignore              # Git ignore rules
│
├── reconshot/              # Core application package
│   ├── __init__.py         # Package metadata & exports
│   ├── cli.py              # CLI argument parsing & validation
│   ├── config.py           # YAML config loader & defaults
│   ├── browser.py          # Playwright Chromium manager & context pool
│   ├── screenshot.py       # Single target navigation & screenshot worker
│   ├── crawler.py          # Async scan orchestrator & Rich live UI
│   ├── input_handler.py    # URL normalization & deduplication
│   ├── metadata.py         # JSON metadata & resume state persistence
│   ├── reporter.py         # Standalone dark-themed HTML report generator
│   ├── logger.py           # File logging & security data masking
│   ├── naming.py           # Deterministic filesystem-safe naming
│   ├── models.py           # Data classes & type models
│   └── utils.py            # Rich console helpers, banners, styling
│
├── tests/                  # Automated pytest test suite
│   ├── test_urls.py        # URL normalization tests
│   ├── test_naming.py      # Filename sanitization & safety tests
│   ├── test_config.py      # Config parsing tests
│   ├── test_models.py      # Model serialization tests
│   ├── test_input_handler.py # Input parsing tests
│   ├── test_reporter.py    # HTML report generator tests
│   ├── test_logger.py      # Logging & secret masking tests
│   ├── test_browser.py     # Browser options & error classifier tests
│   ├── test_cli.py         # CLI argument parser tests
│   ├── test_cli_execution.py # CLI execution tests
│   └── test_crawler.py     # Async crawler & resume workflow tests
│
└── examples/               # Example inputs & templates
    ├── urls.txt            # Sample target list
    ├── cookies.json        # Sample cookies template
    └── headers.json        # Sample custom headers template
```

---

## 🧪 Running the Test Suite

ReconShot includes comprehensive automated unit and integration tests:

```bash
# Run all tests with pytest
pytest -v
```

---

## 🔧 Kali Linux Troubleshooting

### 1. `Executable doesn't exist at /root/.cache/ms-playwright/chromium`
Run:
```bash
playwright install chromium
```

### 2. Missing system libraries (shared object errors on minimal Linux)
Run:
```bash
playwright install --with-deps chromium
```

### 3. Piped stdin without TTY
ReconShot automatically detects non-interactive stdin pipes (`cat urls.txt | python3 reconshot.py`) and disables interactive cursor controls while retaining progress reporting.

---

## 🛡️ Legal & Authorized Use Disclaimer

**ReconShot is developed strictly for authorized security assessments, penetration tests, authorized bug bounty programs, and internal infrastructure audits.**

* Users are solely responsible for ensuring they have explicit, written authorization to scan and interact with target systems.
* Do not scan systems outside your defined authorized scope.
* The author (**Mr Dinesh Pathro**) assumes no liability and is not responsible for any misuse or damage caused by this utility.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ☕ Support the Developer

If ReconShot saves you time and accelerates your reconnaissance workflows, consider supporting further development:

👉 **Buy Me a Coffee:** [https://buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)
