# Omni Scanner: Modular Web Vulnerability Engine

**Omni Scanner** is a highly extensible, multi-threaded, and modular vulnerability assessment framework specifically engineered to automate security auditing across complex web applications and network infrastructure.

Built dynamically across 16 core developmental phases, the engine natively parses complex single-page applications, manages stateful authentication schemas (including DVWA), and unleashes targeted exploits against both web inputs and underlying OS architectures.

---

## 🚀 Key Features

*   **Global Stateful Sessions:** Seamlessly supports authenticated scanning via CLI-injected cookies (`-c`) or automated DVWA login macros (`--dvwa`), cascading the authenticated state recursively into all active modules.
*   **Asynchronous Multi-threading:** Employs concurrent worker pools to multiplex payload delivery, enabling incredibly fast execution against deep application architectures.
*   **Smart Parameter Fuzzing:** The crawler dynamically mutates internal URLs to construct hidden debug/admin parameterized attack vectors, turning conventionally "Secure" targets into actionable hits.
*   **Intelligent Evidence Validation:** Modules utilize contextual verification mapping (e.g., precise HTML response analysis, Boolean inference, and implicit multi-second sleep latency matching for Blind attacks).
*   **Master Reporting Engine:** Generates pristine, color-coded HTML dashboard reports documenting specific vulnerability classifications, payloads delivered, evidence timestamps, severity metrics, and targeted remediation strategies.

---

## 🧩 Supported Scanning Modules

| Module Name | Vulnerability Class | Execution Methodology | Extracted Severity |
| :--- | :--- | :--- | :--- |
| **`crawler`** | Discovery | Deep-maps `href` links and explicit `<form>` geometries across the target boundary. | N/A |
| **`sql_injection`** | Injection (A03) | Boolean inference, URL Param & Path appending, Time-Based delay analysis, WAF blocking signatures, and explicit Form Injection. | High |
| **`xss_scanner`** | Injection (A03) | Safely analyzes form outputs and URL reflections for strictly un-escaped HTML script injection payloads. | High |
| **`lfi_scanner`** | Broken Access (A01) | Tests URL and form structures against explicit OS pathing traversing (`/etc/passwd`, `win.ini`) and PHP base64 wrapper leakage. | High |
| **`command_injection`** | Injection (A03) | Dispatches raw chained command arguments checking for `www-data` daemon footprinting and explicit time-series network blocking. | Critical |
| **`brute_force`** | Auth Failures (A07) | Stateful CSRF-aware password payloading parsing dynamic wordlists against detected forms measuring success via redirects or implicit GUI strings. | Critical |
| **`port_scanner`** | Misconfiguration (A05) | Discovers raw exposed TCP port bindings (e.g., 3306 vs 443) flagging non-standard internal components. | Medium |
| **`owasp_scanner`** | Generic Framework | Wraps top-tier assessment checks explicitly mapped to the OWASP Top 10 with PDF generation matrices. | Various |

---

## 📦 Installation & Setup

Ensure you are running **Python 3.8+**.

```sh
git clone <repository_url> omni-scanner
cd omni-scanner

pip install -r requirements.txt
```

### Dependencies
*   `requests` - For core networking and stateful sessions
*   `beautifulsoup4` - For DOM traversal and explicit CSRF token extractions
*   `colorama` - For colored CLI terminal tracking
*   `reportlab` - For programmatic PDF report generation

---

## ⚙️ Usage Configuration

The orchestrator utilizes standard `argparse` execution strings dynamically dispatching tasks to modules.

```sh
python main.py -t <TARGET_URL> -m <MODULE1> <MODULE2> [OPTIONS]
```

### Options

*   `-t, --target` : Initial URL, Web root, or raw IPv4 socket identifier. (Required)
*   `-m, --modules` : Selected array of scanning modules. Leave blank or use `all` to sequence every module sequentially.
*   `-w, --workers` : Define total concurrent executor threads for multi-threaded payload drops (Defaults to 5).
*   `-c, --cookies` : Manually supply serialized Session cookies to penetrate walled gardens.
*   `--dvwa` : Automatically bypass root login authentication on DVWA servers to deploy modules against internal tools securely.

### Examples

**Standard Broad Target Scan (Multi-threaded & Authenticated):**
```sh
python main.py -t "http://localhost/vulnerabilities/fi/?page=include.php" -m crawler lfi_scanner command_injection -w 10 --dvwa
```

**Password Brute-forcing Web Nodes (Using Dynamic Wordlists):**
```sh
python main.py -t "http://localhost/vulnerabilities/brute/" -m crawler brute_force
```

**Network Architecture Mapping:**
```sh
python main.py -t "http://localhost" -m port_scanner
```

---
## API (FastAPI)

Start the REST API that exposes `POST /scan`:

```sh
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open the UI in your browser:

- Local machine: `http://127.0.0.1:8000/`
- Another device on the LAN: `http://<your-pc-lan-ip>:8000/`

Example request:

```sh
curl -X POST "http://127.0.0.1:8000/scan" ^
  -H "Content-Type: application/json" ^
  -d "{\"target\":\"http://localhost/vulnerabilities/\",\"modules\":[\"crawler\",\"xss_scanner\"],\"deep\":false,\"dvwa\":false}"
```

---

## 🛡️ Educational Disclaimer
This vulnerability assessment framework was constructed purely for defensive educational audits and professional penetration testing workflows. The codebase aggressively tests structural integrity by interacting with forms and injecting raw queries.

**Under no circumstances execute this tool against infrastructure or applications without explicit and documented authorization.**
