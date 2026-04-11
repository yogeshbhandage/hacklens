<p align="center">
  <img src="logo.png" alt="HackLens Logo" width="350"/>
</p>

<h1 align="center">🔍 HackLens</h1>

<p align="center">
  <b>Web Recon & Vulnerability Scanner for Bug Bounty Hunters</b><br/>
  JS Secrets  |  Reflected XSS  |  Open Redirect Detection
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/Purpose-Bug%20Bounty-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Built%20with-AI-purple?style=flat-square"/>
</p>

<p align="center">
  Created by <a href="https://yogeshbhandage.com"><b>Yogesh Bhandage</b></a> &nbsp;|&nbsp; 
  <a href="https://yogeshbhandage.com">yogeshbhandage.com</a>
</p>

---

## ⚠️ Legal Disclaimer

> **HackLens is intended for authorized security testing only.**  
> Only use this tool against targets you have **explicit written permission** to test — such as bug bounty programs, your own applications, or intentional practice environments (e.g. `altoro.testfire.net`, `demo.testfire.net`).  
> Unauthorized use against systems you do not own is **illegal** and unethical. The author assumes no responsibility for misuse.

---

## 📖 About

**HackLens** is a full-featured, automated recon and vulnerability scanning tool built for bug bounty hunters and security researchers.

**You give it a domain name — it does everything else.**

Enter a domain → HackLens automatically:
1. Enumerates subdomains
2. Collects all JavaScript files and page URLs (7 recon sources)
3. Scans all JS files, HTML pages, JSON APIs, and config endpoints for 70+ types of hardcoded secrets and credentials
4. Actively tests every URL parameter for Reflected XSS
5. Actively tests every URL for Open Redirect vulnerabilities
6. Saves everything in a clean per-target folder with JSON + HTML reports

> *Built with AI using original ideas and concepts by Yogesh Bhandage*

---

## ✨ Features

### 🔑 Secret & Credential Detection — 70+ Patterns

| Category | What's Detected |
|---|---|
| ☁️ Cloud | AWS Access/Secret keys, Google API keys, Azure Storage keys, GCP service accounts |
| 🤖 AI / ML | OpenAI (old + project format), Anthropic, Hugging Face |
| 💳 Payment | Stripe live/test/publishable/webhook, PayPal client ID, Braintree |
| 🔐 Auth | JWT tokens, Bearer tokens, OAuth tokens, Basic Auth in URLs |
| 🐙 Source Control | GitHub (classic, OAuth, app, fine-grained PAT), GitLab PAT, NPM tokens |
| 💬 Communication | Slack tokens & webhooks, Discord tokens & webhooks, Telegram bot tokens, Twilio, SendGrid, Mailgun |
| 🗄️ Databases | MongoDB, PostgreSQL, MySQL, Redis URIs with credentials |
| 🔒 Cryptography | AES IV, encryption keys, HMAC secrets, crypto salts, hex-encoded secrets |
| 👤 Credentials | Hardcoded usernames, passwords, username+password pairs |
| 🏗️ Infrastructure | Firebase, S3 buckets, Heroku API keys, Vault tokens, Docker Hub tokens |
| 🔑 SSH / Crypto Keys | RSA, EC, PGP, OpenSSH private keys |
| 🛠️ SaaS | Sentry DSN, Shopify, Algolia, Mapbox, Intercom, Pusher, Amplitude, WordPress auth keys |

**Proactively fetches secret-leaking endpoints** even if not crawled:
```
/.env  /.env.local  /.env.production  /.env.backup
/.git/config  /.git/HEAD
/config.json  /config.js  /settings.json
/package.json  /composer.json
/actuator/env  /actuator/configprops   (Spring Boot)
/api/config  /api/v1/config  /api/v2/config
/phpinfo.php  /wp-config.php.bak
```

---

### ⚡ Reflected XSS — Zero False-Positive Design

Three-phase approach — every reported finding is a **proven, exploitable reflection**:

**Phase 1 — Reflection Check**
Injects a unique random alphanumeric canary (e.g. `SHXSSxyz123`) with zero HTML/JS meaning. Only proceeds if canary appears verbatim and unencoded in the response.

**Phase 2 — Context Detection**
Determines exactly where the reflection landed:

| Context | Description |
|---|---|
| `html_body` | Between HTML tags |
| `attr_double` | Inside a double-quoted attribute |
| `attr_single` | Inside a single-quoted attribute |
| `attr_unquoted` | Unquoted attribute value |
| `js_string_dq` | Inside a JS double-quoted string |
| `js_string_sq` | Inside a JS single-quoted string |
| `js_code` | Bare inside a `<script>` block |
| `url_param` | Inside href/src/action |

**Phase 3 — Context-Specific Payload**
Selects the minimal exploitable payload for that exact context. Confirms payload is also reflected unencoded before reporting.

Every finding includes the **full PoC URL** with the working payload already embedded in the parameter.

Tests **ALL parameters** — known reflection params tested first, all others second. No endpoint is skipped.

---

### ↩ Open Redirect — 3-Layer Detection

**Layer 1 — Raw Location Header** (`allow_redirects=False`)
Catches direct HTTP 301/302/303/307/308 redirects. Highest confidence.

**Layer 2 — Response Body Scan**
Checks for canary/off-site URL in `href=`, `window.location=`, `location.href=`, `<meta http-equiv="refresh">`.

**Layer 3 — Full Redirect Chain Follow**
Follows the complete redirect chain and checks every `Location` header.

**Canary domain:** `yogeshbhandage.com`

**13 bypass probe variants:**
```
https://yogeshbhandage.com
http://yogeshbhandage.com
//yogeshbhandage.com                      (protocol-relative)
https://yogeshbhandage.com/
@yogeshbhandage.com                       (@ confusion)
////yogeshbhandage.com                    (multiple slashes)
\tyogeshbhandage.com                      (tab prefix bypass)
https:yogeshbhandage.com                  (no-slash)
/%09/yogeshbhandage.com                   (horizontal tab)
https://yogeshbhandage.com@target.com     (credential confusion)
https://target.com@yogeshbhandage.com     (reversed)
https://yogeshbhandage.com%23.target.com  (fragment confusion)
https://yogeshbhandage.com/%2F..          (path traversal)
```

Tests **ALL parameters** — not just params named `redirect`, `url`, `next` etc. Also detects params whose current value already looks like a URL (`?url=http://microsoft.com`).

---

### 📡 JS & URL Collection — 7 Sources

| Source | What It Collects |
|---|---|
| Direct Crawl (BeautifulSoup) | JS files, page links, form actions from HTML |
| Katana | Deep JS-rendering crawler |
| GAU | Archived URLs from AlienVault OTX, Wayback, CommonCrawl |
| Hakrawler | Fast web crawler (stdin-based) |
| SubJS | JS files extracted from HTML pages |
| Wayback Machine CDX API | 3 query variants for maximum JS coverage |
| waybackurls | Historical URL tool |

---

### 🌐 Subdomain Enumeration

- crt.sh certificate transparency logs
- Subfinder (passive)
- Assetfinder
- Amass (passive)

---

### 📁 Per-Target Output Folder

Results are automatically saved in a folder named after the target:

```
target.com/
  secrets_20240411_143022.json     ← all findings (machine-readable)
  report_20240411_143022.html      ← visual report (open in browser)
  total_subdomains.txt             ← all discovered subdomains
  crawled-urls.txt                 ← all collected URLs (JS + pages)
  endpoints.txt                    ← API endpoints extracted from JS
```

---

## 🛠 Installation

### Requirements
- Python 3.8+
- Go 1.18+
- Linux or macOS (Kali Linux recommended)

### One-Command Install

```bash
bash install.sh
```

Then apply PATH changes:

```bash
source ~/.bashrc
```

---

## 🚀 Usage

### Basic Scan
```bash
bash run.sh -d target.com
```

### Deep Scan (recommended)
```bash
bash run.sh -d target.com --deep
```

### Full Power — Deep + Subdomains
```bash
bash run.sh -d target.com --deep --subs
```

### All Options

```
bash run.sh -d target.com [options]

  -d, --domain        Target domain  (required)  e.g. example.com
  --deep              Enable Wayback Machine, GAU, waybackurls
  --subs              Enumerate and scan subdomains
  --no-xss            Skip XSS scanning
  --no-redirect       Skip open redirect scanning
  -c, --cookies       Cookie string  e.g. "session=abc123; csrf=xyz"
  -H, --headers       Extra headers  e.g. "Authorization: Bearer token"
  -p, --proxy         Proxy URL  e.g. http://127.0.0.1:8080
  -w, --workers       Parallel workers (default: 10)
```

### Examples

```bash
# Standard scan
bash run.sh -d example.com

# Deep scan with subdomain enumeration
bash run.sh -d example.com --deep --subs

# Authenticated scan (logged-in user session)
bash run.sh -d example.com -c "session=abc123; token=xyz"

# Intercept all requests through Burp Suite
bash run.sh -d example.com -p http://127.0.0.1:8080

# Secrets only — skip active vulnerability testing
bash run.sh -d example.com --no-xss --no-redirect

# Maximum coverage
bash run.sh -d example.com --deep --subs -w 20
```

---

## 📊 Sample Output

```
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████╗██║ ╚████║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝

  Target     : target.com
  Output dir : target.com/
  Mode       : Deep + Subdomains + XSS + OpenRedirect

──────────────────────────────────────────────────────────────
  STEP 0: Subdomain Enumeration
──────────────────────────────────────────────────────────────
[+] crt.sh: 34 subdomains
[+] Subfinder: 28 subdomains
[+] Total subdomains: 47
[+] Subdomains saved → target.com/total_subdomains.txt

──────────────────────────────────────────────────────────────
  STEP 3: Scanning 84 JS + 398 pages/endpoints for Secrets
──────────────────────────────────────────────────────────────

  [CRITICAL] AWS Access Key
  Source : https://target.com/static/js/main.chunk.js (line 1247)
  Value  : AKIAIOSFODNN7EXAMPLE...

  [HIGH] Slack Token
  Source : https://target.com/assets/js/app.js (line 892)
  Value  : xoxb-123456789012-...

──────────────────────────────────────────────────────────────
  STEP 4: XSS Scanning 412 URLs
──────────────────────────────────────────────────────────────
[*] Testing 116 unique combinations (89 priority + 27 secondary)…

  [Reflected XSS]
  https://target.com/search?query=<img src=x id=SHXSS onerror=alert(1)>
  Param   : query
  Context : html_body | Payload verified in response

──────────────────────────────────────────────────────────────
  STEP 5: Open Redirect Scanning
──────────────────────────────────────────────────────────────
  [Open Redirect [CONFIRMED]]
  https://target.com/logout?next=https://yogeshbhandage.com
  Param   : next
  Detail  : off-site Location header | HTTP 302
  Location: https://yogeshbhandage.com

──────────────────────────────────────────────────────────────
  SCAN COMPLETE
──────────────────────────────────────────────────────────────
  🔑 8 secret(s)
     [CRITICAL] 2
     [HIGH]     4
     [MEDIUM]   2
  ⚡ 1 reflected XSS finding(s)
  ↩  1 open redirect finding(s)

  Output dir : target.com/
```

---

## 🔐 Severity Levels

| Severity | Examples |
|---|---|
| 🔴 CRITICAL | AWS keys, Stripe live keys, private RSA/EC/PGP/SSH keys, OpenAI keys, DB URIs with creds, JWTs, GitHub tokens |
| 🟠 HIGH | Google API keys, Slack tokens, Discord tokens, SendGrid, S3 buckets, access tokens, Sentry DSN, NPM tokens |
| 🟡 MEDIUM | Webhooks, Heroku keys, Firebase, Shopify, Algolia, Vault tokens, Stripe publishable |
| 🔵 LOW | Hardcoded passwords, internal IPs, database passwords, Basic Auth in URLs |
| ℹ️ INFO | AWS ARNs, Google service account references |

---

## 🗂 Project Structure

```
HackLens/
  hacklens.py     ← main tool
  install.sh      ← installs all dependencies
  run.sh          ← auto-created by install.sh
  logo.png        ← HackLens logo
  README.md       ← this file
```

---

## 🧰 Integrated Tool Stack

| Tool | Purpose |
|---|---|
| `katana` | JS-aware deep web crawler |
| `gau` | Historical URL collection (OTX, Wayback, CommonCrawl) |
| `hakrawler` | Fast web crawler |
| `subjs` | JS file extractor |
| `waybackurls` | Historical URLs from Wayback Machine |
| `subfinder` | Passive subdomain enumeration |
| `assetfinder` | Subdomain discovery |
| `amass` | Passive subdomain enumeration |
| `jsbeautifier` | JS de-minification before scanning |
| `beautifulsoup4` | HTML parsing |
| `requests` | HTTP client |

---

## 🤝 Contributing

Pull requests welcome. Planned features:
- DOM-based XSS detection
- SSRF detection
- CORS misconfiguration checks
- Stored XSS indicators
- Rate limiting / WAF evasion

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

---

<p align="center">
  <b>Created by Yogesh Bhandage</b><br/>
  <a href="https://yogeshbhandage.com">yogeshbhandage.com</a><br/><br/>
  <i>Built with AI using original ideas by the author.</i><br/>
  <i>Hunt responsibly. 🎯</i>
</p>
