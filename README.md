<p align="center">
  <img src="logo.png" alt="HackLens Logo" width="400"/>
</p>

<h1 align="center">HackLens</h1>

<p align="center">
  <b>Automated Web Recon & Vulnerability Scanner for Bug Bounty Hunters</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/Patterns-240%2B-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Built%20with-AI-purple?style=flat-square"/>
</p>

<p align="center">
  Created by <a href="https://yogeshbhandage.com"><b>Yogesh Bhandage</b></a>
  &nbsp;|&nbsp;
  <a href="https://yogeshbhandage.com">yogeshbhandage.com</a>
</p>

---

## ⚠️ Disclaimer

> **HackLens is for authorized security testing only.**
> Only use against targets you have **explicit written permission** to test — bug bounty programs, your own applications, or intentional practice environments.
> Unauthorized use is **illegal**. The author assumes no responsibility for misuse.

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Modes](#scan-modes)
- [All Flags](#flags)
- [Secret Detection](#secrets)
- [XSS Detection](#xss)
- [Open Redirect](#redirect)
- [Information Disclosure](#infodisclosure)
- [SSTI Detection](#ssti)
- [Command Injection](#ci)
- [Subdomain Enumeration](#subdomains)
- [Output Files](#output)
- [Updating](#updating)
- [Roadmap](#roadmap)

---

## About {#about}

HackLens is a fully automated web reconnaissance and vulnerability scanning tool built for bug bounty hunters and security researchers.

**You give it a domain — it does everything.**

```
bash run.sh -d target.com --deep --subs
```

```
  Domain
    │
    ├── Subdomain Enumeration ──── 12+ sources (crt.sh, HackerTarget, Subfinder,
    │                               Assetfinder, Amass, Chaos, Certspotter, Wayback...)
    │
    ├── Alive Check ─────────────── httpx (filters dead subdomains)
    │
    ├── JS & URL Collection ──────── 7 tools (Katana, GAU, Hakrawler, SubJS,
    │                                Wayback Machine, waybackurls, direct crawl)
    │
    ├── Secret Scanning ──────────── 240+ regex patterns across JS files, HTML,
    │                                JSON APIs, .env, config, source maps
    │
    ├── Reflected XSS ───────────── 3-phase: canary → context detection → payload
    │                                26 payloads, 8 contexts, zero FP design
    │
    ├── Open Redirect ───────────── 3-layer detection, 13 bypass probes
    │                                evil.com must be destination HOST
    │
    ├── Information Disclosure ───── 70+ probe paths, 20+ response patterns
    │                                Debug mode, stack traces, Spring Boot, Git...
    │
    ├── SSTI ─────────────────────── 6 engine formats, triple math verification
    │                                Jinja2, Twig, Freemarker, ERB, Spring EL
    │
    └── Command Injection ────────── Output-based + double-verified time-based
                                     12 separators, OOB interactsh support
```

> *Built with AI using original ideas by Yogesh Bhandage*

---

## Features {#features}

| Feature | Details |
|---------|---------|
| 🔑 **Secret Detection** | 240+ patterns — AWS, Stripe, GitHub, OpenAI, DB credentials, private keys, and more |
| ⚡ **Reflected XSS** | 3-phase zero-FP design — canary reflection, context detection, context-specific payloads |
| ↩ **Open Redirect** | 3-layer detection — Location header, JS sinks, redirect chain |
| 🔍 **Info Disclosure** | 70+ probe paths — debug pages, stack traces, actuator endpoints, backup files |
| 💉 **SSTI** | Triple-verified math probes across 6 template engine formats |
| 🖥 **Command Injection** | Output-based + time-based (double-verified) + OOB interactsh |
| 🌐 **Subdomain Enum** | 12+ sources — no API keys needed for most |
| 🗂 **3 Scan Modes** | Auto recon (`-d`), URL list (`-l`), Burp XML (`-b`) |
| 🎯 **Scope Enforcement** | Only scans target domain and subdomains |
| 📊 **Reports** | JSON + HTML report per scan |
| 🔧 **Memory Safe** | Chunked scanning — handles 20MB+ JS files without OOM |

---

## Installation {#installation}

### Requirements
- Python 3.8+
- Go 1.18+
- Linux or macOS (Kali Linux recommended)

### One-Command Install

```bash
git clone https://github.com/yogeshbhandage/HackLens.git
cd HackLens
bash install.sh
source ~/.bashrc
```

The installer handles everything:
- Python virtual environment + packages
- Go environment setup
- All recon tools (Katana, GAU, Subfinder, Assetfinder, Amass, httpx, etc.)
- MassDNS + SecLists wordlist (optional, for subdomain bruteforce)

If any tools show ✗ after install:
```bash
source ~/.bashrc      # fix PATH first
bash install.sh       # re-run is safe — skips already installed tools
```

---

## Usage {#usage}

### Quick Start

```bash
# Full scan — subdomains + deep crawl + all vuln types
bash run.sh -d target.com --deep --subs

# Authenticated scan
bash run.sh -d target.com --deep --subs -c "session=abc123; csrf=xyz"

# Through Burp Suite proxy
bash run.sh -d target.com -p http://127.0.0.1:8080

# Include SSTI and command injection
bash run.sh -d target.com --deep --subs --ssti --ci

# Secrets only — fast mode
bash run.sh -d target.com --no-xss --no-redirect --no-info
```

---

## Scan Modes {#scan-modes}

### Mode 1 — Auto Recon (`-d`)

Discovers everything automatically. Give it a domain and walk away.

```bash
bash run.sh -d target.com
bash run.sh -d target.com --deep --subs
bash run.sh -d target.com --deep --subs --ssti --ci --ci-server your.interactsh.server
```

**`--deep`** enables: Wayback Machine, GAU, waybackurls — and automatically enables SSTI + CI scanning.

**`--subs`** enables: subdomain enumeration from 12+ sources + httpx alive check.

**Output folder:** `target.com/`

---

### Mode 2 — Pre-Crawled URL List (`-l`)

Skip all recon — scan a URL list you already have. Useful for Burp history, authenticated sessions, or re-scanning with updated patterns.

```bash
bash run.sh -l urls.txt
bash run.sh -l urls.txt --ssti --ci
bash run.sh -l urls.txt -c "session=abc123"
```

**How to prepare a URL list:**
```bash
# From your own crawl
katana -u https://target.com -jc -silent > urls.txt
gau target.com >> urls.txt
waybackurls target.com >> urls.txt

# Then scan
bash run.sh -l urls.txt
```

**What it does:**
1. Splits URLs — JS files, parameterised pages, plain pages
2. Scans all URLs for secrets
3. Tests parameterised URLs for XSS and open redirects
4. Probes known-sensitive paths for info disclosure
5. Tests all params for SSTI and command injection (if `--ssti`/`--ci`)

**Output folder:** `<domain>-urlscan/` — JSON + HTML report only

---

### Mode 3 — Burp XML Export (`-b`)

Feed a full Burp Suite HTTP history export — handles GET and POST requests including request bodies.

**How to export from Burp:**
```
Proxy → HTTP History → Select all → Right click → Save items → burp_export.xml
```

```bash
bash run.sh -b burp_export.xml
bash run.sh -b burp_export.xml -c "session=abc123"
bash run.sh -b burp_export.xml --ssti --ci
```

**What it does beyond `-l`:**
- **Pass A** — scans request bodies directly (query params, POST form data, JSON body, multipart fields)
- **Pass B** — replays every request and scans responses — ALL status codes (200, 201, 401, 403, 500 etc.)
- Tests POST body parameters for XSS (form-encoded, JSON, multipart)
- Handles `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`

**Output folder:** `<domain>-burpscan/` — JSON + HTML report only

> **Note:** `-d`, `-l`, and `-b` are mutually exclusive — use one per scan.

---

## All Flags {#flags}

| Flag | Description | Mode |
|------|-------------|------|
| `-d, --domain DOMAIN` | Target domain e.g. `example.com` | Auto |
| `-l, --list FILE` | Pre-crawled URL list file | List |
| `-b, --burp FILE` | Burp Suite XML export file | Burp |
| `--deep` | Enable Wayback, GAU, waybackurls — also enables `--ssti` and `--ci` | Auto |
| `--subs` | Enumerate subdomains from 12+ sources | Auto |
| `--ssti` | Enable SSTI scanning | All |
| `--ci` | Enable command injection scanning | All |
| `--ci-server DOMAIN` | Interactsh OOB server for blind CI detection | All |
| `--no-xss` | Skip XSS scanning | All |
| `--no-redirect` | Skip open redirect scanning | All |
| `--no-info` | Skip information disclosure scanning | All |
| `-c, --cookies STR` | Cookie string e.g. `"session=abc; csrf=xyz"` | All |
| `-H, --headers HDR` | Extra headers e.g. `"Authorization: Bearer token"` | All |
| `-p, --proxy URL` | Proxy URL e.g. `http://127.0.0.1:8080` | All |
| `-w, --workers N` | Parallel workers (default: 5) | All |
| `--max-js N` | Max JS files to scan (default: 2000) | Auto |
| `--max-pages N` | Max page URLs to scan (default: 1000) | Auto |
| `--version` | Show version and exit | — |

### Cookie Flag Usage

```bash
# ✅ Correct — value only
bash run.sh -d target.com -c "PHPSESSID=abc123"
bash run.sh -d target.com -c "session=abc; csrf=xyz; token=123"

# ❌ Wrong — don't include "Cookie:" header name
bash run.sh -d target.com -c "Cookie: PHPSESSID=abc123"
```

### Examples

```bash
# Full power
bash run.sh -d target.com --deep --subs -w 10

# Authenticated deep scan through Burp
bash run.sh -d target.com --deep --subs \
  -c "session=abc123" -p http://127.0.0.1:8080

# SSTI + CI with OOB callback
bash run.sh -d target.com --ssti --ci \
  --ci-server yourtoken.oast.fun

# Rescan previous results with new patterns
bash run.sh -l target.com/crawled-urls.txt

# Burp history with SSTI + CI
bash run.sh -b burp_export.xml --ssti --ci \
  -c "session=abc123"

# Secrets only — very fast
bash run.sh -d target.com \
  --no-xss --no-redirect --no-info

# Check version
bash run.sh --version
```

---

## Secret Detection {#secrets}

HackLens scans JS files, HTML pages, JSON APIs, `.env` files, config endpoints, source maps, TypeScript files, and more — using 240+ regex patterns.

### Pattern Categories

| Category | Examples |
|----------|---------|
| ☁️ **Cloud** | AWS Access/Secret/Session Key, Google API/OAuth Token, Azure Storage/Client/SAS, GCP Service Account |
| 🤖 **AI / ML** | OpenAI (old + project format), Anthropic, Hugging Face |
| 💳 **Payment** | Stripe (live/test/restricted/webhook), Square, Razorpay, PayPal, Braintree |
| 🔐 **Auth** | JWT tokens, Bearer tokens, OAuth (access/refresh/bearer), Session ID, Basic Auth URLs |
| 🐙 **Source Control** | GitHub (classic PAT, OAuth, App, Fine-Grained), GitLab PAT, NPM token |
| 💬 **Communication** | Slack (bot/user/workspace/webhook), Discord, Telegram bot, Twilio, SendGrid, Mailgun |
| 🗄️ **Database** | MongoDB/PostgreSQL/MySQL/Redis URIs with credentials, PGPASSWORD, MySQL password/username/server/host |
| 🔒 **Cryptography** | AES Key, Master Key, HMAC secret, PBKDF/scrypt, Encryption Password |
| 👤 **Credentials** | Admin Password, Engine Server, hardcoded username/password pairs |
| 🔑 **Private Keys** | RSA, EC, DSA, PGP, OpenSSH, Generic Private Key, Certificate |
| 🛠️ **DevOps / CI-CD** | Datadog, New Relic, Databricks, Kubernetes, Terraform, CircleCI, Vercel, Fly.io, Netlify |
| 🔏 **SSO / Auth** | Auth0, Okta, OAuth Client ID/Secret, Master Key |
| 📧 **Email** | SMTP credentials, Postmark, Resend, Mailchimp, Brevo, SparkPost |
| 🌐 **SaaS** | Shopify, Algolia, Mapbox, Firebase, Vault, Sentry DSN, Intercom, Pusher |
| 🔗 **Web3** | Ethereum private key, Infura, Alchemy, WalletConnect, Pinata |
| 📋 **Productivity** | Notion, Linear, Airtable PAT, Jira, HubSpot, Salesforce, Webflow |
| 🧩 **CamelCase** | `apiKey`, `secretKey`, `authToken`, `clientSecret`, `dbPassword`, `jwtSecret` and 8 more |
| 📦 **JS Objects** | `{"secret":"val"}`, `{"db_password":"val"}`, `{"access_token":"val"}` |
| 🔍 **File Exposure** | `.env` in href/src, `.git` in href/src, UUID in sensitive key context |

### Proactive Endpoint Checks

Even if not crawled, HackLens fetches these paths directly:

```
/.env  /.env.local  /.env.production  /.env.staging  /.env.backup
/.git/config  /.git/HEAD
/config.json  /config.yml  /settings.json  /application.properties
/package.json  /composer.json
/actuator/env  /actuator/configprops
/api/config  /phpinfo.php  /wp-config.php.bak
```

### Severity Levels

| Level | Examples |
|-------|---------|
| 🔴 CRITICAL | AWS Access/Secret Key, private keys, Stripe live, OpenAI, DB URIs with creds, JWT, OAuth Client Secret, SQL dump |
| 🟠 HIGH | Google API, Slack tokens, GitHub, SendGrid, S3 bucket, Access Token, SMTP Password |
| 🟡 MEDIUM | Webhooks, Firebase, Session ID, Shopify, CamelCase tokens, JS Object secrets |
| 🔵 LOW | MySQL server/host, Internal IPs, SMTP host, X-Powered-By header |
| ℹ️ INFO | Stripe test keys, AWS ARNs |

---

## XSS Detection {#xss}

### How It Works

**Phase 1 — Canary Reflection**
A unique random canary (e.g. `SHXSSk3m9pzxq1r4`) with no HTML/JS meaning is injected. Only proceeds if the canary appears verbatim and unencoded in the response.

**Phase 2 — Context Detection**
Determines exactly where the reflection landed using 500-char lookback. Automatically skips Next.js `__NEXT_DATA__`, Nuxt `__NUXT_DATA__`, Redux, and other JSON data blocks that look like JS but aren't executable.

| Context | Where |
|---------|-------|
| `html_body` | Between HTML tags |
| `attr_double` | Inside `value="..."` |
| `attr_single` | Inside `value='...'` |
| `attr_unquoted` | Inside `value=...` |
| `js_string_dq` | Inside `var x = "..."` |
| `js_string_sq` | Inside `var x = '...'` |
| `js_code` | Bare inside `<script>` |
| `url_param` | Inside `href`/`src`/`action` |

**Phase 3 — Context-Specific Payloads**
Multiple payloads tried per context — stops on first confirmed. FP checks applied per context type.

Every finding includes a **ready-to-use PoC URL**.

### All 26 Payloads

| Context | Payloads |
|---------|---------|
| `html_body` | `<img onerror>`, `><script>alert(1)//`, `<svg onload>`, `<details ontoggle>`, `<input onfocus>` |
| `attr_double` | `"><script>`, `"><img>`, `" onfocus autofocus`, `" onmouseover` |
| `attr_single` | `'><script>`, `'><img>`, `' onfocus autofocus`, `' onmouseover` |
| `attr_unquoted` | `><img onerror><x`, `><script></script><x` |
| `js_string_dq` | `";alert(1)//`, `"-alert(1)-"`, `"+alert(1)+"` |
| `js_string_sq` | `';alert(1)//`, `'-alert(1)-'`, `'+alert(1)+'` |
| `js_code` | `;/*canary*/alert(1)//`, `;alert(1)//`, `\nalert(1)//` |
| `url_param` | `javascript:alert(1)//`, `javascript://canary/%0aalert(1)` |

---

## Open Redirect Detection {#redirect}

**Canary domain:** `evil.com`

**Core rule:** `evil.com` must be the **destination host** of the redirect — not just a value in a query parameter.

```
❌ False Positive:  Location: https://target.com/login?next=https://evil.com
✅ True Positive:   Location: https://evil.com/page
```

### Detection Layers

| Layer | Method |
|-------|--------|
| 1 | Raw `Location` header (`allow_redirects=False`) — highest confidence |
| 2 | JS redirect sinks in response body (`window.location`, `location.href`, `meta-refresh`) |
| 3 | Follow full redirect chain — check every hop |

### 13 Bypass Probes

Protocol-relative (`//evil.com`), `@` confusion, multiple slashes, tab prefix, credential confusion, reversed credential confusion, fragment confusion, URL-encoded variants, and more.

### Severity

| Finding | Severity |
|---------|---------|
| `[CONFIRMED]` — browser redirected to evil.com | HIGH |
| `[POSSIBLE]` — JS sink or meta-refresh found | MEDIUM |
| `[One-Click LOW]` — `<a href>` pointing to evil.com | LOW |

---

## Information Disclosure {#infodisclosure}

HackLens probes 70+ known-sensitive paths and checks responses for 20+ disclosure patterns.

### What It Probes

- **Spring Boot Actuator** — `/actuator/env`, `/actuator/heapdump`, `/actuator/beans`, and 10 more
- **Laravel** — `/_ignition/health-check`, `/telescope`, `/horizon`
- **PHP** — `/phpinfo.php`, `/info.php`
- **Config files** — `/.env` (9 variants), `/config.json`, `/config.yml`, `/web.config`, `/application.properties`
- **Source exposure** — `/.git/HEAD`, `/.git/config`, `/.svn/entries`
- **API Documentation** — `/swagger-ui`, `/api-docs`, `/v2/api-docs`, `/openapi.json`, `/graphql`, `/graphiql`
- **Backup files** — `/backup.sql`, `/db.sql`, `/backup.zip`, `/www.zip`
- **Admin panels** — `/admin`, `/wp-admin`, `/administrator`, `/cpanel`
- **Log files** — `/error.log`, `/access.log`, `/debug.log`

### What It Detects in Responses

Python/PHP/Rails/Django/Laravel/Node.js stack traces, `DEBUG=True` pages, server/framework version disclosure, private keys in response, hardcoded credentials, environment variables, directory listing, Git HEAD accessible, SQL error messages, phpinfo() output, GraphQL introspection enabled, Spring Boot Actuator data, SQL dump files.

### Deduplication

Header findings (`X-Powered-By`, `Server` version) are deduplicated per domain — reported once regardless of how many URLs have the header.

Use `--no-info` to skip.

---

## SSTI Detection {#ssti}

### Triple Math Verification

Every parameter on every URL is tested with three independent math expressions — all three must produce correct results before a finding is reported.

```
Round 1: {{456*765}} → response must contain 348840
Round 2: {{89*45}}   → response must contain 4005
Round 3: {{317*213}} → response must contain 67521
```

Three correct math evaluations cannot be coincidence — zero false positives.

### 6 Engine Formats Tested

| Template Syntax | Engine |
|-----------------|--------|
| `{{N*M}}` | Jinja2, Twig, Tornado |
| `${N*M}` | Freemarker, Velocity |
| `*{N*M}` | Spring EL, Thymeleaf |
| `<%=N*M%>` | ERB, Mako |
| `{math equation="N*M"}` | Smarty |

### Engine Fingerprinting

Once injection is confirmed: `{{7*'7'}}` — returns `7777777` = Jinja2, returns `49` = Twig.

Enable with `--ssti` or automatically via `--deep`.

---

## Command Injection {#ci}

### 3 Detection Methods

**Method 1 — Output-based (fastest)**
Injects 12 separators × 16 commands, checks for output in response:
- Unix: `id`, `whoami`, `cat /etc/passwd`, `uname -a`, `ls -la`, `env`, `printenv`
- Windows: `whoami`, `dir`, `ver`, `ipconfig`, `type C:\Windows\win.ini`
- Canary: `echo hacklens_ci_confirmed`

**Method 2 — Time-based blind (double-verified)**
- Round 1: `{sep}sleep 5` — response must take 5+ seconds
- Round 2: `{sep}sleep 3` — response must also take 3+ seconds
- Both rounds must confirm — eliminates network jitter false positives

**Method 3 — OOB via interactsh (optional)**
```bash
bash run.sh -d target.com --ci --ci-server yourtoken.oast.fun
```
Injects DNS/HTTP callback payloads: `; nslookup token.yourserver`, `; curl http://token.yourserver`

### 12 Injection Separators

`;` `|` `&&` `||` `\n` `\r\n` `$(cmd)` `` `cmd` `` `%0a` `%0a%0d` `&` `\x0a`

Also tries: `sleep${IFS}5` (bypass space filter), `ping -c 5 127.0.0.1`, `timeout 5` (Windows), `Start-Sleep 5` (PowerShell)

Enable with `--ci` or automatically via `--deep`. Workers capped at 3 for CI to prevent timing FPs.

---

## Subdomain Enumeration {#subdomains}

### Sources

**No install required (HTTP API calls):**

| Source | Notes |
|--------|-------|
| crt.sh | Certificate Transparency — 2 queries |
| HackerTarget | Passive DNS |
| RapidDNS | DNS search |
| AlienVault OTX | passive_dns + url_list endpoints |
| URLScan.io | Up to 300 results |
| ThreatCrowd | Threat intelligence |
| Certspotter | Reliable CT log API |
| Wayback CDX | Archived URLs → extract subdomains |
| DNSDumpster | DNS recon (scraped) |

**Tool-based (installed by install.sh):**

| Tool | Timeout | Notes |
|------|---------|-------|
| Subfinder | 180s | `-all` flag — uses all sources |
| Assetfinder | 60s | Fast |
| Amass | 300s | Passive, thorough |
| Chaos | 60s | Needs `export CHAOS_KEY=yourkey` |
| MassDNS | 120s | Optional bruteforce with SecLists |
| httpx | 180s | Alive check — filters dead subdomains |

**SecurityTrails (optional):**
```bash
export SECURITYTRAILS_KEY=yourkey
bash run.sh -d target.com --subs
```

---

## Output Files {#output}

### Mode 1 (`-d`)
```
target.com/
  secrets_20260501_143022.json      ← all findings (machine-readable)
  report_20260501_143022.html       ← visual report (open in browser)
  total_subdomains.txt              ← all discovered subdomains
  alive_subdomains.txt              ← live subdomains only
  crawled-urls.txt                  ← in-scope URLs
  crawled-urls-outofscope.txt       ← out-of-scope (reference)
  endpoints.txt                     ← API endpoints from JS
```

### Mode 2 (`-l`) and Mode 3 (`-b`)
```
target-urlscan/    (or target-burpscan/)
  secrets_TIMESTAMP.json
  report_TIMESTAMP.html
```

### HTML Report

The HTML report opens in any browser and shows all findings organized by type with severity colors, full evidence, and PoC URLs for XSS/redirect findings.

---

## File Structure

```
HackLens/
  hacklens.py         ← main scanner (~3900 lines)
  install.sh          ← one-command installer
  update.sh           ← one-command updater
  run.sh              ← launcher (auto-created by install.sh)
  requirements.txt    ← Python dependencies
  README.md           ← this file
  TECHNICAL_DOCS.md   ← full technical documentation
  .gitignore
  logo.png
```

---

## Roadmap {#roadmap}

- [ ] Advanced XSS (DOM-based, blind XSS)
- [ ] SSRF detection
- [ ] WAF evasion
- [ ] SQL injection

---

## Contributing

Pull requests welcome. When adding secret patterns:
- Test against known FP sources (d3.js, three.js, SVG files)
- Use labeled context `"key_name": "value"` for generic patterns
- Add minimum length requirements
- Verify with runtime test cases

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

<p align="center">
  <b>Created by Yogesh Bhandage</b><br/>
  <a href="https://yogeshbhandage.com">yogeshbhandage.com</a><br/><br/>
  <i>Built with AI using original ideas by the author.</i><br/>
  <i>Hunt responsibly. 🎯</i>
</p>
