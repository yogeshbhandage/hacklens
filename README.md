<p align="center">
  <img src="logo.png" alt="HackLens Logo" width="380"/>
</p>

<h1 align="center">HackLens</h1>

<p align="center">
  <b>Web Recon & Vulnerability Scanner for Bug Bounty Hunters</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/Purpose-Bug%20Bounty-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Patterns-162-red?style=flat-square"/>
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

## What Is HackLens?

HackLens is a one-command automated web reconnaissance and vulnerability scanner built for bug bounty hunters and penetration testers.

**Enter a domain → HackLens does everything:**

```
 Domain Input
     │
     ├── Subdomain Enumeration  (crt.sh, Subfinder, Assetfinder, Amass)
     │
     ├── JS & URL Collection    (7 sources: Katana, GAU, Hakrawler, SubJS,
     │                           Wayback Machine, waybackurls, direct crawl)
     │
     ├── Secret Scanning        (162 regex patterns across JS, HTML, JSON,
     │                           config files, .env, API endpoints)
     │
     ├── Reflected XSS          (3-phase: canary → context detection
     │                           → context-specific payload)
     │
     └── Open Redirect          (3-layer: Location header → body JS sinks
                                 → redirect chain, 13 bypass probes)
```

---

## Features

### 🔑 Secret Detection — 162 Patterns

Scans **JS files, HTML pages, JSON APIs, config endpoints** (`.env`, `.git/config`, `package.json`, `/actuator/env`, etc.)

| Category | Examples |
|---|---|
| ☁️ Cloud | AWS Access/Secret, Google API, Azure Storage/Client Secret, GCP SA |
| 🤖 AI / ML | OpenAI (old + proj), Anthropic, Hugging Face |
| 💳 Payment | Stripe (live/test/webhook), PayPal, Braintree, Square, Razorpay |
| 🔐 Auth | JWT, Bearer tokens, Basic Auth in URLs |
| 🐙 VCS | GitHub (4 formats), GitLab PAT, NPM token |
| 💬 Comms | Slack token/webhook, Discord token/webhook, Telegram, Twilio, SendGrid |
| 🗄️ Database | MongoDB/PostgreSQL/MySQL/Redis URIs with credentials |
| 🔒 Crypto | AES IV, encryption keys, HMAC secrets, crypto salts |
| 👤 Credentials | Hardcoded usernames, passwords, credential pairs |
| 🔑 SSH / Keys | RSA, EC, PGP, OpenSSH private keys |
| 🏗️ DevOps | Datadog, New Relic, Dynatrace, CircleCI, Vercel, Netlify, Fly.io |
| 🔏 SSO | Auth0, Okta, OneLogin, Keycloak |
| 📧 Email | Postmark, Resend, Mailchimp, Brevo, SparkPost |
| 🔗 Web3 | Ethereum private key, Infura, Alchemy, WalletConnect |
| 📋 Productivity | Notion, Linear, Airtable, Jira, HubSpot, Salesforce, 10+ more |

**Proactive endpoint checks** (fetched even if not crawled):
```
/.env  /.env.local  /.env.production  /.git/config
/config.json  /package.json  /actuator/env
/api/config  /api/v1/config  /phpinfo.php
```

### ⚡ Reflected XSS — 3-Phase Zero FP Design

1. **Canary injection** — unique random string, no HTML/JS meaning
2. **Context detection** — finds exactly where reflection lands:
   `html_body`, `attr_double`, `attr_single`, `attr_unquoted`, `js_string_dq`, `js_string_sq`, `js_code`, `url_param`
3. **Context-specific payload** — minimal exploitable payload for that context

Automatically detects and skips Next.js `__NEXT_DATA__`, Nuxt `__NUXT_DATA__`, Redux, and other JSON data blocks that look like JS but aren't executable.

Every finding shows a **ready-to-use PoC URL**.

### ↩ Open Redirect — 3-Layer Detection

- **Layer 1**: Raw `Location` header (no redirect following) — highest confidence
- **Layer 2**: JS redirect sinks in HTML body (`window.location`, `location.href`, meta-refresh)
- **Layer 3**: Full redirect chain follow

**13 bypass probe variants** — tab bypass, protocol-relative, `@` confusion, multiple slashes, fragment confusion, credential confusion, and more.

**Canary domain:** `evil.com` — industry-standard test domain

### 🌐 Subdomain Enumeration
crt.sh · Subfinder · Assetfinder · Amass

### 📡 URL Collection — 7 Sources
Katana · GAU · Hakrawler · SubJS · Wayback Machine CDX · waybackurls · Direct crawl

### 🎯 Scope Enforcement
All scanning (secrets, XSS, redirects) is strictly limited to the target domain and its subdomains. Out-of-scope URLs like `youtube.com`, `twitter.com` are never tested.

### 📁 Per-Target Output Folder
```
target.com/
  secrets_TIMESTAMP.json          ← machine-readable findings
  report_TIMESTAMP.html           ← visual report (open in browser)
  total_subdomains.txt            ← all discovered subdomains
  crawled-urls.txt                ← in-scope URLs
  crawled-urls-outofscope.txt     ← out-of-scope URLs (reference)
  endpoints.txt                   ← API endpoints from JS
```

---

## Installation

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

If any tools show ✗ after install:
```bash
bash fix_tools.sh
source ~/.bashrc
```

---

## Usage

```bash
# Basic scan
bash run.sh -d target.com

# Deep scan (Wayback Machine, GAU, waybackurls)
bash run.sh -d target.com --deep

# Deep + subdomain enumeration
bash run.sh -d target.com --deep --subs

# Authenticated scan
bash run.sh -d target.com -c "session=abc123; csrf=xyz"

# Through Burp Suite proxy
bash run.sh -d target.com -p http://127.0.0.1:8080

# Custom headers
bash run.sh -d target.com -H "Authorization: Bearer token123"

# Secrets only (skip active vuln testing)
bash run.sh -d target.com --no-xss --no-redirect

# More workers (faster)
bash run.sh -d target.com -w 20

# Full power
bash run.sh -d target.com --deep --subs -w 20
```

### All Options

```
  -d, --domain        Target domain  (required)
  --deep              Enable Wayback Machine, GAU, waybackurls
  --subs              Enumerate & scan subdomains
  --no-xss            Skip XSS scanning
  --no-redirect       Skip open redirect scanning
  -c, --cookies       Cookie string
  -H, --headers       Extra request headers
  -p, --proxy         Proxy URL (e.g. http://127.0.0.1:8080)
  -w, --workers       Parallel workers (default: 10)
```

---

## Sample Output

```
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ...

  Target     : target.com
  Output dir : target.com/
  Mode       : Deep + Subdomains + XSS + OpenRedirect

[+] Total subdomains: 47
[+] Subdomains saved → target.com/total_subdomains.txt
[+] JS files: 84  |  Page URLs: 412
[+] Crawled URLs saved → target.com/crawled-urls.txt

  [CRITICAL] AWS Access Key
  Source : https://target.com/static/js/main.chunk.js (line 1247)
  Value  : AKIAIOSFODNN7EXAMPLE

  [HIGH] Slack Token
  Source : https://target.com/assets/js/app.js (line 892)
  Value  : xoxb-123456789012-...

  [Reflected XSS] https://target.com/search?query=<img src=x id=SHXSS onerror=alert(1)>
  Param   : query
  Context : html_body | Payload verified

  [Open Redirect [CONFIRMED]] https://target.com/logout?next=https://evil.com
  Param   : next
  Detail  : off-site Location header | HTTP 302

  🔑 8 secret(s)   ⚡ 1 XSS   ↩ 1 redirect
  Output dir : target.com/
```

---

## Severity Levels

| | Level | Examples |
|---|---|---|
| 🔴 | CRITICAL | AWS keys, Stripe live, private keys, OpenAI, DB URIs, JWT, GitHub tokens |
| 🟠 | HIGH | Google API, Slack tokens, SendGrid, S3 buckets, access tokens, Sentry |
| 🟡 | MEDIUM | Webhooks, Heroku, Firebase, Shopify, Algolia, Vault tokens |
| 🔵 | LOW | Hardcoded passwords, internal IPs, Basic Auth URLs |
| ℹ️ | INFO | AWS ARNs, service account references |

---

## Roadmap

- [ ] **Advanced XSS** — DOM-based XSS, stored XSS indicators, blind XSS
- [ ] **SSRF Detection** — internal service probing via URL parameters
- [ ] **WAF Evasion** — automatic payload encoding, bypass techniques
- [ ] **Command Injection** — OS command injection detection
- [ ] **SQL Injection** — error-based and blind SQLi detection

---

## File Structure

```
HackLens/
  hacklens.py           ← main scanner
  install.sh            ← one-command installer
  fix_tools.sh          ← fix PATH / reinstall missing tools
  run.sh                ← launcher (created by install.sh)
  requirements.txt      ← Python dependencies
  README.md             ← this file
  TECHNICAL_DOCS.md     ← detailed technical documentation
  logo.png              ← HackLens logo
```

---

## Contributing

Pull requests are welcome. Please:
- Add tests for new patterns
- Check patterns against known FP sources (d3.js, three.js, etc.)
- Follow the labeled-context pattern design for generic detections

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
