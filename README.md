<p align="center">
  <img src="logo.png" alt="HackLens Logo" width="380"/>
</p>

<h1 align="center">HackLens</h1>
<p align="center"><b>Web Recon & Vulnerability Scanner for Bug Bounty Hunters</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1.0-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Patterns-240%2B-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
</p>

<p align="center">
  Created by <a href="https://yogeshbhandage.com"><b>Yogesh Bhandage</b></a> | <a href="https://yogeshbhandage.com">yogeshbhandage.com</a><br/>
  <i>Built with AI using original ideas by the author</i>
</p>

---

## ⚠️ Disclaimer

> **For authorized security testing only.** Only use against targets you have explicit written permission to test. Unauthorized use is illegal.

---

## What Is HackLens?

One command. Full recon. Automated vulnerability detection.

```
bash run.sh -d target.com --deep --subs
```

```
Domain Input
  ├── Subdomain Enumeration   (10+ sources)
  ├── Alive Check             (httpx)
  ├── JS & URL Collection     (7 tools)
  ├── Secret Scanning         (240+ patterns)
  ├── Reflected XSS           (3-phase, 26 payloads, 8 contexts)
  ├── Open Redirect           (3-layer, 13 bypass probes)
  └── Information Disclosure  (70+ probes, 20+ response patterns)
```

Or skip recon with a pre-crawled URL list:

```
bash run.sh -l urls.txt
```

---

## What's New in v2.1

- **240+ secret patterns** — merged all patterns from Burp extension (camelCase variants, JS object patterns, OAuth tokens, AWS Session Token, Google OAuth, Databricks, Kubernetes, Terraform, `.env`/`.git` file exposure, and 50+ more)
- **Information Disclosure scanner** — 70+ probe paths, 20+ response patterns detecting debug mode, stack traces, Spring Boot Actuator, phpinfo, directory listing, Git exposure, SQL errors, API docs, backup files
- **`--no-info` flag** — skip info disclosure scanning
- **`-l` / `--list` mode fixed** — properly splits JS vs parameterised URLs, no scope filter, outputs to `<domain>-urlscan/` folder
- **26 XSS payloads across 8 contexts** — script tag injection, single/double quote breakout, js_code separators, svg, details, input autofocus
- **`XSS_REFLECT_PARAMS`** — 50+ known reflection parameter names tested first
- **`--version` flag**

---

## Installation

```bash
git clone https://github.com/yogeshbhandage/HackLens.git
cd HackLens
bash install.sh
source ~/.bashrc
```

To update:

```bash
bash update.sh
source ~/.bashrc
```

---

## Usage

### Mode 1 — Auto Recon (`-d`)

```bash
# Standard scan
bash run.sh -d target.com

# Deep + subdomains (recommended)
bash run.sh -d target.com --deep --subs

# Authenticated
bash run.sh -d target.com -c "session=abc123; csrf=xyz"

# Through Burp Suite
bash run.sh -d target.com -p http://127.0.0.1:8080

# Secrets only
bash run.sh -d target.com --no-xss --no-redirect --no-info
```

### Mode 2 — Pre-Crawled URL List (`-l`)

Skip all recon — feed HackLens a URL list you already have.

```bash
bash run.sh -l urls.txt
```

**When to use `-l`:**
- You have a Burp Suite HTTP history export (URLs only)
- You ran your own crawler and saved URLs
- Target blocks automated crawlers but you have authenticated URLs
- Re-scanning with updated patterns

**Prepare a URL list:**

```bash
katana -u https://target.com -jc -silent > urls.txt
gau target.com >> urls.txt
bash run.sh -l urls.txt -c "session=abc123"
```

**Output:** `<domain>-urlscan/` folder with JSON + HTML only

### Mode 3 — Burp XML Export (`-b`)

Feed a full Burp Suite XML export — includes GET params AND POST request bodies.

```bash
bash run.sh -b burp_export.xml
```

**How to export from Burp:**
```
Proxy → HTTP History → Select all → Right click → Save items → burp_export.xml
```

**What `-b` does that `-l` cannot:**
- **Pass A** — scans request bodies directly (no network): URL query params, POST form data, JSON body, multipart fields
- **Pass B** — replays every request and scans the response body for secrets
- Scans ALL response status codes: 200, 201, 301, 302, 400, 401, 403, 404, 500
- Tests POST body params for XSS (form data, JSON body, multipart)
- Tests GET params for XSS and open redirect
- Handles `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`
- Finding source shows status code: `[response 401]`, `[response 403]` etc.

**Output:** `<domain>-burpscan/` folder with JSON + HTML only

```bash
# With authentication cookies
bash run.sh -b burp_export.xml -c "session=abc123"

# Through Burp proxy to verify traffic
bash run.sh -b burp_export.xml -p http://127.0.0.1:8080

# Secrets only (skip active testing)
bash run.sh -b burp_export.xml --no-xss --no-redirect --no-info
```

> `-d`, `-l`, and `-b` are mutually exclusive — use one at a time.

---

## All Flags

| Flag | Description | Mode |
|------|-------------|------|
| `-d, --domain DOMAIN` | Target domain | Auto |
| `-l, --list FILE` | Pre-crawled URL list | List |
| `-b, --burp FILE` | Burp Suite XML export (GET + POST) | Burp |
| `--deep` | Wayback Machine, GAU, waybackurls | Auto |
| `--subs` | Subdomain enumeration | Auto |
| `--no-xss` | Skip XSS scanning | All |
| `--no-redirect` | Skip redirect scanning | All |
| `--no-info` | Skip info disclosure scanning | All |
| `-c, --cookies STR` | Cookie string e.g. `"session=abc"` | All |
| `-H, --headers HDR` | Extra headers | All |
| `-p, --proxy URL` | Proxy e.g. `http://127.0.0.1:8080` | All |
| `-w, --workers N` | Parallel workers (default: 5) | All |
| `--max-js N` | Max JS files (default: 2000) | Auto |
| `--max-pages N` | Max page URLs (default: 1000) | Auto |
| `--version` | Show version | — |

### Cookie Flag

```bash
# Correct — value only, no "Cookie:" prefix
bash run.sh -d target.com -c "PHPSESSID=abc123"
bash run.sh -d target.com -c "session=abc; csrf=xyz; token=123"

# Wrong
bash run.sh -d target.com -c "Cookie: PHPSESSID=abc123"
```

---

## Secret Detection — 240+ Patterns

### Categories

| Category | Patterns |
|---|---|
| ☁️ Cloud | AWS (Access Key, Secret, Session Token, MWS), Google API/OAuth, Azure (Storage, Client Secret, SAS), GCP SA |
| 🤖 AI | OpenAI (old+proj), Anthropic, Hugging Face |
| 💳 Payment | Stripe (live/test/restricted/webhook), Square, Razorpay, PayPal, Braintree |
| 🔐 Auth | JWT, Bearer, Basic Auth URLs, OAuth tokens |
| 🐙 VCS | GitHub (4 formats), GitLab PAT, NPM |
| 💬 Comms | Slack (bot/user/workspace/webhook), Discord, Telegram, Twilio, SendGrid, Mailgun |
| 🗄️ Database | MongoDB/PostgreSQL/MySQL/Redis URIs, PGPASSWORD, MySQL Password/Username/Server |
| 🔒 Crypto | AES Key/IV, Master Key, HMAC, PBKDF/scrypt, Encryption Password |
| 👤 Credentials | Admin Password, Password in JSON/code, Engine Server |
| 🔑 Keys | RSA, EC, DSA, PGP, OpenSSH, Generic Private Key, Certificate |
| 🛠️ DevOps | Datadog, New Relic, CircleCI, Terraform, Databricks, Kubernetes, DigitalOcean, Vercel, Fly.io |
| 🔏 SSO/OAuth | Auth0, Okta, OAuth Client ID/Secret, Access/Refresh/Bearer Token, Session ID |
| 📧 Email | SMTP Password/Host, Postmark, Resend, Mailchimp, Brevo, SparkPost |
| 🌐 SaaS | Shopify, Algolia, Mapbox, Firebase, Vault, Sentry DSN, Intercom, Pusher |
| 🔗 Web3 | Ethereum private key, Infura, Alchemy, WalletConnect |
| 📋 Productivity | Notion, Linear, Airtable, Jira, HubSpot, Salesforce, Webflow |
| 🧩 CamelCase | `apiKey`, `secretKey`, `authToken`, `clientSecret`, `privateKey`, `encryptionKey`, `dbPassword`, `accessToken`, `jwtSecret`, `webhookSecret`, `signingSecret`, `cookieSecret`, `sessionSecret`, `refreshToken` |
| 📦 JS Objects | `{"secret":"val"}`, `{"db_password":"val"}`, `{"access_token":"val"}` |
| 🔍 Exposure | `.env` in href/src, `.git` in href/src, UUID in sensitive context |
| 🌍 Social | Twitter Access/OAuth Token, Facebook Access Token |

---

## XSS Detection — 3-Phase, 26 Payloads, 8 Contexts

### Phase 1 — Canary Reflection
Injects unique alphanumeric canary. Skips if HTML-encoded or not reflected.

### Phase 2 — Context Detection
Detects where reflection lands. Skips Next.js `__NEXT_DATA__`, Nuxt, Redux JSON blocks.

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

### Phase 3 — Multi-Payload Per Context

| Context | Payloads (tries in order) |
|---------|--------------------------|
| `html_body` | `<img onerror>`, `><script>`, `<svg onload>`, `<details ontoggle>`, `<input onfocus>` |
| `attr_double` | `"><script>`, `"><img onerror>`, `" onfocus autofocus`, `" onmouseover` |
| `attr_single` | `'><script>`, `'><img onerror>`, `' onfocus autofocus`, `' onmouseover` |
| `attr_unquoted` | `><img onerror><x`, `><script></script><x` |
| `js_string_dq` | `";alert(1)//`, `"-alert(1)-"`, `"+alert(1)+"` |
| `js_string_sq` | `';alert(1)//`, `'-alert(1)-'`, `'+alert(1)+'` |
| `js_code` | `;/*canary*/alert(1)//`, `;alert(1)//`, `\nalert(1)//` |
| `url_param` | `javascript:alert(1)//`, `javascript://canary/%0aalert(1)` |

Every confirmed finding includes a **ready-to-use PoC URL**.

---

## Open Redirect — 3-Layer, 13 Bypass Probes

**Canary domain:** `evil.com`

**Key rule:** `evil.com` must be the **destination host** — not just a query param value.

```
❌ FP: Location: https://target.com/login?next=https://evil.com
✅ REAL: Location: https://evil.com/malicious
```

| Layer | Method |
|-------|--------|
| 1 | Raw `Location` header (`allow_redirects=False`) |
| 2 | JS redirect sinks in body (`window.location`, `location.href`, meta-refresh) |
| 3 | Full redirect chain follow |

**Severities:**
- `[CONFIRMED]` — browser actually redirected to evil.com
- `[POSSIBLE]` — JS assignment or meta-refresh found
- `[One-Click LOW]` — `<a href>` pointing to evil.com

---

## Information Disclosure — 70+ Probes

Probes known-sensitive paths and checks responses for disclosure patterns.

**Probe paths include:**
- Spring Boot Actuator (`/actuator/env`, `/actuator/heapdump`, 10+ endpoints)
- Laravel (`/_ignition`, `/telescope`, `/horizon`)
- PHP (`/phpinfo.php`, `/info.php`)
- Config files (`/.env`, `/config.json`, `/config.yml`, `/web.config`, `/application.properties`)
- Git/SVN (`/.git/HEAD`, `/.git/config`, `/.svn/entries`)
- API Docs (`/swagger-ui`, `/api-docs`, `/openapi.json`, `/graphql`, `/graphiql`)
- Backup files (`/backup.sql`, `/db.sql`, `/backup.zip`)
- Admin panels (`/admin`, `/wp-admin`, `/administrator`, `/cpanel`)
- Log files (`/error.log`, `/access.log`, `/debug.log`)

**Response patterns detect:**
- Python/PHP/Rails/Django/Laravel/Node.js stack traces
- `DEBUG=True` pages
- Server/framework version disclosure
- Private keys in response
- Hardcoded credentials in response
- Environment variables exposed
- Directory listing enabled
- Git repository accessible
- SQL error messages
- phpinfo() output
- GraphQL introspection enabled
- Spring Boot Actuator data
- SQL dump accessible

Use `--no-info` to skip.

---

## Subdomain Enumeration — 10+ Sources

| Source | Type |
|--------|------|
| crt.sh | Certificate Transparency (API) |
| HackerTarget | Passive DNS (API) |
| RapidDNS | DNS search (API) |
| AlienVault OTX | Threat intelligence (API) |
| URLScan.io | Scan history (API) |
| ThreatCrowd | Threat intelligence (API) |
| DNSDumpster | DNS recon (scrape) |
| Subfinder | Tool |
| Assetfinder | Tool |
| Amass | Tool |
| Chaos | Tool (needs API key) |
| MassDNS | DNS bruteforce (optional) |
| httpx | Alive check |

---

## Output Files

### `-d` mode
```
target.com/
  secrets_TIMESTAMP.json
  report_TIMESTAMP.html
  total_subdomains.txt
  alive_subdomains.txt
  crawled-urls.txt
  crawled-urls-outofscope.txt
  endpoints.txt
```

### `-l` mode
```
target-urlscan/
  secrets_TIMESTAMP.json
  report_TIMESTAMP.html
```

---

## Severity Levels

| | Level | Examples |
|---|---|---|
| 🔴 | CRITICAL | AWS keys, private keys, Stripe live, OpenAI, DB URIs with creds, JWT, OAuth Client Secret |
| 🟠 | HIGH | Google API, Slack tokens, SendGrid, S3, GitHub, Refresh Token, SMTP Password |
| 🟡 | MEDIUM | Webhooks, Firebase, Shopify, Session ID, CamelCase tokens, JS Object secrets |
| 🔵 | LOW | MySQL Server, Internal IPs, Azure Client ID, Google Client ID, Certificate |
| ℹ️ | INFO | Stripe test keys |

---

## Roadmap

- [ ] Advanced XSS (DOM-based, blind XSS)
- [ ] SSRF detection
- [ ] WAF evasion
- [ ] Command injection
- [ ] SQL injection

---

## File Structure

```
HackLens/
  hacklens.py         ← main scanner (2900+ lines)
  install.sh          ← one-command installer
  update.sh           ← one-command updater
  run.sh              ← launcher (auto-created by install.sh)
  requirements.txt    ← Python dependencies
  README.md
  TECHNICAL_DOCS.md
  .gitignore
  logo.png
```

---

## Updating

```bash
cd HackLens
bash update.sh
source ~/.bashrc
```

Or manually:

```bash
git pull origin main
bash install.sh
source ~/.bashrc
```

---

## License

MIT — free to use, modify, distribute with attribution.

---

<p align="center">
  <b>Yogesh Bhandage</b> | <a href="https://yogeshbhandage.com">yogeshbhandage.com</a><br/>
  <i>Built with AI using original ideas by the author. Hunt responsibly. 🎯</i>
</p>
