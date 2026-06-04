<p align="center">
  <img src="logo.png" alt="HackLens" width="420"/>
</p>

<h1 align="center">HackLens</h1>

<p align="center">
  <b>Automated Web Recon &amp; Vulnerability Scanner for Bug Bounty Hunters</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/patterns-240+-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Kali%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

<p align="center">
  By <a href="https://yogeshbhandage.com"><b>Yogesh Bhandage</b></a>
  &nbsp;·&nbsp;
  <a href="https://yogeshbhandage.com">yogeshbhandage.com</a>
  <br/>
  <sub>Built with AI using original ideas by the author</sub>
</p>

---

> ⚠️ **For authorized security testing only.**
> Only use against targets you have explicit written permission to test — bug bounty programs, your own apps, or intentional lab environments.
> Unauthorized use is illegal. The author assumes no responsibility for misuse.

---

## What Is HackLens?

HackLens is a bug bounty automation tool that runs from your terminal. Point it at a domain and it handles reconnaissance, URL collection, and vulnerability scanning end-to-end — outputting a JSON report and a visual HTML report you can review and submit.

```bash
bash run.sh -d target.com --deep --subs
```

It will automatically:

- Discover subdomains from 12+ sources and filter for alive hosts
- Crawl every subdomain for JavaScript files, API endpoints, and page URLs
- Scan all discovered files against 240+ secret detection patterns
- Test every reflected parameter for XSS with 26 context-aware payloads
- Test redirect parameters for open redirects with 13 bypass probes
- Probe 70+ known-sensitive paths for information disclosure
- Test all parameters for SSTI across 6 template engine formats
- Test all parameters for command injection using output, timing, and OOB techniques

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [All Flags](#all-flags)
- [Secret Detection](#secret-detection)
- [XSS Detection](#xss-detection)
- [Open Redirect](#open-redirect)
- [Information Disclosure](#information-disclosure)
- [SSTI Detection](#ssti-detection)
- [Command Injection](#command-injection)
- [Subdomain Enumeration](#subdomain-enumeration)
- [Output](#output)
- [Updating](#updating)
- [Roadmap](#roadmap)

---

## Installation

**Requirements:** Python 3.8+, Go 1.18+, Linux or macOS (Kali recommended)

```bash
git clone https://github.com/yogeshbhandage/HackLens.git
cd HackLens
bash install.sh
source ~/.bashrc
```

The installer handles everything — Python virtual environment, Go setup, and all recon tools. It is safe to re-run.

**Check everything installed correctly:**
```bash
bash run.sh --version
# HackLens v3.0.0
```

If any tools show ✗ after install:
```bash
source ~/.bashrc   # fix PATH first
bash install.sh    # re-run, skips already-installed tools
```

---

## Quick Start

```bash
# Full scan — best starting point for any target
bash run.sh -d target.com --deep --subs

# Authenticated scan
bash run.sh -d target.com --deep --subs \
  -c "session=abc123; csrf=xyz"

# Through Burp Suite proxy so you can watch traffic
bash run.sh -d target.com --deep --subs \
  -c "session=abc123" -p http://127.0.0.1:8080

# Scan your Burp history (GET + POST bodies)
bash run.sh -b burp_export.xml -c "session=abc123"

# Scan a URL list you already have
bash run.sh -l urls.txt

# Secrets only — very fast
bash run.sh -d target.com --no-xss --no-redirect --no-info
```

---

## Scan Modes

HackLens has three modes depending on what input you have. Use one at a time.

---

### Mode 1 — Auto Recon &nbsp;`-d`

The default mode. Discovers everything on its own.

```bash
bash run.sh -d target.com
bash run.sh -d target.com --deep --subs
bash run.sh -d target.com --deep --subs --ssti --ci
```

**What happens:**

```
STEP 0   Subdomain enumeration (12+ sources)
STEP 0b  Alive check with httpx
STEP 1   JS and URL collection across all subdomains
STEP 2   Endpoint extraction from JS files
STEP 3   Secret scanning (240+ patterns)
STEP 4   Reflected XSS testing
STEP 5   Open redirect testing
STEP 6   Information disclosure probing
STEP 7   SSTI scanning          (with --deep or --ssti)
STEP 8   Command injection       (with --deep or --ci)
```

**`--deep`** adds Wayback Machine, GAU, and waybackurls to URL collection — and automatically enables SSTI and CI scanning.

**`--subs`** enables full subdomain enumeration before scanning.

**Output:** `target.com/` folder with all files.

---

### Mode 2 — URL List &nbsp;`-l`

Skip discovery. Scan a list of URLs you already have.

```bash
bash run.sh -l urls.txt
bash run.sh -l urls.txt -c "session=abc123"
bash run.sh -l urls.txt --ssti --ci
```

**How to build a URL list:**
```bash
# From your own crawl
katana   -u https://target.com -jc -silent > urls.txt
gau         target.com                    >> urls.txt
waybackurls target.com                    >> urls.txt

# Or export URLs from Burp:
# Proxy → HTTP History → Select all → Right click → Copy URLs → paste to file
```

**What it scans:**
1. Splits URLs into JS files, pages with params, and pages without params
2. Secret scan — all URLs
3. XSS — all parameterised URLs plus endpoints extracted from JS
4. Open redirect — all parameterised URLs
5. Information disclosure — probes primary domain + checks collected pages
6. SSTI and CI — if `--ssti` / `--ci` / `--deep` passed

**Best used when:** you have an authenticated session, the target blocks automated crawlers, you want to re-scan with updated patterns, or you already have URLs from manual browsing.

**Output:** `target-urlscan/` — JSON and HTML report only.

---

### Mode 3 — Burp XML Export &nbsp;`-b`

The most thorough mode. Import a complete Burp Suite HTTP history export — includes full request and response data for every request you made.

**Export from Burp:**
```
Proxy → HTTP History → Select all → Right click → Save items → export.xml
```

```bash
bash run.sh -b burp_export.xml
bash run.sh -b burp_export.xml -c "session=abc123"
bash run.sh -b burp_export.xml --ssti --ci
```

**What it does that `-d` and `-l` cannot:**

- **Scans request bodies directly** (Pass A — no network needed) — catches secrets hardcoded in POST bodies like `{"api_key":"sk_live_..."}`
- **Replays every request** and scans responses — ALL status codes: 200, 201, 302, 401, 403, 500
- **Tests POST body parameters for XSS** — form data, JSON body, multipart fields
- Handles `application/x-www-form-urlencoded`, `application/json`, and `multipart/form-data`
- Strips hop-by-hop headers before replaying so requests don't get rejected

**Output:** `target-burpscan/` — JSON and HTML report only.

> `-d`, `-l`, and `-b` are mutually exclusive.

---

## All Flags

| Flag | Description | Mode |
|------|-------------|------|
| `-d, --domain DOMAIN` | Target domain | Auto |
| `-l, --list FILE` | Pre-crawled URL list file | List |
| `-b, --burp FILE` | Burp Suite XML export | Burp |
| `--deep` | Deep crawl + auto-enables SSTI and CI | Auto |
| `--subs` | Full subdomain enumeration | Auto |
| `--ssti` | SSTI scanning | All |
| `--ci` | Command injection scanning | All |
| `--ci-server DOMAIN` | Interactsh OOB server for blind CI | All |
| `--no-xss` | Skip XSS scanning | All |
| `--no-redirect` | Skip open redirect scanning | All |
| `--no-info` | Skip information disclosure | All |
| `-c, --cookies STR` | Cookie string | All |
| `-H, --headers HDR [HDR...]` | Extra request headers | All |
| `-p, --proxy URL` | Proxy URL | All |
| `-w, --workers N` | Parallel workers (default: 5) | All |
| `--max-js N` | Max JS files to scan (default: 2000) | Auto |
| `--max-pages N` | Max page URLs (default: 1000) | Auto |
| `--version` | Print version and exit | — |

**Cookie flag — correct format:**
```bash
# ✅ Pass value only, no header name
bash run.sh -d target.com -c "PHPSESSID=abc123"
bash run.sh -d target.com -c "session=abc; csrf=xyz; remember=1"

# ❌ Wrong — don't include "Cookie:"
bash run.sh -d target.com -c "Cookie: PHPSESSID=abc123"
```

---

## Secret Detection

HackLens scans JavaScript files, HTML pages, JSON API responses, `.env` files, TypeScript, source maps, config endpoints, and HTTP response bodies — using 240+ regular expression patterns.

### Coverage

| Category | Patterns Include |
|----------|-----------------|
| ☁️ **Cloud** | AWS Access Key, Secret Key, Session Token, MWS Token · Google API Key, OAuth Token, Client Secret · Azure Storage Key, Client Secret, SAS Token · GCP Service Account JSON |
| 🤖 **AI / ML** | OpenAI (classic `sk-...T3BlbkFJ` and project `sk-proj-` formats) · Anthropic · HuggingFace |
| 💳 **Payment** | Stripe (live / test / restricted / webhook) · Square · Razorpay · PayPal · Braintree |
| 🔐 **Auth** | JWT (3-part structure validated) · Bearer tokens · OAuth (access / refresh / client) · Session IDs · Basic Auth in URLs |
| 🐙 **Source Control** | GitHub (PAT, OAuth, App, Fine-Grained — 4 formats) · GitLab PAT · NPM token |
| 💬 **Communication** | Slack (bot / user / workspace / webhook) · Discord · Telegram bot · Twilio · SendGrid · Mailgun |
| 🗄️ **Database** | MongoDB, PostgreSQL, MySQL, Redis URIs with embedded credentials · PGPASSWORD · MySQL password / username / server / host · Engine Server · Encryption Password |
| 🔒 **Cryptography** | AES Key · Master Key · HMAC Secret · PBKDF / scrypt · Signing Key |
| 🔑 **Private Keys** | RSA · EC · DSA · PGP · OpenSSH · Generic Private Key · Certificate |
| 🛠️ **DevOps / CI-CD** | Datadog · New Relic · Databricks (`dapi` prefix) · Kubernetes · Terraform · CircleCI · DigitalOcean · Vercel · Fly.io · Netlify |
| 📧 **Email** | SMTP credentials · Postmark · Resend · Mailchimp · Brevo · SparkPost |
| 🌐 **SaaS** | Shopify · Algolia · Mapbox · Firebase · HashiCorp Vault · Sentry DSN · Intercom · Pusher |
| 🔗 **Web3** | Ethereum private key · Infura · Alchemy · WalletConnect |
| 📋 **Productivity** | Notion · Linear · Airtable · Jira · HubSpot · Salesforce · Webflow |
| 🧩 **CamelCase** | `apiKey` `secretKey` `authToken` `clientSecret` `privateKey` `encryptionKey` `dbPassword` `accessToken` `jwtSecret` `webhookSecret` `signingSecret` `cookieSecret` `sessionSecret` `refreshToken` |
| 📦 **JS Objects** | `{"secret":"value"}` · `{"db_password":"value"}` · `{"access_token":"value"}` |
| 🔍 **File Exposure** | `.env` in href/src · `.git` in href/src · UUID in sensitive key context |

### Severity Levels

| | Level | Examples |
|---|---|---|
| 🔴 | **CRITICAL** | AWS Access/Secret Key, Stripe live, private keys, OpenAI, DB URIs, OAuth Client Secret |
| 🟠 | **HIGH** | Google API, Slack tokens, GitHub tokens, SendGrid, SMTP password, Refresh Token |
| 🟡 | **MEDIUM** | Webhooks, Firebase, Session ID, CamelCase tokens, JS object secrets |
| 🔵 | **LOW** | MySQL host/server, internal IPs, SMTP host, certificate PEM |
| ℹ️ | **INFO** | Stripe test keys, ARNs, service account identifiers |

### False Positive Filtering

Every match is tested against 8 FP filters before reporting: code reference patterns, placeholder values (`changeme`, `your_key_here`), low entropy values, JS identifier patterns, version strings, data URIs, raw base64 blobs, and per-pattern structural validation.

---

## XSS Detection

### How It Works

**Phase 1 — Canary Reflection**
A unique random token is injected as the parameter value. If it comes back HTML-encoded or doesn't appear at all, the parameter is skipped — no point testing further.

**Phase 2 — Context Detection**
The scanner inspects the 500 characters around the canary to determine exactly where it landed.

| Context | Where the value reflects |
|---------|--------------------------|
| `html_body` | Between HTML tags |
| `attr_double` | Inside `value="..."` |
| `attr_single` | Inside `value='...'` |
| `attr_unquoted` | Inside `value=...` |
| `js_string_dq` | Inside a JS double-quoted string |
| `js_string_sq` | Inside a JS single-quoted string |
| `js_code` | Directly inside a `<script>` block |
| `url_param` | Inside href / src / action attributes |

Next.js `__NEXT_DATA__`, Nuxt `__NUXT_DATA__`, Redux state, and other JSON data blocks embedded in page source are automatically detected and skipped — they look like JS but are never executed.

**Phase 3 — Context-Specific Payloads**
Multiple payloads are tried in sequence for the detected context. The first one confirmed in the response is reported. False positive checks are applied per context type — for example, attribute contexts verify the payload is not HTML-entity-encoded, and JS code contexts verify the injection is not still inside a quoted string.

Every confirmed finding includes a **ready-to-use PoC URL**.

### Payload Table

| Context | Payloads Tried |
|---------|---------------|
| `html_body` | `<img onerror=alert(1)>` · `><script>alert(1)//` · `<svg onload=alert(1)>` · `<details ontoggle=alert(1) open>` · `<input onfocus=alert(1) autofocus>` |
| `attr_double` | `"><script>alert(1)//` · `"><img onerror=alert(1)>` · `" onfocus=alert(1) autofocus` · `" onmouseover=alert(1)` |
| `attr_single` | `'><script>alert(1)//` · `'><img onerror=alert(1)>` · `' onfocus=alert(1) autofocus` · `' onmouseover=alert(1)` |
| `attr_unquoted` | `><img onerror=alert(1)><x` · `><script>alert(1)//</script><x` |
| `js_string_dq` | `";alert(1)//` · `"-alert(1)-"` · `"+alert(1)+"` |
| `js_string_sq` | `';alert(1)//` · `'-alert(1)-'` · `'+alert(1)+'` |
| `js_code` | `;/*canary*/alert(1)//` · `;alert(1)//` · `\nalert(1)//` |
| `url_param` | `javascript:alert(1)//` · `javascript://canary/%0aalert(1)` |

XSS is also tested on POST body parameters when using `-b` Burp mode.

---

## Open Redirect

**Core rule:** `evil.com` must be the **destination host** of the redirect — not just a value appearing in a query parameter.

```
❌  Not vulnerable:  https://app.target.com/login?next=https://evil.com
                     (evil.com is a param value, target.com is still the destination)

✅  Vulnerable:      Location: https://evil.com/page
                     (browser sent to evil.com)
```

**3 detection layers:**

1. Raw `Location` header check with `allow_redirects=False` — highest confidence
2. JavaScript redirect sinks in response body — `window.location.href`, `location.replace()`, `location.assign()`, meta-refresh, form action
3. Full redirect chain follow — checks every hop

**13 bypass probes per parameter:** standard HTTPS, HTTP, protocol-relative (`//evil.com`), trailing slash, path traversal (`/%2F..`), `@` confusion, multiple slashes, tab prefix, missing slashes, horizontal tab, credential confusion (two variants), fragment confusion.

**Severity:**
- `[CONFIRMED]` — browser actually redirected to evil.com — HIGH
- `[POSSIBLE]` — JS sink or meta-refresh pointing to evil.com — MEDIUM
- `[One-Click LOW]` — `<a href>` pointing to evil.com, requires user click — LOW

---

## Information Disclosure

HackLens probes 70+ known-sensitive paths on the target domain and all discovered subdomains, then checks every response for 20+ disclosure patterns.

**Paths probed include:**

- Spring Boot Actuator — `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/beans`, `/actuator/mappings`, `/actuator/logfile`, `/actuator/sessions`, and more
- Laravel — `/_ignition/health-check`, `/telescope`, `/telescope/requests`, `/horizon`
- PHP — `/phpinfo.php`, `/info.php`, `/test.php`
- Config files — `/.env`, `/.env.local`, `/.env.production`, `/.env.staging`, `/.env.backup`, `/config.json`, `/config.yml`, `/web.config`, `/application.properties`
- Source exposure — `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/package.json`, `/composer.json`
- API documentation — `/swagger-ui`, `/swagger-ui.html`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/graphql`, `/graphiql`, `/redoc`
- Backup files — `/backup.sql`, `/db.sql`, `/dump.sql`, `/backup.zip`, `/www.zip`
- Admin panels — `/admin`, `/wp-admin`, `/wp-login.php`, `/administrator`, `/cpanel`
- Log files — `/error.log`, `/access.log`, `/debug.log`, `/application.log`

**Response patterns detected:**

Python, PHP, Rails, Django, Laravel, and Node.js exception stack traces · Server and framework version disclosure · X-Powered-By header · Private keys in response · Hardcoded credentials · Environment variables exposed · Directory listing enabled · Git HEAD accessible · SQL error messages · phpinfo() output · GraphQL introspection enabled · Spring Boot Actuator config data · SQL dump files · Internal file paths

Findings are deduplicated intelligently — header-based findings like X-Powered-By are reported once per domain, not once per URL.

Use `--no-info` to skip.

---

## SSTI Detection

**Reflected (primary method):**

Three independent math expressions must all evaluate correctly — one coincidence is possible, three is not.

```
{{456*765}} → response must contain 348840
{{89*45}}   → response must contain 4005
{{317*213}} → response must contain 67521
```

Tested across 6 engine formats in every parameter:

| Format | Engine |
|--------|--------|
| `{{N*M}}` | Jinja2, Twig, Tornado |
| `${N*M}` | Freemarker, Velocity |
| `*{N*M}` | Spring EL, Thymeleaf |
| `<%=N*M%>` | ERB, Mako |
| `{math equation="N*M"}` | Smarty |

Once confirmed, the exact engine is fingerprinted: `{{7*'7'}}` returns `7777777` for Jinja2 and `49` for Twig.

**Blind time-based (fallback):**

When the application processes templates but never shows output in the response, HackLens falls through to time-based detection. Engine-specific sleep payloads are injected. Both sleep 5 and sleep 3 must confirm before reporting — eliminates timing jitter false positives.

Engines covered for blind detection: Jinja2 (Python), Twig (PHP), Freemarker (Java), ERB (Ruby), Spring EL, Velocity.

Enable with `--ssti` or automatically with `--deep`.

---

## Command Injection

**Method 1 — Output-based:**
Injects 12 separators combined with 16 commands. Response is compared against a clean baseline — patterns must appear *new* in the injected response to count. This eliminates false positives from pages that happen to contain words like "root".

Commands include: `id`, `whoami`, `cat /etc/passwd`, `uname -a`, `ls -la`, `pwd`, `env` (Unix) and `whoami`, `dir`, `ver`, `ipconfig`, `type C:\Windows\win.ini` (Windows).

Output patterns are strict: `uid=N(name) gid=N` format only for id output, full colon-separated `/etc/passwd` format for passwd, kernel build number required for uname, drive letter format for Windows dir.

**Method 2 — Time-based blind (double-verified):**
Injects sleep payloads via each separator. Sleep 5 must delay the response, then sleep 3 must also delay it. Different delay values eliminate network jitter as a source of false positives.

**Method 3 — OOB via interactsh:**
At scan start, HackLens registers with an interactsh server and receives a unique callback domain. DNS and HTTP callback payloads are injected into every testable parameter. After injection, the interactsh API is polled to confirm whether a callback was received — works for completely blind injection where there is no output and no timing difference.

```bash
# Self-hosted server (recommended for reliability)
bash run.sh -d target.com --deep --ci-server your.interactsh.server

# Public server used automatically when --deep is passed
bash run.sh -d target.com --deep
```

**12 injection separators:** `;` `|` `&&` `||` `\n` `\r\n` `$(cmd)` `` `cmd` `` `%0a` `%0a%0d` `&` `\x0a`

**Params automatically skipped** (never CI sinks): `utm_source`, `utm_medium`, `ref`, `referrer`, `q`, `search`, `id`, `slug`, `page`, `lang`, `sort`, `token`, `csrf`, and 20+ more analytics and display parameters that get reflected in HTML but are never executed.

Enable with `--ci` or automatically with `--deep`.

---

## Subdomain Enumeration

### Sources

**No install required — pure HTTP API calls:**

| Source | Notes |
|--------|-------|
| crt.sh | Certificate Transparency logs — two queries per scan |
| HackerTarget | Passive DNS — detects rate limits |
| RapidDNS | DNS search |
| AlienVault OTX | Both `passive_dns` and `url_list` endpoints |
| URLScan.io | Scan history — up to 300 results |
| ThreatCrowd | Threat intelligence |
| Certspotter | Reliable CT log API |
| Wayback CDX | Archived URLs — subdomains extracted from all archived URLs |
| DNSDumpster | DNS recon (scraped) |

**Tool-based (installed by `install.sh`):**

| Tool | Notes |
|------|-------|
| Subfinder | `-all` flag — uses all available passive sources |
| Assetfinder | Fast |
| Amass | Passive, thorough — 300 second timeout |
| Chaos | Requires `export CHAOS_KEY=yourkey` |
| MassDNS | DNS bruteforce with SecLists top-5000 wordlist — optional |
| httpx | Alive check — removes dead subdomains before scanning |

**SecurityTrails (optional, needs free API key):**
```bash
export SECURITYTRAILS_KEY=yourkey
bash run.sh -d target.com --subs
```

After collection, all subdomains are normalised — schemes, ports, wildcard prefixes, and case inconsistencies are stripped before deduplication. httpx then filters to alive subdomains only, which are saved separately in `alive_subdomains.txt`.

---

## Output

### Auto mode (`-d`)

```
target.com/
├── secrets_20260601_143022.json     all findings in machine-readable format
├── report_20260601_143022.html      visual report — open in any browser
├── total_subdomains.txt             every subdomain discovered
├── alive_subdomains.txt             live subdomains only
├── crawled-urls.txt                 in-scope URLs collected during crawl
├── crawled-urls-outofscope.txt      out-of-scope URLs for reference
└── endpoints.txt                    API endpoints extracted from JS files
```

### List mode (`-l`) and Burp mode (`-b`)

```
target-urlscan/   or   target-burpscan/
├── secrets_TIMESTAMP.json
└── report_TIMESTAMP.html
```

### HTML Report

The HTML report opens in any browser. Findings are organised by type with severity colour-coding. XSS and redirect findings include a ready-to-use PoC URL. SSTI and CI findings include the confirming payload and evidence.

### JSON Structure

```json
{
  "domain": "target.com",
  "timestamp": "20260601_143022",
  "secrets":                { "total": 3, "findings": [...] },
  "xss":                    { "total": 1, "findings": [...] },
  "redirects":              { "total": 2, "findings": [...] },
  "ssti_ci":                { "total": 1, "findings": [...] },
  "information_disclosure": { "total": 4, "findings": [...] }
}
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

## File Structure

```
HackLens/
├── hacklens.py        main scanner
├── install.sh         one-command installer
├── update.sh          one-command updater
├── run.sh             launcher (created by install.sh)
├── requirements.txt   Python dependencies
├── README.md          this file
├── TECHNICAL_DOCS.md  deep technical documentation
├── .gitignore
└── logo.png
```

---

## Roadmap

- [ ] DOM-based and blind XSS detection
- [ ] SSRF detection
- [ ] SQL injection
- [ ] WAF evasion / bypass

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

<p align="center">
  <b>Yogesh Bhandage</b> · <a href="https://yogeshbhandage.com">yogeshbhandage.com</a><br/>
  <sub>Built with AI using original ideas by the author · Hunt responsibly 🎯</sub>
</p>
