<p align="center">
  <img src="logo.png" alt="HackLens Logo" width="380"/>
</p>

<h1 align="center">HackLens</h1>
<p align="center"><b>Web Recon & Vulnerability Scanner for Bug Bounty Hunters</b></p>
<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1.0-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Patterns-162-red?style=flat-square"/>
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
  ├── Subdomain Enumeration   (10 sources: crt.sh, HackerTarget, RapidDNS,
  │                            AlienVault OTX, URLScan, ThreatCrowd,
  │                            DNSDumpster, Subfinder, Assetfinder, Amass, Chaos)
  ├── Alive Check             (httpx filters dead subdomains)
  ├── JS & URL Collection     (7 tools: Katana, GAU, Hakrawler, SubJS,
  │                            Wayback Machine, waybackurls, direct crawl)
  ├── Secret Scanning         (162 patterns — JS, HTML, JSON, .env, source maps,
  │                            .ts/.jsx/.tsx files, chunked scan for large files)
  ├── Reflected XSS           (3-phase: canary → context detection → payload)
  └── Open Redirect           (3-layer: Location header → JS sinks → chain)
```

Or skip recon entirely with a pre-crawled URL list:
```
bash run.sh -l my_burp_urls.txt
```

---

## What's New in v2.0

- **`-l` / `--list` flag** — pass a pre-crawled URL list, skip recon
- **10 subdomain sources** — added HackerTarget, RapidDNS, AlienVault OTX, URLScan, ThreatCrowd, DNSDumpster
- **httpx alive check** — only scans live subdomains
- **MassDNS bruteforce** — finds subdomains passive sources miss
- **`.ts`, `.jsx`, `.tsx`, `.mjs`, `.map` files** — now scanned
- **Chunked scanning** — large files (20MB+) scanned in 2MB chunks, no OOM
- **Fixed crashes** — massdns NoneType, Amass/Assetfinder timeouts, non-zero exit handling
- **`--version` flag**

---

## Installation

```bash
git clone https://github.com/yogeshbhandage/HackLens.git
cd HackLens
bash install.sh
source ~/.bashrc
```

Installs: Python packages, Go, Katana, GAU, Hakrawler, SubJS, waybackurls, Subfinder, Assetfinder, httpx, Amass, Chaos, TruffleHog, MassDNS, SecLists.

If tools show ✗ after install:
```bash
source ~/.bashrc      # fix PATH
bash install.sh       # re-run is safe
```

---

## Usage

### Mode 1 — Auto Recon (default)

HackLens discovers everything on its own. Give it a domain and it handles subdomains, crawling, and scanning automatically.

```bash
# Standard scan
bash run.sh -d target.com

# Deep scan (Wayback Machine, GAU, waybackurls)
bash run.sh -d target.com --deep

# Deep + subdomain enumeration (recommended for full coverage)
bash run.sh -d target.com --deep --subs

# Authenticated scan
bash run.sh -d target.com -c "session=abc123; csrf=xyz"

# Through Burp Suite proxy
bash run.sh -d target.com -p http://127.0.0.1:8080

# Secrets only — skip active vuln testing (fast mode)
bash run.sh -d target.com --no-xss --no-redirect
```

---

### Mode 2 — Pre-Crawled URL List (`-l`)

**Skip all recon and crawling** — feed HackLens a URL list you already have. It goes straight to secret scanning, XSS detection, and open redirect testing.

```bash
bash run.sh -d target.com -l urls.txt
```

**When to use `-l`:**
- You already have a Burp Suite sitemap / history export
- You ran your own crawler and saved the URLs
- You want to re-scan a previous crawl with updated patterns
- The target blocks automated crawlers but you have authenticated URLs
- You want faster results without waiting for recon

**How to prepare the URL list:**

```bash
# From Burp Suite:
# Proxy → HTTP history → Select all → Right click → Copy URLs → paste to file

# From your own tools:
katana -u https://target.com -jc -silent -d 5 > urls.txt
gau target.com >> urls.txt
waybackurls target.com >> urls.txt

# Then scan:
bash run.sh -d target.com -l urls.txt
```

**What `-l` mode does:**
1. Reads all URLs from the file (lines starting with `http://` or `https://`)
2. Splits into JS files vs page URLs automatically
3. Extracts API endpoints from JS files
4. Scans all files for secrets (162 patterns)
5. Tests all parameterised URLs for XSS
6. Tests all parameterised URLs for open redirects
7. Saves full JSON + HTML report

**What `-l` mode skips:**
- Subdomain enumeration
- All crawling tools (Katana, GAU, Hakrawler, SubJS, Wayback)
- All HTTP requests for discovery

> Note: `-d` and `-l` are mutually exclusive — use one or the other, not both.

---

### All Flags

| Flag | Description | Used With |
|------|-------------|-----------|
| `-d, --domain DOMAIN` | Target domain (auto recon mode) | Mode 1 |
| `-l, --list FILE` | Pre-crawled URL list (skip recon) | Mode 2 |
| `--deep` | Enable Wayback Machine, GAU, waybackurls | Mode 1 |
| `--subs` | Enumerate & scan subdomains | Mode 1 |
| `--no-xss` | Skip XSS scanning | Both |
| `--no-redirect` | Skip open redirect scanning | Both |
| `-c, --cookies STR` | Cookie string e.g. `"session=abc"` | Both |
| `-H, --headers HDR` | Extra headers e.g. `"Authorization: Bearer token"` | Both |
| `-p, --proxy URL` | Proxy e.g. `http://127.0.0.1:8080` | Both |
| `-w, --workers N` | Parallel workers (default: 5) | Both |
| `--max-js N` | Max JS files to scan (default: 2000) | Both |
| `--max-pages N` | Max page URLs to scan (default: 1000) | Both |
| `--version` | Show version and exit | — |

---

### Examples

```bash
# Full power — deep scan with subdomains
bash run.sh -d target.com --deep --subs -w 10

# Authenticated deep scan through Burp
bash run.sh -d target.com --deep --subs \
  -c "session=abc123" \
  -p http://127.0.0.1:8080

# Use Burp export list with authentication
bash run.sh -d target.com -l burp_urls.txt \
  -c "session=abc123"

# Secrets only from URL list (fastest possible)
bash run.sh -d target.com -l urls.txt \
  --no-xss --no-redirect

# Check version
bash run.sh --version
```

---

## Secret Detection — 162 Patterns

| Category | Examples |
|---|---|
| ☁️ Cloud | AWS (AKIA/ASIA), Google API, Azure Storage/Client, GCP SA |
| 🤖 AI | OpenAI (old+proj), Anthropic, HuggingFace |
| 💳 Payment | Stripe live/test/webhook, Square, Razorpay, PayPal |
| 🔐 Auth | JWT, Bearer, Basic Auth URLs |
| 🐙 VCS | GitHub (4 formats), GitLab PAT, NPM |
| 💬 Comms | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun |
| 🗄️ DB | MongoDB/PostgreSQL/MySQL/Redis URIs with credentials |
| 🔒 Crypto | AES IV, encryption keys, HMAC secrets, salts |
| 👤 Creds | Usernames, passwords, hardcoded pairs |
| 🔑 Keys | RSA, EC, PGP, OpenSSH private keys |
| 🛠️ DevOps | Datadog, New Relic, Dynatrace, CircleCI, Vercel, Fly.io |
| 🌐 SaaS | Notion, Linear, Airtable, Shopify, HubSpot, Salesforce |
| 🔗 Web3 | Ethereum private key, Infura, Alchemy, WalletConnect |

Scans: JS, TypeScript, JSX, HTML, JSON, `.env` (9 variants), source maps, config files, Spring Boot actuator, Git config, and more.

---

## XSS Detection — 3-Phase Zero FP

1. **Canary** — unique alphanumeric string, no HTML/JS meaning  
2. **Context** — detects where reflection lands: `html_body`, `attr_double/single/unquoted`, `js_string_dq/sq`, `js_code`, `url_param`  
3. **Payload** — context-specific minimal payload, verified in response

Auto-detects and skips `__NEXT_DATA__`, `__NUXT_DATA__`, Redux/Relay JSON blocks.

Every finding = **ready PoC URL**.

---

## Open Redirect — 3-Layer

- **Layer 1**: Raw `Location` header — `evil.com` must be the **destination host**, not a query param value
- **Layer 2**: JS redirect sinks (`window.location`, `location.href`, meta-refresh)
- **Layer 3**: Full redirect chain

13 bypass probes. One-click redirect detection (`<a href>`) reported as LOW severity.

---

## Output Files

```
target.com/
  secrets_TIMESTAMP.json           ← all findings
  report_TIMESTAMP.html            ← visual report
  total_subdomains.txt             ← all subdomains
  alive_subdomains.txt             ← live subdomains only
  crawled-urls.txt                 ← in-scope URLs
  crawled-urls-outofscope.txt      ← out-of-scope (reference)
  endpoints.txt                    ← API endpoints
```

---

## Severity

| | Level | Examples |
|---|---|---|
| 🔴 | CRITICAL | AWS keys, private keys, Stripe live, OpenAI, DB URIs, JWTs |
| 🟠 | HIGH | Google API, Slack, SendGrid, S3, GitHub tokens |
| 🟡 | MEDIUM | Webhooks, Heroku, Firebase, Shopify, CI/CD tokens |
| 🔵 | LOW | Passwords, internal IPs, Basic Auth URLs |
| ℹ️ | INFO | ARNs, service account references |

---

## Roadmap

- [ ] Advanced XSS (DOM-based, blind XSS)
- [ ] SSRF detection
- [ ] WAF evasion
- [ ] Command injection
- [ ] SQL injection

---

## Files

```
HackLens/
  hacklens.py         ← main scanner
  install.sh          ← installer
  run.sh              ← launcher (auto-created)
  requirements.txt    ← Python deps
  README.md
  TECHNICAL_DOCS.md
  .gitignore
  logo.png
```

---

## License

MIT — free to use, modify, distribute with attribution.

---

<p align="center">
  <b>Yogesh Bhandage</b> | <a href="https://yogeshbhandage.com">yogeshbhandage.com</a><br/>
  <i>Built with AI using original ideas by the author. Hunt responsibly. 🎯</i>
</p>
