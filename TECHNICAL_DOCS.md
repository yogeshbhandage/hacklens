[# HackLens v3.0.0 — Technical Documentation

**Created by Yogesh Bhandage | yogeshbhandage.com**
*Built with AI using original ideas by the author. For authorized testing only.*

---

## Table of Contents

1. [Architecture](#architecture)
2. [Secret Detection — 240+ Patterns](#secrets)
3. [XSS Detection](#xss)
4. [Open Redirect Detection](#redirect)
5. [Information Disclosure](#infodisclosure)
6. [SSTI Detection](#ssti)
7. [Command Injection Detection](#ci)
8. [Subdomain Enumeration](#subdomains)
9. [Scope Enforcement](#scope)
10. [False Positive Filtering](#fp)
11. [Memory Management](#memory)
12. [Output Reference](#output)
13. [Roadmap](#roadmap)

---

## 1. Architecture {#architecture}

```
hacklens.py
│
├── MODE 1: -d target.com
│   ├── STEP 0   Subdomain Enumeration (12+ sources)
│   ├── STEP 0b  httpx alive check
│   ├── STEP 1   URL & JS Collection (7 sources)
│   ├── STEP 2   Endpoint Extraction from JS
│   ├── STEP 3   Secret Scanning (240+ patterns, chunked)
│   ├── STEP 4   Reflected XSS (3-phase, 26 payloads)
│   ├── STEP 5   Open Redirect (3-layer, 13 probes)
│   ├── STEP 6   Information Disclosure (70+ probes)
│   ├── STEP 7   SSTI (--ssti or --deep)
│   └── STEP 8   Command Injection (--ci or --deep)
│   Output: target.com/ with all files
│
├── MODE 2: -l urls.txt
│   ├── STEP 1   Secret Scanning
│   ├── STEP 2   XSS
│   ├── STEP 3   Open Redirect
│   ├── STEP 4   Information Disclosure
│   ├── STEP 5   SSTI (--ssti or --deep)
│   └── STEP 6   Command Injection (--ci or --deep)
│   Output: <domain>-urlscan/ (JSON + HTML only)
│
└── MODE 3: -b burp_export.xml
    ├── Parse Burp XML → GET + POST requests
    ├── STEP 1   Secret Scanning (Pass A: request bodies + Pass B: responses)
    ├── STEP 2   XSS (GET params + POST body params)
    ├── STEP 3   Open Redirect
    ├── STEP 4   Information Disclosure
    ├── STEP 5   SSTI (--ssti or --deep)
    └── STEP 6   Command Injection (--ci or --deep)
    Output: <domain>-burpscan/ (JSON + HTML only)
```

---

## 2. Secret Detection — 240+ Patterns {#secrets}

### Pattern Types

| Type | Example |
|------|---------|
| PREFIX | `sk_live_`, `ghp_`, `AIza`, `ya29.`, `xoxb-` |
| CONTEXT | `"api_key": "abc123"` |
| ENV | `SECRET_KEY=abc123` |
| URI | `mongodb://user:pass@host` |
| PEM | `-----BEGIN RSA PRIVATE KEY-----` |
| CAMELCASE | `secretKey: "abc123"` |
| JSOBJECT | `{"password":"abc123"}` |

### Key Pattern Groups

**AWS:** Access Key (AKIA/ABIA/ACCA/ASIA prefix), Secret Key (labeled), Session Token (100+ chars), MWS Auth Token, ARN

**Azure:** Storage Key (AccountKey= + 88 base64), Client Secret (labeled), Client ID, SAS Token, Full connection string

**Google:** API Key (AIza prefix), OAuth Client, OAuth Token (ya29. prefix), Client Secret (labeled), GCP Service Account

**Payment:** Stripe live/test/restricted/webhook, Square, PayPal, Braintree, Razorpay

**Auth:** JWT (eyJ + 3 parts), Bearer, OAuth tokens, Session ID, GitHub (4 formats), GitLab, NPM

**Communication:** Slack (bot/user/workspace/webhook), Discord (labeled), Telegram, Twilio (labeled), SendGrid

**AI/ML:** OpenAI old (T3BlbkFJ anchor), OpenAI proj (sk-proj-), Anthropic (sk-ant-), HuggingFace (hf_)

**Database:** MongoDB/MySQL/PostgreSQL/Redis URIs (require credentials), PGPASSWORD, MySQL Password/Username/Server/Host, Engine Server, Encryption Password

**Crypto:** AES Key, Master Key, HMAC, PBKDF/scrypt, DSA/RSA/EC/PGP/OpenSSH private keys, Certificate

**CamelCase (14):** apiKey, secretKey, authToken, clientSecret, privateKey, encryptionKey, dbPassword, accessToken, jwtSecret, webhookSecret, signingSecret, cookieSecret, sessionSecret, refreshToken

**JS Objects (3):** secret/password fields, db credential fields, token fields

**DevOps:** Datadog, New Relic (NRII- prefix), Databricks (dapi prefix), Kubernetes, Terraform, CircleCI, DigitalOcean, Vercel, Netlify, Fly.io (fo1_ prefix)

---

## 3. XSS Detection {#xss}

### 3-Phase Algorithm

```
Phase 1: Canary Injection
  → SHXSSrandom12 injected as param value
  → Skip if HTML-encoded OR not reflected

Phase 2: Context Detection (500-char lookback)
  → 8 contexts detected
  → JSON data blocks skipped:
     __NEXT_DATA__, __NUXT_DATA__, __REDUX_STATE__

Phase 3: Multi-Payload (tries each, stops on first confirmed)
  → FP checks per context type
  → Report PoC URL
```

### All 26 Payloads by Context

| Context | Payloads |
|---------|---------|
| `html_body` | `<img onerror>`, `><script>`, `<svg onload>`, `<details ontoggle>`, `<input onfocus>` |
| `attr_double` | `"><script>`, `"><img>`, `" onfocus autofocus`, `" onmouseover` |
| `attr_single` | `'><script>`, `'><img>`, `' onfocus autofocus`, `' onmouseover` |
| `attr_unquoted` | `><img onerror><x`, `><script></script><x` |
| `js_string_dq` | `";alert(1)//`, `"-alert(1)-"`, `"+alert(1)+"` |
| `js_string_sq` | `';alert(1)//`, `'-alert(1)-'`, `'+alert(1)+'` |
| `js_code` | `;/*canary*/alert(1)//`, `;alert(1)//`, `\nalert(1)//` |
| `url_param` | `javascript:alert(1)//`, `javascript://canary/%0aalert(1)` |

---

## 4. Open Redirect Detection {#redirect}

**Canary:** `evil.com` — must be destination HOST, not a query param value.

```
❌ FP: Location: https://target.com/login?return=https://evil.com
✅ REAL: Location: https://evil.com/page
```

**13 bypass probes:** standard, HTTP, protocol-relative, trailing slash, path traversal, @ confusion, multiple slashes, tab prefix, missing slashes, horizontal tab, credential confusion ×2, fragment confusion.

**3 layers:** raw Location header → body JS sinks → redirect chain

**Severities:** CONFIRMED (auto-redirect to evil.com), POSSIBLE (JS sink), One-Click LOW (`<a href>`)

---

## 5. Information Disclosure {#infodisclosure}

**70+ probe paths:** Spring Boot Actuator (13 endpoints), Laravel (Ignition/Telescope/Horizon), PHP info, `.env` (9 variants), Git/SVN, API docs (Swagger/OpenAPI/GraphQL), backup files (SQL/ZIP), admin panels, log files.

**20+ response patterns:** Python/PHP/Rails/Django/Laravel/Node.js stack traces, version disclosure, private keys in response, credentials in response, env vars exposed, directory listing, Git HEAD, SQL errors, phpinfo, GraphQL introspection, Spring Boot Actuator data, SQL dump.

**Deduplication:** Header findings (X-Powered-By, Server version) deduplicated per domain — one report per domain regardless of how many URLs.

---

## 6. SSTI Detection {#ssti}

### Algorithm

```
For each parameter on every URL:
  For each of 6 engine formats:
    Round 1: inject fmt % (456, 765) → check 348840 in response
    Round 2: inject fmt % (89, 45)   → check 4005 in response
    Round 3: inject fmt % (317, 213) → check 67521 in response

    ALL 3 rounds must pass → SSTI confirmed
    (one coincidence is possible, three is impossible)

  On confirmation → fingerprint exact engine:
    {{7*'7'}} → '7777777' = Jinja2
    {{7*'7'}} → '49'      = Twig
```

### 6 Engine Formats

| Format | Engine | Example |
|--------|--------|---------|
| `{{N*M}}` | Jinja2, Twig, Tornado | `{{456*765}}` |
| `${N*M}` | Freemarker, Velocity | `${456*765}` |
| `*{N*M}` | Spring EL, Thymeleaf | `*{456*765}` |
| `<%=N*M%>` | ERB, Mako | `<%=456*765%>` |
| `{math equation="N*M"}` | Smarty | `{math equation="456*765"}` |

### Triple Verification Values

| Round | Expression | Expected |
|-------|-----------|---------|
| 1 | 456 × 765 | 348840 |
| 2 | 89 × 45 | 4005 |
| 3 | 317 × 213 | 67521 |

All parameters tested — none skipped.

---

## 7. Command Injection Detection {#ci}

### 3 Detection Methods

**Method 1 — Output-based (fastest, tried first)**

Injects 16 commands via 12 separators, checks response for output patterns:

Commands: `id`, `whoami`, `echo hacklens_ci_confirmed`, `cat /etc/passwd`, `cat /etc/hostname`, `uname -a`, `ls -la`, `pwd`, `env`, `printenv` (Unix) + `whoami`, `dir`, `ver`, `set`, `ipconfig`, `type C:\Windows\win.ini` (Windows)

Output patterns: `uid=\d+\([^)]+\)`, `root:x:0:0`, `hacklens_ci_confirmed`, `www-data|root|apache`, Linux kernel string, Windows IP config, drive listing.

**Method 2 — Time-based blind (double verified)**

```
Round 1: {sep}sleep 5  → response must take 5+ seconds
Round 2: {sep}sleep 3  → response must take 3+ seconds
Both rounds must confirm → CONFIRMED Time-Based
```
Also tries: `sleep${IFS}5`, `ping -c 5 127.0.0.1`, `timeout 5` (Windows), `Start-Sleep 5` (PowerShell)

**Method 3 — OOB via interactsh (optional, if --ci-server provided)**

```bash
bash run.sh -d target.com --ci --ci-server yourserver.interact.sh
```
Injects `; nslookup token.yourserver`, `; curl http://token.yourserver`, etc. Logs token for manual verification.

### 12 Injection Separators

`;`, `|`, `&&`, `||`, `\n`, `\r\n`, `$(cmd)`, `` `cmd` ``, `%0a`, `%0a%0d`, `&`, `\x0a`

### Workers

Capped at 3 for CI to prevent server load from causing false timing positives.

---

## 8. Subdomain Enumeration {#subdomains}

### Sources

**API (no install, no key):**

| Source | Notes |
|--------|-------|
| crt.sh | 2 queries: `%.domain` AND `domain` |
| HackerTarget | Detects `API count exceeded` |
| RapidDNS | |
| AlienVault OTX | Both `passive_dns` AND `url_list` endpoints |
| URLScan.io | Up to 300 results, checks domain + URL fields |
| ThreatCrowd | Deprecated but kept |
| Certspotter | Reliable CT log API |
| Wayback CDX | `*.domain/*` archived URLs |
| DNSDumpster | Scraped with browser User-Agent |

**Tool-based:**

| Tool | Timeout |
|------|---------|
| Subfinder (`-all`) | 180s |
| Assetfinder | 60s |
| Amass (passive) | 300s |
| Chaos | 60s (needs API key) |
| MassDNS | 120s (optional, needs SecLists) |

**Post-collection:** httpx alive check → `alive_subdomains.txt` saved separately. Strips port from httpx output for correct matching. Falls back to all subdomains if alive check returns no matches.

**Optional:** `export SECURITYTRAILS_KEY=yourkey` to enable SecurityTrails API.

---

## 9. Scope Enforcement {#scope}

```python
def is_in_scope(url, target_domain):
    host = urlparse(url).netloc.lower().split(":")[0]
    return host == target_domain or host.endswith("." + target_domain)
```

Applied at: Secret scanner, XSS scanner, Redirect scanner, crawled-urls.txt, endpoints.txt.

`-l` and `-b` modes: scope filter disabled — user owns the list.

---

## 10. False Positive Filtering {#fp}

### Secret Scanner

1. Code reference filter (`this.`, `process.env`, `${}`, `function(`, etc.)
2. Placeholder filter (`your_`, `<token>`, `changeme`, `replace_me`, etc.)
3. Low entropy filter (≤3 unique chars in 10+ char value)
4. JS identifier filter (pure camelCase/snake_case under 32 chars)
5. Version string filter (`1.0.0`, `2.3.1-beta`)
6. Data URI filter (anything from `data:image/`, `data:font/`)
7. Raw base64 blob filter (80+ chars pure base64)
8. Per-pattern (JWT 3-part structure, password mixed char classes, etc.)

### SSTI Scanner

All 3 math verification rounds must produce exact correct results. One coincidence is possible — three independent math results matching is cryptographically unlikely.

### CI Scanner (Time-based)

Sleep 5 AND sleep 3 must both confirm. Different delay values eliminate false positives from network jitter. Baseline measured from 2 clean requests with 1.5s buffer added.

### Info Disclosure

Header findings (`X-Powered-By`, `Server` version) deduplicated per domain — not per URL. Path-based findings deduplicated per domain+path.

---

## 11. Memory Management {#memory}

| File Size | Strategy | RAM |
|-----------|----------|-----|
| < 512 KB JS | jsbeautifier + scan | ~5x file size |
| > 512 KB any | Raw scan, 2MB chunks, 500-byte overlap | ~2MB constant |
| Binary content | Skipped | 0 |

Batch processing: 200 URLs per batch, `gc.collect()` between batches. Workers default: 5 (secret/XSS/redirect), 3 (CI — avoids timing FPs).

---

## 12. Output Reference {#output}

### JSON Schema
```json
{
  "domain": "target.com",
  "timestamp": "20260501_143022",
  "secrets":               {"total": 3, "findings": [...]},
  "xss":                   {"total": 1, "findings": [...]},
  "redirects":             {"total": 1, "findings": [...]},
  "information_disclosure":{"total": 2, "findings": [...]}
}
```

SSTI and CI findings appear in the `xss` array with type prefix `SSTI —` and `Command Injection`.

### Severity

| Level | Examples |
|-------|---------|
| CRITICAL | AWS keys, private keys, Stripe live, OpenAI, DB URIs, Master Key, SQL dump |
| HIGH | Google API, Slack, SSTI, Command Injection, Spring Boot Actuator, Git exposure |
| MEDIUM | Session ID, webhooks, API docs, CamelCase tokens, SSTI possible |
| LOW | X-Powered-By, MySQL host, internal IPs, Basic Auth |
| INFO | Stripe test keys, ARNs |

---

## 13. Roadmap {#roadmap}

- [ ] Advanced XSS (DOM-based, blind XSS)
- [ ] SSRF detection
- [ ] WAF evasion
- [ ] SQL injection

---

*HackLens v3.0.0 — Yogesh Bhandage | yogeshbhandage.com*
*Built with AI using original ideas by the author. Hunt responsibly. 🎯*
