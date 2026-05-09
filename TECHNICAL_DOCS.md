# HackLens v2.1 — Technical Documentation

**Created by Yogesh Bhandage | yogeshbhandage.com**
*Built with AI using original ideas by the author. For authorized testing only.*

---

## Table of Contents

1. [Architecture](#architecture)
2. [Secret Detection — 240+ Patterns](#secrets)
3. [XSS Detection Technology](#xss)
4. [Open Redirect Detection](#redirect)
5. [Information Disclosure Scanner](#infodisclosure)
6. [Subdomain Enumeration](#subdomains)
7. [Scope Enforcement](#scope)
8. [False Positive Filtering](#fp)
9. [Memory Management](#memory)
10. [Output Reference](#output)
11. [Roadmap](#roadmap)

---

## 1. Architecture {#architecture}

```
hacklens.py
│
├── MODE 1: -d target.com
│   ├── STEP 0  Subdomain Enumeration (10+ sources)
│   ├── STEP 0b httpx alive check
│   ├── STEP 1  URL & JS Collection (7 sources)
│   ├── STEP 2  Endpoint Extraction from JS
│   ├── STEP 3  Secret Scanning (240+ patterns, chunked)
│   ├── STEP 4  Reflected XSS (3-phase, 26 payloads)
│   ├── STEP 5  Open Redirect (3-layer, 13 probes)
│   └── STEP 6  Information Disclosure (70+ probes)
│
├── MODE 2: -l urls.txt
│   ├── STEP 1  Secret Scanning (all URLs)
│   ├── STEP 2  XSS (parameterised URLs + JS endpoints)
│   ├── STEP 3  Open Redirect (parameterised URLs)
│   └── STEP 4  Information Disclosure
│   Output: <domain>-urlscan/ (JSON + HTML only)
│
└── MODE 3: -b burp_export.xml
    ├── Parse Burp XML → extract all GET + POST requests
    ├── STEP 1  Secret Scanning — TWO PASSES:
    │   ├── Pass A (no network): scan request bodies directly
    │   │   ├── URL query string params
    │   │   ├── POST form body (url-encoded)
    │   │   ├── POST JSON body
    │   │   └── Multipart fields
    │   └── Pass B (network): replay each request → scan response
    │       ├── ALL status codes scanned: 200, 201, 301, 302, 401, 403, 404, 500
    │       ├── Source label shows status: "url [response 403]"
    │       └── Skips only binary content (image, video, zip, pdf)
    ├── STEP 2  XSS — GET params + POST body params
    ├── STEP 3  Open Redirect — GET params
    └── STEP 4  Information Disclosure probes
    Output: <domain>-burpscan/ (JSON + HTML only)
```

### Burp XML Parser (`parse_burp_xml`)

Parses Burp Suite XML format (Proxy → HTTP History → Save items):

```
For each <item> in XML:
  ├── URL from <url>
  ├── Method from <method>
  ├── Request body: base64-decoded if base64="true"
  ├── Hop-by-hop headers stripped (connection, transfer-encoding, etc.)
  └── Params extracted by Content-Type:
       ├── application/x-www-form-urlencoded → parse_qsl()
       ├── application/json → json.loads() → flatten one level
       └── multipart/form-data → parse name= fields
```

### POST XSS Testing Algorithm

```
For each POST item with body params:
  For each param in params:
    1. Inject canary into that param, POST to URL
    2. Check if canary reflected in response
    3. If yes → detect context (_detect_context)
    4. Try each payload from _payloads_for_context
    5. Confirm payload reflected + FP checks
    6. Report "Reflected XSS (POST)" with PoC
```

### Why Pass A matters

Secrets are often hardcoded in request bodies, not just responses:
```json
POST /api/config
{"mysql_password":"secret123","api_key":"sk_live_abc"}
```
Pass A catches these without needing a live server response.

---

## 2. Secret Detection — 240+ Patterns {#secrets}

### Pattern Types

| Type | Description | Example |
|------|-------------|---------|
| PREFIX | Fixed vendor prefix | `sk_live_`, `ghp_`, `AIza`, `ya29.` |
| CONTEXT | Quoted `"key": "value"` | `"api_key": "abc123"` |
| ENV | Env var assignment | `SECRET_KEY=abc123` |
| URI | Connection string with creds | `mongodb://user:pass@host` |
| PEM | Private key header | `-----BEGIN RSA PRIVATE KEY-----` |
| CAMELCASE | camelCase JS property | `secretKey: "abc123"` |
| JSOBJECT | JSON object key-value | `{"password":"abc123"}` |

---

### Complete Pattern List

#### ☁️ AWS (5 patterns)

| Pattern | Regex | Notes |
|---------|-------|-------|
| AWS Access Key | `(?<![A-Z0-9])(AKIA\|ABIA\|ACCA\|ASIA)[A-Z0-9]{16}` | Fixed prefix, boundary-anchored |
| AWS Secret Key | `AWS_SECRET_ACCESS_KEY\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']` | Labeled, 40-char base64 |
| AWS Session Token | `(?:AWS_SESSION_TOKEN\|SessionToken)\s*[:=,]\s*["']([A-Za-z0-9/+=]{100,})["']` | 100+ chars |
| AWS MWS Auth Token | `amzn\.mws\.[0-9a-f]{8}-...-[0-9a-f]{12}` | Fixed UUID format |
| AWS ARN | `arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"']+` | Fixed prefix |

#### ☁️ Azure (5 patterns)

| Pattern | Regex Key | Notes |
|---------|-----------|-------|
| Azure Storage Key | `AccountKey=[A-Za-z0-9+/=]{88}==` | Connection string format |
| Azure Client Secret | `AZURE_CLIENT_SECRET\s*[:=]\s*["']([A-Za-z0-9~.-_]{34,})["']` | Labeled |
| Azure Client ID | `AZURE_CLIENT_ID\s*[:=]\s*["']([UUID])["']` | UUID format, LOW |
| Azure SAS Token | `(?:AZURE_SAS_TOKEN\|sas_token)\s*[:=]\s*["']([A-Za-z0-9%]{20,512})["']` | Labeled |
| Azure Storage Full | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=` | Connection string |

#### 🟡 Google / GCP (5 patterns)

| Pattern | Regex Key | Notes |
|---------|-----------|-------|
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | Fixed prefix |
| Google OAuth Client | `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` | Fixed suffix |
| Google OAuth Token | `ya29\.[0-9A-Za-z\-_]{60,}` | Fixed prefix |
| Google Client Secret | `GOOGLE_CLIENT_SECRET\s*[:=]\s*["']([A-Za-z0-9\-_]{24})["']` | Labeled, 24 chars |
| GCP Service Account | `"type"\s*:\s*"service_account"...(500chars)..."private_key"..."-----BEGIN` | Must have both fields |

#### 💳 Payment (9 patterns)

| Pattern | Regex Key | Notes |
|---------|-----------|-------|
| Stripe Live Secret | `sk_live_[0-9a-zA-Z]{24,}` | Prefix |
| Stripe Test | `(sk\|pk\|rk)_test_[0-9A-Za-z]{24,}` | Prefix |
| Stripe Restricted | `rk_live_[0-9A-Za-z]{24,}` | Prefix |
| Stripe Publishable | `pk_live_[0-9A-Za-z]{24,}` | Prefix |
| Stripe Webhook | `whsec_[0-9a-zA-Z]{32,}` | Prefix |
| Square Access | `sq0atp-[0-9A-Za-z\-_]{22}` | Prefix |
| Square OAuth | `sq0csp-[0-9A-Za-z\-_]{43}` | Prefix |
| PayPal Client Secret | `PAYPAL_CLIENT_SECRET\s*[:=]\s*["']([A-Za-z0-9\-_]{60,100})["']` | Labeled |
| Braintree Token | `access_token$production$[0-9a-z]{16}$[0-9a-f]{32}` | Literal separators |

#### 🔐 Auth / Identity (13 patterns)

| Pattern | Regex Key |
|---------|-----------|
| JWT Token | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}` |
| Bearer Token | `[Bb]earer\s+([A-Za-z0-9][A-Za-z0-9\-_\.]{28,}[A-Za-z0-9])` |
| Bearer Token (env) | `(?:BEARER_TOKEN\|bearerToken)\s*[:=]\s*["']([A-Za-z0-9\-_.+/=]{20,512})["']` |
| Basic Auth URL | `https?://user:pass_with_non_alpha@host` |
| OAuth Token | `(?:OAUTH_TOKEN\|oauthToken)\s*[:=]\s*["']([A-Za-z0-9\-_.+/=]{20,512})["']` |
| OAuth Client ID | `OAUTH_CLIENT_ID\s*[:=]\s*["']([A-Za-z0-9\-_]{8,128})["']` |
| OAuth Client Secret | `OAUTH_CLIENT_SECRET\s*[:=]\s*["']([A-Za-z0-9\-_]{16,256})["']` |
| Access Token (env) | `(?:ACCESS_TOKEN\|accessToken)\s*[:=]\s*["']([A-Za-z0-9\-_.+/=]{20,512})["']` |
| Refresh Token (env) | `(?:REFRESH_TOKEN\|refreshToken)\s*[:=]\s*["']([A-Za-z0-9\-_.+/=]{20,512})["']` |
| Session ID | `(?:SESSION_ID\|sessionId\|PHPSESSID\|JSESSIONID)\s*[:=]\s*["']([A-Za-z0-9\-_]{20,256})["']` |
| GitHub (4 formats) | `ghp_`, `gho_`, `ghu/ghs_`, `github_pat_` + fixed lengths |
| GitLab Token | `glpat-[A-Za-z0-9\-_]{20}` |
| NPM Token | `npm_[A-Za-z0-9]{36}` |

#### 💬 Communication (9 patterns)

| Pattern | Regex Key |
|---------|-----------|
| Slack Bot | `xoxb-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{24,}` |
| Slack User | `xoxp-[0-9]{9,13}-[0-9]{9,13}-[0-9]{9,13}-[0-9a-f]{32}` |
| Slack Workspace | `xoxa-[0-9A-Za-z\-]{50,}` |
| Slack Webhook | `https://hooks.slack.com/services/T.../B.../...` |
| Discord Webhook | `https://discord.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{60,}` |
| Discord Token | `DISCORD_TOKEN\s*[:=]\s*["']([MNO][A-Za-z0-9]{23}\.[6chars]\.[27chars])["']` |
| Telegram Bot | `(?<!\d)[0-9]{8,10}:[A-Za-z0-9_\-]{35}` |
| Twilio Account SID | `TWILIO_ACCOUNT_SID\s*[:=]\s*["']AC([a-f0-9]{32})["']` — labeled |
| SendGrid | `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}` |

#### 🤖 AI / ML (4 patterns)

| Pattern | Regex Key |
|---------|-----------|
| OpenAI (old) | `sk-[A-Za-z0-9]{20,50}T3BlbkFJ[A-Za-z0-9]{20,50}` — `T3BlbkFJ`=base64("OpenAI") anchor |
| OpenAI (proj) | `sk-proj-[A-Za-z0-9\-_]{40,}` |
| Anthropic | `sk-ant-(?:api03-)?[A-Za-z0-9\-_]{90,}` |
| HuggingFace | `hf_[A-Za-z0-9]{34,}` |

#### 🗄️ Database (10 patterns)

| Pattern | Regex Key |
|---------|-----------|
| MongoDB URI | `mongodb(?:\+srv)?://user:pass@host` |
| MySQL URI | `mysql://user:pass@host` |
| PostgreSQL URI | `postgres(?:ql)?://user:pass@host` |
| Redis URI | `redis://user:pass@host` |
| Elasticsearch URI | `https?://user:pass@host*elasticsearch` |
| PGPASSWORD | `PGPASSWORD\s*[:=]\s*["']([^"']{4,128})["']` |
| MySQL Password | `mysql_pass(?:word)?\s*[:=]\s*["']([^"']{6,128})["']` |
| MySQL Username | `mysql_user(?:name)?\s*[:=]\s*["']([^"']{3,64})["']` |
| MySQL Server | `mysql_(?:server\|host)\s*[:=]\s*["']([^"']{4,256})["']` |
| Redis Password | `redis_(?:pass(?:word)?\|auth)\s*[:=]\s*["']([^"']{4,128})["']` |

#### 🔒 Crypto / Keys (11 patterns)

| Pattern | Regex Key |
|---------|-----------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` |
| DSA Private Key | `-----BEGIN DSA PRIVATE KEY-----` |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| Generic Private Key | `-----BEGIN PRIVATE KEY-----` |
| Certificate | `-----BEGIN CERTIFICATE-----` |
| AES Key | `(?:AES_KEY\|aesKey\|CIPHER_KEY\|ENCRYPT_KEY)\s*[:=]\s*["']([A-Za-z0-9+/=\-_]{16,512})["']` |
| Master Key | `(?:MASTER_KEY\|MASTER_SECRET\|ROOT_KEY)\s*[:=]\s*["']([A-Za-z0-9\-_+/=]{16,256})["']` |
| HMAC Secret | `(?:HMAC_SECRET\|hmacSecret\|HMAC_KEY)\s*[:=]\s*["']([A-Za-z0-9\-_+/=]{16,256})["']` |
| PBKDF Secret | `(?:PBKDF_SECRET\|SCRYPT_SECRET\|KDF_SECRET)\s*[:=]\s*["']([^"']{8,256})["']` |

#### 🧩 CamelCase (14 patterns)

All use `(?<![A-Za-z])` negative lookbehind to prevent matching inside longer identifiers:

`apiKey`, `secretKey`, `authToken`, `clientSecret`, `privateKey`, `encryptionKey`, `dbPassword`, `accessToken`, `jwtSecret`, `webhookSecret`, `signingSecret`, `cookieSecret`, `sessionSecret`, `refreshToken`

#### 📦 JS Object (3 patterns)

Match `{"key":"value"}` format:
- `JS Object Secret/Password` — keys: secret, apikey, password, secretkey, privatekey, encryptionkey, mysql_password
- `JS Object DB Credential` — keys: db_pass, db_password, mysql_password, redis_password
- `JS Object Token` — keys: access_token, refresh_token, id_token, bearer_token, oauth_token

#### 🔍 Exposure / Infrastructure (20+ patterns)

Shopify, Algolia, Mapbox, Firebase, Vault, Databricks (`dapi`), Kubernetes, Terraform, CircleCI, DigitalOcean, Heroku (labeled), `.env` in href/src, `.git` in href/src, UUID in sensitive key context, S3 bucket (quoted), Internal IP (RFC1918), LDAP Password, FTP/SSH Password

#### 🌍 Social (4 patterns)

Twitter Access Token, Twitter OAuth Token, Facebook Access Token (`EAA`), Google OAuth Token (`ya29.`)

---

## 3. XSS Detection Technology {#xss}

### 3-Phase Algorithm

```
Phase 1: Canary Injection
  → Generate SHXSSrandom12
  → Inject as param value
  → Skip if HTML-encoded OR not reflected

Phase 2: Context Detection (500-char lookback)
  → Detect 8 contexts
  → Skip JSON data blocks:
     __NEXT_DATA__, __NUXT_DATA__, __REDUX_STATE__
     type="application/json", type="text/template"

Phase 3: Multi-Payload Per Context
  → Try each payload in order
  → Stop on first confirmed
  → FP checks per context type
  → Report PoC URL
```

### FP Checks Per Context

| Context | FP Check |
|---------|----------|
| `attr_*` | Payload must NOT appear only HTML-encoded |
| `js_code` | Preceding char must NOT be a quote (still in string) |
| `<script>` | Must appear as `<script>`, not `&lt;script&gt;` |

### All 26 Payloads

**html_body:**
```
<img src=x id=CANARY onerror=alert(1)>
><script>alert(1)//CANARY</script>
<svg id=CANARY onload=alert(1)>
<details id=CANARY open ontoggle=alert(1)>
<input id=CANARY autofocus onfocus=alert(1)>
```

**attr_double:**
```
"><script>alert(1)//CANARY</script>
"><img src=x id=CANARY onerror=alert(1)>
" onfocus=alert(1) autofocus id="CANARY
" onmouseover=alert(1) id="CANARY
```

**attr_single:**
```
'><script>alert(1)//CANARY</script>
'><img src=x id=CANARY onerror=alert(1)>
' onfocus=alert(1) autofocus id='CANARY
' onmouseover=alert(1) id='CANARY
```

**attr_unquoted:**
```
><img src=x id=CANARY onerror=alert(1)><x
><script>alert(1)//CANARY</script><x
```

**js_string_dq:**
```
";alert(1)//CANARY
"-alert(1)-"CANARY
"+alert(1)+"CANARY
```

**js_string_sq:**
```
';alert(1)//CANARY
'-alert(1)-'CANARY
'+alert(1)+'CANARY
```

**js_code:**
```
;/*CANARY*/alert(1)//
;alert(1)//CANARY
\nalert(1)//CANARY
```

**url_param:**
```
javascript:alert(1)//CANARY
javascript://CANARY/%0aalert(1)
```

---

## 4. Open Redirect Detection {#redirect}

### Canary Domain
`evil.com` — industry-standard test domain

### Core Rule
`evil.com` must be the **destination host**, not a query param value:
```
❌ FP: Location: https://gcore.com/login?return=https://evil.com
✅ REAL: Location: https://evil.com/page
```

### 13 Bypass Probes

| Probe | Bypass Type |
|-------|-------------|
| `https://evil.com` | Standard |
| `http://evil.com` | HTTP |
| `//evil.com` | Protocol-relative |
| `https://evil.com/` | Trailing slash |
| `https://evil.com/%2F..` | Path traversal |
| `@evil.com` | @ confusion |
| `////evil.com` | Multiple slashes |
| `\tevil.com` | Tab prefix |
| `https:evil.com` | Missing slashes |
| `/%09/evil.com` | Horizontal tab |
| `https://evil.com@target.com` | Credential confusion |
| `https://target.com@evil.com` | Reversed credential confusion |
| `https://evil.com%23.target.com` | Fragment confusion |

### 3 Detection Layers

**Layer 1 — Raw Location Header (`allow_redirects=False`)**
- Status 301/302/303/307/308
- Parse `Location` netloc
- Must equal `evil.com` exactly

**Layer 2 — Response Body JS Sinks**
Active sinks only: `window.location.href=`, `window.location.replace()`, `window.location.assign()`, `<meta http-equiv=refresh>`, `<form action>`
NOT reported: `<a href>` (passive — requires user click → ONE-CLICK LOW)

**Layer 3 — Redirect Chain**
Follow all hops, check every `Location` header for `evil.com` as host.

### Severity

| Finding | Meaning |
|---------|---------|
| `[CONFIRMED]` | Browser redirected to evil.com |
| `[POSSIBLE]` | JS sink or meta-refresh found |
| `[One-Click LOW]` | `<a href>` to evil.com — user must click |

### Exclusions

Never tested: `utm_*`, `q`, `search`, `id`, `slug`, `page`, `token`, `nonce`, `secret`, `format`, `lang`, `sort`, `order`, `filter`, `labels`

---

## 5. Information Disclosure Scanner {#infodisclosure}

### 70+ Probe Paths

Categories: Spring Boot Actuator (13 endpoints), Laravel (Ignition/Telescope/Horizon), PHP (phpinfo), Config files (`.env` variants, YAML, JSON, XML), Source code (`.git`, `.svn`, package files), API Docs (Swagger, OpenAPI, GraphQL), Backup files (SQL dumps, ZIP archives), Admin panels, Log files.

### 20+ Response Patterns

| Pattern | Severity | Detects |
|---------|----------|---------|
| Python Traceback | HIGH | `Traceback (most recent call last)` |
| PHP Error | HIGH | `Fatal error:... in /path on line N` |
| Rails Exception | HIGH | `ActiveRecord::Exception` |
| Django Debug | HIGH | `Django Version:` |
| Java Stack Trace | HIGH | `com.sun.*Exception` |
| Laravel Whoops | HIGH | `Whoops! Exception` |
| Node.js Stack | HIGH | `at Module._compile (module.js:N:N)` |
| Server Version | LOW | `Apache/2.4.x` in response |
| X-Powered-By | LOW | Technology stack in header |
| Private Key in Response | CRITICAL | `-----BEGIN ... PRIVATE KEY-----` |
| AWS Key in Response | CRITICAL | `AKIA[A-Z0-9]{16}` |
| Env Vars Exposed | CRITICAL | `DB_PASSWORD=`, `SECRET_KEY=` |
| Credentials in Response | CRITICAL | `"password":"abc123"` |
| Directory Listing | MEDIUM | `Index of /` |
| Git Repo Exposed | HIGH | `ref: refs/heads/main` |
| SQL Error | HIGH | `mysql_fetch`, `ORA-00001` |
| phpinfo() | HIGH | `<title>phpinfo()` |
| API Docs | MEDIUM | `"swagger":"3.0"`, `"openapi":"3.0"` |
| GraphQL Introspection | MEDIUM | `"__schema"` |
| Spring Boot Actuator | HIGH | `"activeProfiles":`, `"beans":[` |
| SQL Dump | CRITICAL | `INSERT INTO ... VALUES` |
| Internal Path | MEDIUM | `/var/www/html/config.php` |

---

## 6. Subdomain Enumeration {#subdomains}

### Sources

**API (no install, no key):**
crt.sh, HackerTarget, RapidDNS, AlienVault OTX, URLScan.io, ThreatCrowd, DNSDumpster (scrape)

**Tools (installed by install.sh):**
Subfinder (`-all`, 180s), Assetfinder (60s), Amass passive (300s), Chaos (60s, needs API key)

**Optional bruteforce:**
MassDNS with SecLists top-5000 DNS wordlist

**Post-collection:**
httpx alive check → saves `alive_subdomains.txt` separately

### Tool Timeouts

| Tool | Timeout | Why |
|------|---------|-----|
| Subfinder | 180s | Fast, multiple sources |
| Assetfinder | 60s | Single source |
| Amass | 300s | Many sources, slow but thorough |
| Chaos | 60s | Fast API |
| MassDNS | 120s | DNS bruteforce |

---

## 7. Scope Enforcement {#scope}

```python
def is_in_scope(url, target_domain):
    host = urlparse(url).netloc.lower().split(":")[0]
    return host == target_domain or host.endswith("." + target_domain)
```

Applied at: Secret scanner, XSS scanner, Redirect scanner, crawled-urls.txt, endpoints.txt

**`-l` mode:** scope filter disabled — user owns the list.

---

## 8. False Positive Filtering {#fp}

Applied to every regex match before reporting:

1. **Code reference** — `this.`, `process.env`, `${}`, `function(`, `import`, `require(`
2. **Placeholder** — `your_`, `<token>`, `changeme`, `replace_me`, `test123`, `example`
3. **Low entropy** — ≤ 3 unique chars in 10+ char value
4. **JS identifier** — pure `camelCase`/`snake_case` under 32 chars
5. **Version string** — `1.0.0`, `2.3.1-beta`
6. **Data URI** — anything starting with `data:image/`, `data:font/` etc.
7. **Raw base64 blob** — 80+ chars of pure `[A-Za-z0-9+/=]` (not in known pattern list)
8. **Per-pattern** — JWT needs valid 3-part structure, password needs mixed char classes

---

## 9. Memory Management {#memory}

| File Size | Strategy | RAM Used |
|-----------|----------|----------|
| < 512 KB JS | jsbeautifier + scan | ~5x file size |
| > 512 KB any | Raw scan, 2MB chunks, 500-byte overlap | ~2MB constant |
| Binary (image/font/zip/pdf) | Skip entirely | 0 |

**Batch processing:** 200 URLs per batch, `gc.collect()` between batches.

**Workers:** Default 5 (keeps RAM manageable). Increase with `-w` for faster scans on machines with more RAM.

---

## 10. Output Reference {#output}

### `-d` mode folder structure
```
target.com/
  secrets_YYYYMMDD_HHMMSS.json
  report_YYYYMMDD_HHMMSS.html
  total_subdomains.txt
  alive_subdomains.txt
  crawled-urls.txt
  crawled-urls-outofscope.txt
  endpoints.txt
```

### `-l` mode folder structure
```
target-urlscan/
  secrets_YYYYMMDD_HHMMSS.json
  report_YYYYMMDD_HHMMSS.html
```

### JSON Schema
```json
{
  "domain": "target.com",
  "timestamp": "20260501_143022",
  "secrets": {
    "total": 3,
    "findings": [{"type":"AWS Access Key","severity":"CRITICAL","value":"AKIA...","source":"https://...","line":1247}]
  },
  "xss": {
    "total": 1,
    "findings": [{"type":"Reflected XSS","url":"https://...","param":"q","detail":"Context: html_body","evidence":"PoC: https://..."}]
  },
  "redirects": {
    "total": 1,
    "findings": [{"type":"Open Redirect [CONFIRMED]","url":"https://...","param":"next","detail":"Location header","evidence":"Location: https://evil.com"}]
  },
  "information_disclosure": {
    "total": 2,
    "findings": [{"type":"[HIGH] Django Debug Mode","url":"https://...","detail":"Django DEBUG=True","evidence":"Django Version: 4.2"}]
  }
}
```

### Severity Levels

| Level | Patterns |
|-------|---------|
| CRITICAL | AWS keys, Stripe live, all private keys, OpenAI, Anthropic, DB URIs with creds, JWT, OAuth Client Secret, Master Key, AES Key, Admin Password, Encryption Password, GCP SA, SQL Dump |
| HIGH | Google API, Slack tokens, SendGrid, S3, GitHub, Refresh Token, SMTP Password, LDAP, CamelCase secrets, JS Object credentials, Spring Boot Actuator, Git exposure |
| MEDIUM | Webhooks, Firebase, Session ID, Shopify, Algolia, CamelCase tokens, JS Object tokens, API Docs, GraphQL introspection |
| LOW | MySQL Server, Internal IPs, Azure Client ID, Certificate, SMTP Host, .env file exposure |
| INFO | Stripe test keys |

---

## 11. Roadmap {#roadmap}

### Planned

**Advanced XSS:** DOM-based XSS, stored XSS indicators, blind XSS (callback-based), CSP bypass detection

**SSRF Detection:** Inject internal IP probes, cloud metadata endpoint probing (`169.254.169.254`), DNS-based confirmation

**WAF Evasion:** Automatic payload encoding variants, case randomization, Unicode normalization bypass

**Command Injection:** OS command via `;`, `|`, `&&`, time-delay blind detection

**SQL Injection:** Error-based, boolean-based blind, time-based blind

---

*HackLens v2.1 — Yogesh Bhandage | yogeshbhandage.com*
*Built with AI using original ideas by the author. Hunt responsibly. 🎯*
