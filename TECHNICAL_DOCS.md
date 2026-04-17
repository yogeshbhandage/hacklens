# HackLens — Technical Documentation

**Created by Yogesh Bhandage | yogeshbhandage.com**
*Built with AI using original ideas by the author. For authorized testing only.*

---

## Table of Contents

1. [Architecture](#architecture)
2. [Secret Detection — 162 Patterns](#secrets)
3. [XSS Detection Technology](#xss)
4. [Open Redirect Detection](#redirect)
5. [Scope Enforcement](#scope)
6. [False Positive Filtering](#fp)
7. [Output Reference](#output)
8. [Roadmap](#roadmap)

---

## 1. Architecture {#architecture}

```
hacklens.py -d target.com
│
├── STEP 0: Subdomain Enumeration
│   └── crt.sh + Subfinder + Assetfinder + Amass
│
├── STEP 1 & 2: URL & JS Collection
│   ├── Direct crawl (BeautifulSoup)
│   ├── Katana (-jc deep JS crawl)
│   ├── GAU (AlienVault OTX + Wayback + CommonCrawl)
│   ├── Hakrawler (stdin)
│   ├── SubJS (JS from HTML pages)
│   ├── Wayback Machine CDX API (3 queries)
│   └── waybackurls (stdin)
│
├── STEP 2.5: Endpoint Extraction
│   └── fetch/axios/url:/BASE_URL patterns from JS content
│
├── STEP 3: Secret Scanning
│   ├── JS files → jsbeautifier → 162 regex patterns
│   ├── HTML/JSON/config → raw scan → 162 regex patterns
│   └── Proactive: /.env, /.git/config, /actuator/env, etc.
│
├── STEP 4: Reflected XSS
│   └── Phase 1: Canary → Phase 2: Context → Phase 3: Payload
│
└── STEP 5: Open Redirect
    └── Layer 1: Location header → Layer 2: Body sinks → Layer 3: Chain
```

---

## 2. Secret Detection — 162 Patterns {#secrets}

### Pattern Types

| Type | Description | Example |
|------|-------------|---------|
| **PREFIX** | Vendor-specific fixed prefix | `sk_live_`, `ghp_`, `AIza` |
| **CONTEXT** | Quoted `"key": "value"` pair | `"api_key": "abc123"` |
| **URI** | Connection string with credentials | `mongodb://user:pass@host` |
| **PEM** | Exact private key header | `-----BEGIN RSA PRIVATE KEY-----` |
| **STRUCTURE** | Fixed internal structure | Slack: `xox[baprs]-NNN-NNN-chars` |

---

### All 162 Patterns

#### ☁️ Cloud (8)

| # | Name | Regex | Notes |
|---|------|-------|-------|
| 1 | AWS Access Key | `(?<![A-Z0-9])(AKIA\|ABIA\|ACCA\|ASIA)[A-Z0-9]{16}(?![A-Z0-9])` | 4-char prefix + 16 uppercase. Boundary anchored. |
| 2 | AWS Secret Key | `(?i)["'](?:aws[_-]?secret[_-]?(?:access[_-]?)?key\|AWS_SECRET_ACCESS_KEY)["']\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']` | Labeled. Exactly 40-char base64. |
| 3 | AWS ARN | `arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s'"]+` | Fixed `arn:aws:` prefix. |
| 4 | Google API Key | `AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9\-_])` | Fixed `AIza` + exactly 35 chars. |
| 5 | Google OAuth Client | `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` | Fixed `.apps.googleusercontent.com` suffix. |
| 6 | Google Service Account | `["']type["']\s*:\s*["']service_account["'][^}]{0,500}["']private_key["']\s*:\s*["']-----BEGIN` | Requires both `type:service_account` AND `private_key:-----BEGIN` in same JSON object. |
| 7 | Azure Storage Key | `AccountKey=[A-Za-z0-9+/]{88}==` | Connection string format. Exactly 88 base64 + `==`. |
| 8 | Azure Client Secret | `(?i)["'](?:azure[_-]?client[_-]?secret\|AZURE_CLIENT_SECRET\|clientSecret)["']\s*[:=]\s*["']([A-Za-z0-9\-_~.]{34,})["']\s*[,}]` | Labeled. Must be followed by `,` or `}`. |

#### 💳 Payment (6)

| # | Name | Regex | Notes |
|---|------|-------|-------|
| 9 | Stripe Live Secret | `sk_live_[0-9a-zA-Z]{24,}` | Stripe's own prefix. |
| 10 | Stripe Test Secret | `sk_test_[0-9a-zA-Z]{24,}` | |
| 11 | Stripe Publishable | `pk_(?:live\|test)_[0-9a-zA-Z]{24,}` | |
| 12 | Stripe Webhook | `whsec_[0-9a-zA-Z]{32,}` | |
| 13 | PayPal Client ID | `(?i)["']paypal[_\-]?(?:client[_\-]?id\|clientid)["']\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']` | Labeled. |
| 14 | Braintree Token | `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` | Literal `$production$` separators. |

#### 🔐 Auth / Identity (14)

| # | Name | Regex | Notes |
|---|------|-------|-------|
| 15 | JWT Token | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])` | `eyJ` = base64(`{"`). 3 parts, minimum lengths, boundary anchor. |
| 16 | Bearer Token | `[Bb]earer\s+([A-Za-z0-9][A-Za-z0-9\-_\.]{28,}[A-Za-z0-9])(?![A-Za-z0-9\-_\.])` | Value must start AND end with alphanum. |
| 17 | Basic Auth URL | `https?://[A-Za-z0-9_%.-]+:(?=[^@]{6,}@)(?=[^@]*[^A-Za-z])[^@\s]{6,}@[A-Za-z0-9.-]+\.[a-z]{2,}` | Lookahead requires at least one non-alpha in password. |
| 18 | GitHub Token | `ghp_[A-Za-z0-9]{36}` | Classic PAT format. |
| 19 | GitHub OAuth | `gho_[A-Za-z0-9]{36}` | |
| 20 | GitHub App Token | `(?:ghu\|ghs)_[A-Za-z0-9]{36}` | |
| 21 | GitHub Fine-Grained | `github_pat_[A-Za-z0-9_]{82}` | |
| 22 | GitLab Token | `glpat-[A-Za-z0-9\-_]{20}` | |
| 23 | NPM Token | `npm_[A-Za-z0-9]{36}` | |

#### 💬 Communication (9)

| # | Name | Regex | Notes |
|---|------|-------|-------|
| 24 | Slack Token | `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}` | xoxb=bot, xoxa=app, xoxp=user. Numeric workspace+user IDs. |
| 25 | Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}` | |
| 26 | Discord Token | `(?i)["'](?:discord[_-]?(?:bot[_-]?)?token\|DISCORD_TOKEN)["']\s*[:=]\s*["']([MNO][A-Za-z0-9]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27})["']` | Labeled — raw format too broad. |
| 27 | Discord Webhook | `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{60,}` | |
| 28 | Telegram Bot Token | `(?<!\d)[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])` | 8-10 digit bot ID + 35-char token. |
| 29 | Twilio Account SID | `(?i)["'](?:twilio[_-]?(?:account[_-]?)?sid\|TWILIO_ACCOUNT_SID)["']\s*[:=]\s*["']AC([a-f0-9]{32})["']` | Labeled — bare `AC`+hex matched CSS colors. |
| 30 | Twilio Auth Token | Labeled context + 32 hex | |
| 31 | SendGrid API Key | `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}` | Fixed structure: `SG.` + 22 + `.` + 43. |
| 32 | Mailgun API Key | `(?i)["'](?:mailgun[_-]?(?:api[_-]?)?key\|MAILGUN_API_KEY)["']\s*[:=]\s*["']key-([0-9a-zA-Z]{32})["']` | Labeled — bare `key-` was too broad. |

#### 🤖 AI / ML (4)

| # | Name | Regex | Notes |
|---|------|-------|-------|
| 33 | OpenAI Key (old) | `sk-[A-Za-z0-9]{20,50}T3BlbkFJ[A-Za-z0-9]{20,50}` | `T3BlbkFJ` = base64("OpenAI") — hardcoded anchor. |
| 34 | OpenAI Key (proj) | `sk-proj-[A-Za-z0-9\-_]{40,}` | New project key format. |
| 35 | Anthropic Key | `sk-ant-(?:api03-)?[A-Za-z0-9\-_]{90,}` | |
| 36 | Hugging Face Token | `hf_[A-Za-z0-9]{34,}` | |

#### 🗄️ Database (7)

| # | Name | Regex | Notes |
|---|------|-------|-------|
| 37 | MongoDB URI | `mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[^@\s'"<>]{4,}@[^\s'"<>]+` | Requires `user:pass@host` — bare URIs ignored. |
| 38 | MySQL URI | `mysql://[A-Za-z0-9_\-]+:[^@\s'"<>]{4,}@[^\s'"<>]+` | |
| 39 | PostgreSQL URI | `postgres(?:ql)?://[A-Za-z0-9_\-]+:[^@\s'"<>]{4,}@[^\s'"<>]+` | |
| 40 | Redis URI | `redis://[A-Za-z0-9_\-]+:[^@\s'"<>]{4,}@[^\s'"<>]+` | |
| 41 | Database Password | `(?i)["'](?:db\|database)[_\-]?(?:pass(?:word)?\|pwd)["']\s*:\s*["']([^\s'"<>{},]{8,})["']` | Labeled. |
| 90 | Elasticsearch URI | `https?://user:[^@\s<>]{4,}@host*elasticsearch*` | Credentials required. |
| 93 | Neo4j URI | `bolt://user:[^@\s<>]{4,}@host` | |

#### 🔑 SSH / Private Keys (5)

```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN (DSA|ENCRYPTED) PRIVATE KEY-----
```
Zero false positives — unique to actual key files.

#### 👤 Credentials (3)

| # | Name | How FP is Prevented |
|---|------|---------------------|
| 47 | Username | Value must be 4-30 chars, start with alphanum |
| 48 | Password | Lookaheads: must have uppercase + lowercase + digit or special char |
| 49 | Hardcoded Credential | Both username AND password must be quoted, within 100 chars of each other |

#### 🔒 Cryptography (5)
Crypto IV, Encryption Key, Crypto Salt, Hex Secret, HMAC Secret — all labeled context required.

#### ☁️ Infrastructure (6)
Heroku (labeled UUID), Firebase URL/API Key, S3 Bucket (quoted), Internal IP (string context), Vault Token, Docker Hub Token.

#### 🛠️ DevOps / CI-CD (15+)
Datadog, New Relic (`NRII-` prefix), Dynatrace (`dt0x00.24chars.64chars`), Grafana, Splunk HEC, Rollbar, Bugsnag, CircleCI, Travis CI, Terraform, Vercel, Netlify, Render (`rnd_`), Railway, Fly.io (`fo1_`).

#### 🌐 Social / SaaS (10+)
Twitter Bearer (22 A's prefix), Facebook (`EAACEdEose0cBA`), Mapbox (`pk.eyJ1`), Shopify (`shpat_`/`shpss_`), Algolia, Cloudflare, DigitalOcean, Square (`sq0atp-`/`sq0csp-`), Razorpay (`rzp_live/test_`).

#### 🔏 Auth / SSO (5)
Auth0, Okta (labeled), OneLogin, Keycloak — all labeled context required.

#### 📧 Email (6)
Postmark, SparkPost, Resend (`re_` + 20-26 alphanum, no underscores), Loops, Brevo (`xkeysib-64hex-16chars`), Mailchimp (labeled).

#### 📋 Productivity / SaaS (12+)
Notion (labeled), Linear (`lin_api_`), Airtable PAT (`pat14chars.64hex`), Jira, Confluence, HubSpot, Salesforce, Webflow, Contentful, Sanity (labeled), Sentry DSN (`hex32@sentry.io`), Intercom, Pusher, Amplitude.

---

## 3. XSS Detection Technology {#xss}

### Design Principle
Zero false positives through canary-first confirmation. Every reported finding is proven exploitable.

### 3-Phase Algorithm

```
For each URL with parameters:
│
├── PHASE 1: Reflection Check
│   ├── Generate unique canary: SHXSSrandom12chars
│   ├── Inject canary as param value: ?param=SHXSSk3m9pzxq1r4
│   ├── Fetch response
│   ├── IF canary not found → SKIP (no reflection)
│   ├── IF canary HTML-encoded (&lt; etc.) → SKIP (safe encoding)
│   └── IF canary verbatim unencoded → PROCEED to Phase 2
│
├── PHASE 2: Context Detection
│   ├── Find canary position in HTML
│   ├── Look back 200-500 chars for context clues
│   ├── Check if inside <script> block:
│   │   ├── Detect JSON data blocks (NOT executable):
│   │   │   type="application/json"
│   │   │   id="__NEXT_DATA__" (Next.js)
│   │   │   id="__NUXT_DATA__" (Nuxt.js)
│   │   │   id="__REDUX_STATE__"
│   │   │   id="__RELAY_STORE__"
│   │   │   → Return NULL (skip, not exploitable)
│   │   ├── Count unescaped " → js_string_dq
│   │   ├── Count unescaped ' → js_string_sq
│   │   └── Neither → js_code
│   ├── Check if inside HTML tag:
│   │   ├── After ="  → attr_double
│   │   ├── After ='  → attr_single
│   │   └── After =   → attr_unquoted
│   ├── Check if inside href/src/action → url_param
│   └── Default → html_body
│
└── PHASE 3: Context-Specific Payload
    ├── Choose payload for detected context
    ├── Inject payload: ?param=<payload>
    ├── Fetch response
    ├── Check payload regex matches in response
    ├── For js_code: verify preceding char is NOT a quote
    └── IF confirmed → REPORT with PoC URL
```

### Payload Table

| Context | Payload | Exploits |
|---------|---------|---------|
| `html_body` | `<img src=x id=SHXSS onerror=alert(1)>` | Direct tag injection |
| `attr_double` | `" onfocus=alert(1) autofocus data-x="SHXSS` | Break double quote |
| `attr_single` | `' onfocus=alert(1) autofocus data-x='SHXSS` | Break single quote |
| `attr_unquoted` | `><img src=x id=SHXSS onerror=alert(1)><x ` | Close tag, inject new |
| `js_string_dq` | `"-alert(1)-"SHXSS` | Break JS string |
| `js_string_sq` | `'-alert(1)-'SHXSS` | Break JS string |
| `js_code` | `;/*SHXSS*/alert(1)//` | Statement separator |
| `url_param` | `javascript:alert(1)//SHXSS` | JS URI injection |

### Deduplication

- URLs normalised: scheme stripped, params sorted
- Same `netloc + path + param` reported only once
- Logger deduplicates by MD5 hash of `type:value`

---

## 4. Open Redirect Detection {#redirect}

### Canary Domain
```
evil.com
```
Industry-standard test domain. Any redirect to this domain = confirmed finding.

### 13 Bypass Probes

| Probe | Bypass Technique |
|-------|-----------------|
| `https://evil.com` | Standard HTTPS |
| `http://evil.com` | Standard HTTP |
| `//evil.com` | Protocol-relative |
| `https://evil.com/` | Trailing slash |
| `https://evil.com/%2F..` | URL-encoded path traversal |
| `@evil.com` | `@` host confusion |
| `////evil.com` | Multiple slashes bypass |
| `\tevil.com` | Tab character prefix |
| `https:evil.com` | Missing slashes |
| `/%09/evil.com` | Horizontal tab in path |
| `https://evil.com@target.com` | Credential confusion |
| `https://target.com@evil.com` | Reversed credential confusion |
| `https://evil.com%23.target.com` | Fragment confusion |

### 3-Layer Detection Algorithm

```
For each parameter (redirect-likely OR value looks like URL):
│
├── LAYER 1: Raw Location Header
│   ├── GET url (allow_redirects=False)
│   ├── IF status 301/302/303/307/308:
│   │   ├── Parse Location header netloc
│   │   ├── IF netloc == evil.com → CONFIRMED
│   │   ├── IF netloc is off-target AND not benign pair → CONFIRMED
│   │   └── IF netloc is on-target (app.target.com) → FALSE POSITIVE → SKIP
│   └── IF status 200 → check body (Layer 2)
│
├── LAYER 2: Response Body JS Sinks
│   ├── IF Content-Type has "html":
│   │   ├── window.location.href = "..evil.com.." → POSSIBLE
│   │   ├── window.location.replace("..evil.com..") → POSSIBLE
│   │   ├── location.href = "..evil.com.." → POSSIBLE
│   │   ├── <form action="..evil.com.."> → POSSIBLE
│   │   ├── <meta http-equiv=refresh url=..evil.com..> → CONFIRMED
│   │   └── <a href="..evil.com.."> → SKIP (passive link, not a redirect)
│   └── (Only active redirect sinks trigger findings)
│
└── LAYER 3: Redirect Chain
    ├── GET url (allow_redirects=True, max_redirects=8)
    ├── Check final r.url netloc == evil.com → CONFIRMED
    └── Check every Location in r.history for evil.com or off-site → CONFIRMED
```

### Key Distinction — Why Previous Version Had FPs

```
❌ FALSE POSITIVE (old logic):
   Location: https://app.target.com/login?next=https://evil.com
   
   The redirect destination is app.TARGET.COM (on-site)
   evil.com only appears as a QUERY PARAM VALUE
   The browser stays on target.com — not a redirect to evil.com

✅ TRUE POSITIVE (new logic):
   Location: https://evil.com/malicious
   
   The redirect destination HOST IS evil.com
   Browser is actually sent to evil.com
```

### Parameter Selection

**Priority (tested first):**
- `next`, `redirect`, `url`, `return`, `goto`, `dest`, `target`, `redir`, `redirect_uri`, `callback`, `back`, `continue`, `forward`, `out`, `exit`, etc.
- Any param whose current value already starts with `http://`, `https://`, `//`, `www.`

**Also tested:** All other params

**Never tested (permanent exclusion):**
`utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `q`, `search`, `filter`, `labels`, `id`, `slug`, `page`, `token`, `nonce`, `secret`, `format`, `lang`, `sort`, `order`, etc.

**Proactive auth path testing:**
Even if not crawled: `/login`, `/logout`, `/signin`, `/oauth/authorize`, `/sso`, `/redirect`, `/auth/callback`, etc.

### Benign Redirect Whitelist
```
twitter.com  →  x.com           (domain migration)
x.com        →  twitter.com
fb.com       →  facebook.com    (shortlink)
youtu.be     →  youtube.com     (shortlink)
goo.gl       →  google.com      (shortlink)
```

---

## 5. Scope Enforcement {#scope}

```python
def is_in_scope(url, target_domain):
    host = urlparse(url).netloc.lower().split(":")[0]
    return host == target_domain or host.endswith("." + target_domain)
```

Applied at every level:

| Layer | Enforcement |
|-------|-------------|
| Secret scanner | `scan_url()` returns early if not in scope |
| XSS scanner | `_test_param()` returns early if not in scope |
| Redirect scanner | `_test_param()` returns early if not in scope |
| `crawled-urls.txt` | In-scope only |
| `crawled-urls-outofscope.txt` | Out-of-scope (separate file) |
| `endpoints.txt` | In-scope + relative paths only |
| Scan targets | `js_inscope` + `pages_inscope` filter applied |

---

## 6. False Positive Filtering {#fp}

Every regex match passes through a multi-layer FP filter before reporting:

### Code Reference Filter
Blocks JS property accesses that aren't real values:
```
this. / self. / config. / options. / process.env
window. / document. / ${}  (template literal)
function( / => / new Class / .prototype.
import / require( / return / typeof
```

### Placeholder Filter
```
your_ / <token> / [placeholder] / example / dummy
changeme / replace_me / test123 / n/a / undefined
myapikey / here (at end) / INSERT_ / ENTER_
```

### Entropy Filter
Values with ≤ 3 unique characters in 10+ char string (e.g. `aaaaaaaaaa`, `01010101`) → filtered.

### JS Identifier Filter
Pure `camelCase` or `snake_case` under 32 chars → filtered (it's a variable name, not a secret).

### Version String Filter
`1.0.0`, `2.3.1-beta` → filtered.

### Per-Pattern Filters
- JWT: must have exactly 3 parts with adequate lengths
- Bearer: value must not be a plain alphanumeric identifier
- Password: must have mixed character classes (upper + lower + digit/special)
- Telegram: bot ID must be 8-10 digits exactly
- Basic Auth: password must contain at least one non-alpha character

---

## 7. Output Reference {#output}

### File Structure
```
target.com/
  secrets_YYYYMMDD_HHMMSS.json
  report_YYYYMMDD_HHMMSS.html
  total_subdomains.txt
  crawled-urls.txt
  crawled-urls-outofscope.txt
  endpoints.txt
```

### JSON Schema
```json
{
  "domain": "target.com",
  "timestamp": "20260411_230435",
  "secrets": {
    "total": 8,
    "findings": [
      {
        "type": "AWS Access Key",
        "severity": "CRITICAL",
        "value": "AKIAIOSFODNN7EXAMPLE",
        "source": "https://target.com/static/js/main.chunk.js",
        "line": 1247
      }
    ]
  },
  "xss": {
    "total": 1,
    "findings": [
      {
        "type": "Reflected XSS",
        "url": "https://target.com/search?query=...",
        "param": "query",
        "detail": "Context: html_body | Payload verified",
        "evidence": "PoC: https://..."
      }
    ]
  },
  "redirects": {
    "total": 1,
    "findings": [
      {
        "type": "Open Redirect [CONFIRMED]",
        "url": "https://target.com/logout?next=https://evil.com",
        "param": "next",
        "detail": "off-site Location header | HTTP 302",
        "evidence": "Location: https://evil.com"
      }
    ]
  }
}
```

### Severity Levels

| Severity | Patterns |
|----------|---------|
| CRITICAL | AWS keys, Stripe live, RSA/EC/PGP/OpenSSH private keys, OpenAI, Anthropic, MongoDB/PostgreSQL/MySQL URIs, JWT, GitHub, GitLab |
| HIGH | Google API, Slack, Discord, SendGrid, S3, Generic Access Token, Sentry DSN, NPM, Stripe Test, HuggingFace |
| MEDIUM | Webhooks, Heroku, Firebase, Shopify, Algolia, Vault, CI/CD tokens, SaaS platform keys |
| LOW | Hardcoded passwords, Internal IPs, Basic Auth URLs, Database passwords |
| INFO | AWS ARNs, Service account references |

---

## 8. Roadmap {#roadmap}

### Planned Features

#### Advanced XSS Detection
- DOM-based XSS (injecting into `innerHTML`, `document.write`, `eval`)
- Stored XSS indicators (finding injection points that persist)
- Blind XSS (Burp Collaborator-style callback)
- CSP bypass detection

#### SSRF Detection
- Injecting internal IP probes into URL parameters
- Cloud metadata endpoint probing (`169.254.169.254`)
- DNS-based SSRF confirmation

#### WAF Evasion
- Automatic payload encoding variants
- Case randomization
- HTML entity encoding
- Unicode normalization bypass

#### Command Injection
- OS command injection via `;`, `|`, `&&`, backticks
- Blind command injection via time delays
- Out-of-band confirmation

#### SQL Injection
- Error-based SQLi detection
- Boolean-based blind SQLi
- Time-based blind SQLi
- Detection across GET/POST parameters

---

*HackLens — Created by Yogesh Bhandage | yogeshbhandage.com*
*Built with AI using original ideas by the author. Hunt responsibly. 🎯*
