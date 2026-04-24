#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       HACKLENS v2.0 - Web Recon & Vulnerability Scanner      ║
║       JS Secrets  |  Reflected XSS  |  Open Redirect        ║
║                                                              ║
║  Created by  : Yogesh Bhandage                               ║
║  Website     : yogeshbhandage.com                            ║
║  Purpose     : Bug Bounty & Authorized Security Testing      ║
║  Note        : Built with AI using original ideas by author  ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import sys
import os
import json
import argparse
import threading
import subprocess
import urllib.parse
import tempfile
import hashlib
import shutil
import gc
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import requests
    import jsbeautifier
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
    init(autoreset=True)
except ImportError as e:
    print(f"[!] Missing dependency: {e}\n[!] Run: bash install.sh")
    sys.exit(1)

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
R=Fore.RED; G=Fore.GREEN; Y=Fore.YELLOW; B=Fore.BLUE
M=Fore.MAGENTA; C=Fore.CYAN
BR=Fore.LIGHTRED_EX; BG=Fore.LIGHTGREEN_EX
DIM=Style.DIM; BOLD=Style.BRIGHT; RESET=Style.RESET_ALL

def banner():
    print(f"""{G}{BOLD}
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║     ██╔════╝████╗  ██║██╔════╝
  ███████║███████║██║     █████╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
  ██╔══██║██╔══██║██║     ██╔═██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████╗██║ ╚████║███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
{C}            Web Recon  +  JS Secrets  +  XSS  +  Open Redirect
{M}            Created by Yogesh Bhandage  |  yogeshbhandage.com
{Y}            ⚠  For Authorized Security Testing Only  ⚠{RESET}
""")

# ─────────────────────────────────────────────
#  SECRET PATTERNS  (tightened, low-FP)
# ─────────────────────────────────────────────

SECRET_PATTERNS = {
    # ── Cloud ──────────────────────────────────────────────────────────
    # AWS key: fixed 4-char prefix + exactly 16 uppercase alphanum, no adjoining alphanum
    "AWS Access Key":         r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])',
    # AWS secret: must be preceded by aws context word and be quoted
    "AWS Secret Key":         r'(?i)["\'](?:aws[_-]?secret[_-]?(?:access[_-]?)?key|AWS_SECRET_ACCESS_KEY)["\']\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    "AWS ARN":                r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\'"]+',
    # Google key always starts AIza + exactly 35 chars, no continuation
    "Google API Key":         r'AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9\-_])',
    # Google OAuth: numeric id + hyphen + 32 alphanum + fixed suffix
    "Google OAuth Client":    r'[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Google Service Account": r'["\']type["\']\s*:\s*["\']service_account["\'][^}]{0,500}["\']private_key["\']\s*:\s*["\']-----BEGIN',
    # Azure: AccountKey= followed by 88-char base64 + ==
    "Azure Storage Key":      r'AccountKey=[A-Za-z0-9+/]{88}==',
    "Azure Client Secret":    r'(?i)["\'](?:azure[_-]?client[_-]?secret|AZURE_CLIENT_SECRET|clientSecret)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_~.]{34,})["\']\s*[,}]',

    # ── Payment ────────────────────────────────────────────────────────
    # Stripe keys: deterministic prefix, very reliable
    "Stripe Live Secret":     r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Test Secret":     r'sk_test_[0-9a-zA-Z]{24,}',
    "Stripe Publishable":     r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
    "Stripe Webhook":         r'whsec_[0-9a-zA-Z]{32,}',
    # PayPal: must be labeled as client id
    "PayPal Client ID":       r'(?i)["\']paypal[_\-]?(?:client[_\-]?id|clientid)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
    "Braintree Token":        r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',

    # ── Auth / Identity ────────────────────────────────────────────────
    # JWT: 3 base64url parts separated by dots, each sufficiently long
    "JWT Token":              r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])',
    # Bearer: must have actual long token value (not a variable name)
    "Bearer Token":           r'[Bb]earer\s+([A-Za-z0-9][A-Za-z0-9\-_\.]{28,}[A-Za-z0-9])(?![A-Za-z0-9\-_\.])',
    # Basic auth embedded in URL — must have real-looking credentials
    "Basic Auth URL":         r'https?://[A-Za-z0-9_%.-]+:(?=[^@]{6,}@)(?=[^@]*[^A-Za-z])[^@\s]{6,}@[A-Za-z0-9.-]+\.[a-z]{2,}',
    # GitHub tokens: all have fixed deterministic prefixes
    "GitHub Token":           r'ghp_[A-Za-z0-9]{36}',
    "GitHub OAuth":           r'gho_[A-Za-z0-9]{36}',
    "GitHub App Token":       r'(?:ghu|ghs)_[A-Za-z0-9]{36}',
    "GitHub Fine-Grained":    r'github_pat_[A-Za-z0-9_]{82}',
    "GitLab Token":           r'glpat-[A-Za-z0-9\-_]{20}',
    "NPM Token":              r'npm_[A-Za-z0-9]{36}',

    # ── Communication ──────────────────────────────────────────────────
    # Slack bot token: xox[b/a/p/r/s]- + specific numeric segments
    "Slack Token":            r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
    # Slack webhook: full URL with T+B+token segments
    "Slack Webhook":          r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}',
    # Discord token: specific character class structure (MNO prefix)
    "Discord Token":          r'(?i)["\'](?:discord[_-]?(?:bot[_-]?)?token|DISCORD_TOKEN)["\']\s*[:=]\s*["\']([MNO][A-Za-z0-9]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27})["\']',
    # Discord webhook: specific URL format with snowflake ID length
    "Discord Webhook":        r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{60,}',
    # Telegram: numeric bot id : 35-char token — no adjoining digits
    "Telegram Bot Token":     r'(?<!\d)[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])',
    # Twilio SID: AC + 32 lowercase hex
    "Twilio Account SID":     r'(?i)["\'](?:twilio[_-]?(?:account[_-]?)?sid|TWILIO_ACCOUNT_SID)["\']\s*[:=]\s*["\']AC([a-f0-9]{32})["\']',
    "Twilio Auth Token":      r'(?i)twilio.{0,30}["\']([a-f0-9]{32})["\']',
    # SendGrid: SG. + 22 chars + . + 43 chars (deterministic structure)
    "SendGrid API Key":       r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    "Mailgun API Key":        r'(?i)["\'](?:mailgun[_-]?(?:api[_-]?)?key|MAILGUN_API_KEY)["\']\s*[:=]\s*["\']key-([0-9a-zA-Z]{32})["\']',

    # ── AI / ML ────────────────────────────────────────────────────────
    # OpenAI old format has T3BlbkFJ anchor in the middle
    "OpenAI Key (old)":       r'sk-[A-Za-z0-9]{20,50}T3BlbkFJ[A-Za-z0-9]{20,50}',
    "OpenAI Key (proj)":      r'sk-proj-[A-Za-z0-9\-_]{40,}',
    "Anthropic Key":          r'sk-ant-(?:api03-)?[A-Za-z0-9\-_]{90,}',
    "Hugging Face Token":     r'hf_[A-Za-z0-9]{34,}',

    # ── Database URIs — must have credentials (user:pass@host) ─────────
    "MongoDB URI":            r'mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[^@\s\'"<>]{4,}@[^\s\'"<>]+',
    "MySQL URI":              r'mysql://[A-Za-z0-9_\-]+:[^@\s\'"<>]{4,}@[^\s\'"<>]+',
    "PostgreSQL URI":         r'postgres(?:ql)?://[A-Za-z0-9_\-]+:[^@\s\'"<>]{4,}@[^\s\'"<>]+',
    "Redis URI":              r'redis://[A-Za-z0-9_\-]+:[^@\s\'"<>]{4,}@[^\s\'"<>]+',
    # DB password: quoted key:value pair, value 8+ chars
    "Database Password":      r'(?i)["\'](?:db|database)[_\-]?(?:pass(?:word)?|pwd)["\']\s*:\s*["\']([^\s\'"<>{},]{8,})["\']',

    # ── SSH / Crypto ───────────────────────────────────────────────────
    "RSA Private Key":        r'-----BEGIN RSA PRIVATE KEY-----',
    "EC Private Key":         r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":        r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "OpenSSH Private Key":    r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Generic Private Key":    r'-----BEGIN (?:DSA|ENCRYPTED) PRIVATE KEY-----',

    # ── Generic (strict — quoted key:value only, no code refs) ─────────
    # Key must be in quotes, value in quotes, value 20+ real chars
    # -- Credentials --
    "Username":               r'(?i)["\'](?:username|user_name|login)["\']\s*[:=]\s*["\']([a-zA-Z0-9][a-zA-Z0-9._@+-]{4,30})["\']',
    "Password":               r'(?i)["\'](?:password|passwd)["\']\s*[:=]\s*["\'](?=[^\'\"]{10,})(?=[^\'\"]*[A-Z])(?=[^\'\"]*[a-z])(?=[^\'\"]*[0-9\W])([^\'\"<>{}\\]{10,60})["\']',
    "Hardcoded Credential":   r'(?i)["\'](?:username|user|login)["\']\s*[:=]\s*["\']([^\'\"\s]{3,30})["\"][^"\']{0,100}["\'](?:password|passwd|pass|pwd)["\']\s*[:=]\s*["\']([^\'\"\s]{6,})["\']\s*[,}]',
    # -- Cryptography --
    "Crypto IV":              r'(?i)["\'](?:iv|aes[_\-]?iv|init[_\-]?vector)["\']\s*[:=]\s*["\']([A-Fa-f0-9]{16,64})["\']',
    "Encryption Key":         r'(?i)["\'](?:encryption[_\-]?key|aes[_\-]?key|cipher[_\-]?key|crypto[_\-]?key)["\']\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,})["\']',
    "Crypto Salt":            r'(?i)["\'](?:salt|hash[_\-]?salt|password[_\-]?salt)["\']\s*[:=]\s*["\']([A-Za-z0-9+/=$]{10,})["\']',
    "Hex Secret":             r'(?i)["\'](?:hex[_\-]?(?:key|secret|token))["\']\s*[:=]\s*["\']([A-Fa-f0-9]{32,64})["\']',
    "HMAC Secret":            r'(?i)["\'](?:hmac[_\-]?(?:secret|key)|signing[_\-]?(?:secret|key)|jwt[_\-]?secret)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_\/+]{20,})["\']',
    # -- Generic --
    "Generic API Key":        r'(?i)["\'](?:api[_\-]?key|apikey|api[_\-]?secret)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
    "Generic Client Secret":  r'(?i)["\']client[_\-]?secret["\']\s*[:=]\s*["\']([A-Za-z0-9\-_\/+]{20,})["\']',
    # Password: quoted key, quoted value, 10+ chars
    # Access token: quoted key:value, value 30+ chars
    "Generic Access Token":   r'(?i)["\'](?:access[_\-]?token|auth[_\-]?token|id[_\-]?token)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{30,})["\']',
    "Generic Private Key Val":r'(?i)["\']private[_\-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9\-_/+=]{30,})["\']',

    # ── Infrastructure ─────────────────────────────────────────────────
    # Heroku: UUID must have heroku keyword nearby
    "Heroku API Key":         r'(?i)["\']heroku[_-]?(?:api[_-]?)?key["\']\s*[:=]\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
    "Firebase URL":           r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Firebase API Key":       r'(?i)["\'](?:firebase[_\-]?api[_\-]?key|FIREBASE_API_KEY)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{35,40})["\']',
    # S3: must be amazonaws.com subdomain
    "S3 Bucket":              r'["\'](?:https?://)?([a-z0-9][a-z0-9\-]{2,62})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com["\']\|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9\-]{2,62})/',
    # Internal IP: must be in a string context (quoted or in a URL)
    "Internal IP":            r'(?:["\']|//\s*)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:["\']|[/\s])',

    # ── DevOps ─────────────────────────────────────────────────────────
    "Vault Token":            r'(?i)["\']vault[_\-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
    "Docker Hub Token":       r'(?i)["\']docker[_\-]?(?:token|password)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']',

    # ── Social / SaaS ──────────────────────────────────────────────────
    # Twitter Bearer: must be in a quoted string context.
    # Raw base64 image data (PNG/ICC profiles) contains long runs of A's
    # which matched the old pattern. Require quote boundary on left.
    "Twitter Bearer":         r'(?<=["\'\`\s])AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}(?=["\'\`\s]|$)',
    "Facebook Token":         r'EAACEdEose0cBA[0-9A-Za-z]+',
    "Mapbox Token":           r'pk\.eyJ1[A-Za-z0-9\-_\.]{10,}',
    "Shopify Token":          r'shpat_[a-fA-F0-9]{32}',
    "Shopify Secret":         r'shpss_[a-fA-F0-9]{32}',
    "WordPress Auth Key":     r'define\s*\(\s*["\']AUTH_KEY["\']\s*,\s*["\'](.{30,})["\']',
    "Algolia App ID":         r'(?i)["\']algolia[_\-]?app[_\-]?id["\']\s*[:=]\s*["\']([A-Z0-9]{10})["\']',
    "Algolia API Key":        r'(?i)["\']algolia[_\-]?api[_\-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']',
    # ── Extended Cloud / CDN ──────────────────────────────────────────────
    "Cloudflare API Token":   r'(?i)["\'\']cloudflare[_\-]?(?:api[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9_\-]{40})["\'\']',
    "Cloudflare API Key":     r'(?i)["\'\']cloudflare[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([a-f0-9]{37})["\'\']',
    "DigitalOcean Token":     r'(?i)["\'\'](?:digitalocean|do)[_\-]?token["\'\']\s*[:=]\s*["\'\']([a-f0-9]{64})["\'\']',
    "Linode Token":           r'(?i)["\'\']linode[_\-]?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{64})["\'\']',
    "Vultr API Key":          r'(?i)["\'\']vultr[_\-]?api[_\-]?key["\'\']\s*[:=]\s*["\'\']([A-Z0-9]{36})["\'\']',

    # ── Extended Payment ──────────────────────────────────────────────────
    "Square Access Token":    r'sq0atp-[A-Za-z0-9\-_]{22,}',
    "Square OAuth Token":     r'sq0csp-[A-Za-z0-9\-_]{22,}',
    "Razorpay Key":           r'rzp_(?:live|test)_[A-Za-z0-9]{14,}',
    "Payoneer Token":         r'(?i)["\'\']payoneer[_\-]?(?:token|key|secret)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{20,})["\'\']',

    # ── Extended Source Control ───────────────────────────────────────────
    "Bitbucket Client ID":    r'(?i)["\'\']bitbucket[_\-]?client[_\-]?(?:id|secret)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{20,})["\'\']',
    "Azure DevOps PAT":       r'(?i)(?:azure[_\-]?devops|ado)[_\-]?(?:token|pat)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{52})["\'\']',
    "Codecov Token":          r'(?i)["\'\']codecov[_\-]?token["\'\']\s*[:=]\s*["\'\']([a-f0-9\-]{36})["\'\']',

    # ── Extended Communication ────────────────────────────────────────────
    "PagerDuty Key":          r'(?i)["\'\']pagerduty[_\-]?(?:api[_\-]?)?(?:key|token)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9+]{20,})["\'\']',
    "Nexmo API Key":          r'(?i)["\'\']nexmo[_\-]?api[_\-]?(?:key|secret)["\'\']\s*[:=]\s*["\'\']([a-f0-9]{8,})["\'\']',
    "MessageBird Key":        r'(?i)["\'\']messagebird[_\-]?(?:api[_\-]?)?(?:key|token)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{25,})["\'\']',
    "Plivo Auth Token":       r'(?i)["\'\']plivo[_\-]?(?:auth[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{40})["\'\']',
    "Vonage/Nexmo Secret":    r'(?i)["\'\'](?:vonage|nexmo)[_\-]?(?:api[_\-]?)?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{16})["\'\']',

    # ── Extended Database ─────────────────────────────────────────────────
    "Elasticsearch URI":      r"https?://[A-Za-z0-9_-]+:[^@\s<>]{4,}@[^\s<>]*(?:9200|9300|elasticsearch)[^\s<>]*",
    "CouchDB URI":            r"https?://[A-Za-z0-9_-]+:[^@\s<>]{4,}@[^\s<>]*(?:5984|couchdb)[^\s<>]*",
    "Cassandra Credentials":  r'(?i)["\']cassandra[_-]?(?:pass(?:word)?|user(?:name)?)["\']\s*[:=]\s*["\']([^\s<>]{6,})["\']',
    "Neo4j URI":              r"bolt://[A-Za-z0-9_-]+:[^@\s<>]{4,}@[^\s<>]+",

    # ── Extended Monitoring / APM ─────────────────────────────────────────
    "Datadog API Key":        r'(?i)["\'\']datadog[_\-]?api[_\-]?key["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "Datadog App Key":        r'(?i)["\'\']datadog[_\-]?app[_\-]?key["\'\']\s*[:=]\s*["\'\']([a-f0-9]{40})["\'\']',
    "New Relic License Key":  r'(?i)["\'\']new[_\-]?relic[_\-]?(?:license[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{40})["\'\']',
    "New Relic Ingest Key":   r'NRII-[A-Za-z0-9_\-]{40}',
    "Dynatrace Token":        r'dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}',
    "Grafana API Key":        r'(?i)["\'\']grafana[_\-]?(?:api[_\-]?)?(?:key|token)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9=+/]{40,})["\'\']',
    "Splunk HEC Token":       r'(?i)["\'\']splunk[_\-]?(?:hec[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([a-f0-9\-]{36})["\'\']',
    "Rollbar Token":          r'(?i)["\'\']rollbar[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "Bugsnag API Key":        r'(?i)["\'\']bugsnag[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "LogDNA Ingestion Key":   r'(?i)["\'\']logdna[_\-]?(?:ingestion[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "Honeybadger API Key":    r'(?i)["\'\']honeybadger[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9+/]{30,})["\'\']',

    # ── Extended DevOps / CI/CD ───────────────────────────────────────────
    "CircleCI Token":         r'(?i)["\'\']circleci[_\-]?token["\'\']\s*[:=]\s*["\'\']([a-f0-9]{40})["\'\']',
    "Travis CI Token":        r'(?i)["\'\']travis[_\-]?(?:ci[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9_\-]{20,})["\'\']',
    "Terraform Cloud Token":  r'(?i)["\'\']terraform[_\-]?(?:cloud[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9.=]{14,})["\'\']',
    "Vercel Token":           r'(?i)["\'\']vercel[_\-]?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{24,})["\'\']',
    "Netlify Token":          r'(?i)["\'\']netlify[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{20,})["\'\']',
    "Render API Key":         r'rnd_[A-Za-z0-9]{30,40}(?![A-Za-z0-9_-])',
    "Railway Token":          r'(?i)["\'\']railway[_\-]?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{20,})["\'\']',
    "Fly.io Token":           r'fo1_[A-Za-z0-9\-_]{43}',

    # ── Extended E-Commerce ───────────────────────────────────────────────
    "WooCommerce Key":        r'(?:wc_live|wc_test)_[a-zA-Z0-9]{40}',
    "Magento Token":          r'(?i)["\'\']magento[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "BigCommerce Token":      r'(?i)["\'\']bigcommerce[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{30,})["\'\']',

    # ── Extended Social / Advertising ────────────────────────────────────
    "LinkedIn Client ID":     r'(?i)["\'\']linkedin[_\-]?client[_\-]?(?:id|secret)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{12,})["\'\']',
    "Pinterest Token":        r'(?i)["\'\']pinterest[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{30,})["\'\']',
    "TikTok App ID":          r'(?i)["\'\']tiktok[_\-]?(?:app[_\-]?)?(?:id|secret|key)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{15,})["\'\']',
    "Reddit Client ID":       r'(?i)["\'\']reddit[_\-]?client[_\-]?(?:id|secret)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{14,})["\'\']',
    "Spotify Client Secret":  r'(?i)["\'\']spotify[_\-]?client[_\-]?secret["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "Twitch Client Secret":   r'(?i)["\'\']twitch[_\-]?client[_\-]?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{30,})["\'\']',

    # ── Extended Crypto / Web3 ────────────────────────────────────────────
    "Ethereum Private Key":   r'(?i)["\'\'](?:eth[_\-]?)?private[_\-]?key["\'\']\s*[:=]\s*["\'\'](?:0x)?([a-fA-F0-9]{64})["\'\']',
    "Infura Project Secret":  r'(?i)["\'\']infura[_\-]?(?:project[_\-]?)?secret["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "Alchemy API Key":        r'(?i)["\'\']alchemy[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{32,})["\'\']',
    "Moralis API Key":        r'(?i)["\'\']moralis[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{64,})["\'\']',
    "WalletConnect Project":  r'(?i)["\'\']wallet[_\-]?connect[_\-]?project[_\-]?id["\'\']\s*[:=]\s*["\'\']([a-f0-9]{32})["\'\']',
    "Pinata JWT":             r'(?i)["\'\']pinata[_\-]?(?:jwt|api[_\-]?key)["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_.]{50,})["\'\']',

    # ── Extended Auth / SSO ───────────────────────────────────────────────
    "Auth0 Client Secret":    r'(?i)["\'\']auth0[_\-]?client[_\-]?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{40,})["\'\']',
    "Okta API Token":         r'(?i)["\']okta[_-]?(?:api[_-]?)?token["\']\s*[:=]\s*["\']([A-Za-z0-9]{20}[A-Za-z]{2,}[A-Za-z0-9]{15,})["\']',
    "Okta Client Secret":     r'(?i)["\'\']okta[_\-]?client[_\-]?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{40,})["\'\']',
    "OneLogin Client Secret": r'(?i)["\'\']onelogin[_\-]?client[_\-]?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9+/=]{40,})["\'\']',
    "Keycloak Client Secret": r'(?i)["\'\']keycloak[_\-]?client[_\-]?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-]{20,})["\'\']',

    # ── Extended Storage ──────────────────────────────────────────────────
    "GCS Service Account Key":r'(?i)"private_key_id"\s*:\s*"([a-f0-9]{40})"',
    "Backblaze App Key":      r'(?i)["\'\']backblaze[_\-]?(?:app[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9+/]{31})["\'\']',
    "Wasabi Secret Key":      r'(?i)["\'\']wasabi[_\-]?secret[_\-]?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9/+=]{40})["\'\']',
    "MinIO Secret Key":       r'(?i)["\'\']minio[_\-]?secret[_\-]?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9/+=]{20,})["\'\']',

    # ── Extended Email ────────────────────────────────────────────────────
    "Postmark Token":         r'(?i)["\'\']postmark[_\-]?(?:server[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([a-f0-9\-]{36})["\'\']',
    "SparkPost API Key":      r'(?i)["\'\']sparkpost[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{20,})["\'\']',
    "Resend API Key":         r're_[A-Za-z0-9]{20,26}(?![A-Za-z0-9_])',
    "Loops API Key":          r'(?i)["\'\']loops[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9_\-]{20,})["\'\']',
    "Brevo/Sendinblue Key":   r'xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}',
    "Mailchimp API Key":      r'(?i)["\']mailchimp[_-]?(?:api[_-]?)?key["\']\s*[:=]\s*["\']([a-f0-9]{32}-us[0-9]{1,2})["\']',

    # ── Miscellaneous High-Value ───────────────────────────────────────────
    "Jira API Token":         r'(?i)["\'\']jira[_\-]?(?:api[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9=+/]{24,})["\'\']',
    "Confluence API Token":   r'(?i)["\'\']confluence[_\-]?(?:api[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9=+/]{24,})["\'\']',
    "Airtable API Key":       r'(?i)["\']airtable[_-]?(?:api[_-]?)?key["\']\s*[:=]\s*["\']key([A-Za-z0-9]{14})["\']',
    "Airtable PAT":           r'pat[A-Za-z0-9]{14}\.[a-f0-9]{64}',
    "Notion Integration":     r'(?i)["\'](?:notion[_-]?(?:integration[_-]?)?(?:token|secret)|NOTION_TOKEN)["\']\s*[:=]\s*["\']secret_([A-Za-z0-9]{43})["\']',
    "Notion OAuth Secret":    r'(?i)["\'\']notion[_\-]?(?:oauth[_\-]?)?secret["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{40,})["\'\']',
    "Linear API Key":         r'lin_api_[A-Za-z0-9]{40}',
    "Asana PAT":              r'(?i)["\'\']asana[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([0-9]{16}/[a-f0-9]{16})["\'\']',
    "Monday.com Token":       r'(?i)["\'\']monday[_\-]?(?:api[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9.=_\-]{30,})["\'\']',
    "Zendesk Subdomain":      r'(?i)["\'](?:zendesk[_-]?(?:subdomain|url)|ZENDESK_URL)["\']\s*[:=]\s*["\']https?://([a-zA-Z0-9-]+)\.zendesk\.com["\']',
    "Typeform Token":         r'(?i)["\'\']typeform[_\-]?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9\-_]{20,})["\'\']',
    "Freshdesk API Key":      r'(?i)["\'\']freshdesk[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9]{20,})["\'\']',
    "HubSpot API Key":        r'(?i)["\'\']hubspot[_\-]?(?:api[_\-]?)?key["\'\']\s*[:=]\s*["\'\']([a-f0-9\-]{36})["\'\']',
    "Salesforce Token":       r'(?i)["\'\']salesforce[_\-]?(?:access[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9!.]{40,})["\'\']',
    "Webflow API Token":      r'(?i)["\'\']webflow[_\-]?(?:api[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([a-f0-9]{64})["\'\']',
    "Contentful CDA Token":   r'(?i)["\'\']contentful[_\-]?(?:cda[_\-]?|delivery[_\-]?)?token["\'\']\s*[:=]\s*["\'\']([A-Za-z0-9_\-]{43})["\'\']',
    "Sanity Project Token":   r'(?i)["\'](?:sanity[_-]?(?:api[_-]?)?(?:token|key)|SANITY_API_TOKEN)["\']\s*[:=]\s*["\']sk[A-Za-z0-9]{90,}["\']',

        "Sentry DSN":             r'https://[a-f0-9]{32}@(?:o\d+\.)?sentry\.io/\d+',
    "Intercom Token":         r'(?i)["\']intercom[_\-]?(?:secret|token|api[_\-]?key)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
    "Pusher Key":             r'(?i)["\']pusher[_\-]?(?:app[_\-]?)?key["\']\s*[:=]\s*["\']([a-f0-9]{20})["\']',
    "Amplitude Key":          r'(?i)["\']amplitude[_\-]?api[_\-]?key["\']\s*[:=]\s*["\']([a-f0-9]{32})["\']',
}

# ─────────────────────────────────────────────
#  SEVERITY
# ─────────────────────────────────────────────

SEVERITY = {
    "CRITICAL": [
        "AWS Access Key","AWS Secret Key","Stripe Live Secret",
        "RSA Private Key","EC Private Key","PGP Private Key",
        "OpenSSH Private Key","Generic Private Key",
        "OpenAI Key (old)","OpenAI Key (proj)","Anthropic Key",
        "MongoDB URI","PostgreSQL URI","MySQL URI",
        "JWT Token","GitHub Token","GitHub Fine-Grained","GitLab Token",
    ],
    "HIGH": [
        "Google API Key","Google OAuth Client","Firebase API Key",
        "Slack Token","Discord Token","Twilio Auth Token",
        "SendGrid API Key","GitHub OAuth","GitHub App Token",
        "S3 Bucket","Stripe Test Secret","PayPal Client ID",
        "Bearer Token","Generic Access Token","Hugging Face Token",
        "Sentry DSN","NPM Token",
    ],
    "MEDIUM": [
        "Slack Webhook","Discord Webhook","Telegram Bot Token",
        "Generic API Key","Generic Client Secret","Generic Private Key Val",
        "Firebase URL","Heroku API Key","Vault Token",
        "Mapbox Token","Shopify Token","Shopify Secret",
        "Algolia API Key","Algolia App ID","Stripe Publishable","Stripe Webhook",
        "Intercom Token","Pusher Key","Amplitude Key",
    ],
    "LOW": [
        "Basic Auth URL","AWS ARN","Mailgun API Key",
        "WordPress Auth Key","Docker Hub Token","Redis URI",
    ],
    "INFO": [
        "Google Service Account","Azure Storage Key","Braintree Token",
    ],
}

def get_severity(name):
    for sev, names in SEVERITY.items():
        if name in names:
            # normalise MEDIUM_CRYPTO -> MEDIUM for display
            return "MEDIUM" if sev == "MEDIUM_CRYPTO" else sev
    return "MEDIUM"

SEV_COLOR = {
    "CRITICAL": R+BOLD, "HIGH": BR, "MEDIUM": Y, "LOW": B, "INFO": C
}

# ─────────────────────────────────────────────
#  OUTPUT FOLDER  (per-domain)
# ─────────────────────────────────────────────

def make_output_dir(domain):
    safe = re.sub(r'[^\w.\-]', '_', domain)
    path = Path(safe)
    path.mkdir(parents=True, exist_ok=True)
    return path

# ─────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────

class Logger:
    def __init__(self, out_dir):
        self.out_dir  = out_dir
        self.findings = []
        self.xss      = []
        self.redirs   = []
        self.lock     = threading.Lock()
        self._seen    = set()

    def info(self,    msg): print(f"{C}[*]{RESET} {msg}")
    def success(self, msg): print(f"{BG}[+]{RESET} {msg}")
    def warn(self,    msg): print(f"{Y}[!]{RESET} {msg}")
    def error(self,   msg): print(f"{R}[-]{RESET} {msg}")

    def section(self, title):
        print(f"\n{M}{BOLD}{'─'*62}{RESET}")
        print(f"{M}{BOLD}  {title}{RESET}")
        print(f"{M}{BOLD}{'─'*62}{RESET}")

    def finding(self, secret_type, value, source, line=None):
        key = hashlib.md5(f"{secret_type}:{value}".encode()).hexdigest()
        with self.lock:
            if key in self._seen:
                return
            self._seen.add(key)
        sev   = get_severity(secret_type)
        color = SEV_COLOR.get(sev, Y)
        loc   = f" (line {line})" if line else ""
        disp  = value[:120] + ("…" if len(value) > 120 else "")
        print(f"  {color}[{sev}]{RESET} {BOLD}{secret_type}{RESET}")
        print(f"  {DIM}Source :{RESET} {source}{loc}")
        print(f"  {DIM}Value  :{RESET} {G}{disp}{RESET}\n")
        with self.lock:
            self.findings.append({"type":secret_type,"severity":sev,
                                  "value":value,"source":source,"line":line})

    def vuln(self, vtype, url, param, detail, evidence=""):
        # Deduplicate: strip query string for the key so same endpoint+param
        # isn't reported multiple times with different canary values
        parsed   = urllib.parse.urlparse(url)
        base_key = f"{vtype}:{parsed.netloc}{parsed.path}:{param}"
        with self.lock:
            if base_key in self._seen:
                return
            self._seen.add(base_key)

        color = R+BOLD if vtype == "Reflected XSS" else BR
        print(f"  {color}[{vtype}]{RESET} {BOLD}{url}{RESET}")
        print(f"  {DIM}Param   :{RESET} {Y}{param}{RESET}")
        print(f"  {DIM}Detail  :{RESET} {detail}")
        if evidence:
            print(f"  {DIM}Evidence:{RESET} {G}{evidence[:160]}{RESET}")
        print()
        entry = {"type": vtype, "url": url, "param": param,
                 "detail": detail, "evidence": evidence}
        with self.lock:
            if vtype == "Reflected XSS":
                self.xss.append(entry)
            else:
                self.redirs.append(entry)

    def save(self, domain, ts):
        data = {
            "domain": domain, "timestamp": ts,
            "secrets":   {"total": len(self.findings), "findings": self.findings},
            "xss":       {"total": len(self.xss),      "findings": self.xss},
            "redirects": {"total": len(self.redirs),   "findings": self.redirs},
        }
        jf = self.out_dir / f"secrets_{ts}.json"
        with open(jf, "w") as f:
            json.dump(data, f, indent=2)
        self.success(f"JSON  → {jf}")

        hf = self.out_dir / f"report_{ts}.html"
        self._save_html(hf, domain, ts)
        self.success(f"HTML  → {hf}")

    def _sev_bg(self, s):
        return {"CRITICAL":"#3d0000","HIGH":"#2d1500","MEDIUM":"#2d2500",
                "LOW":"#001530","INFO":"#001a30"}.get(s, "#111")

    def _sev_fg(self, s):
        return {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00",
                "LOW":"#4488ff","INFO":"#44ccff"}.get(s, "#888")

    def _save_html(self, path, domain, ts):
        th = "background:#1a1a2e;color:#c44dff;padding:10px;text-align:left;font-size:13px"

        def colored_sev(s):
            return f'<span style="color:{self._sev_fg(s)};font-weight:bold">{s}</span>'

        secret_rows = ""
        for f in sorted(self.findings,
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
                        .index(x["severity"])):
            secret_rows += (
                f"<tr>"
                f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a'>{colored_sev(f['severity'])}</td>"
                f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;font-weight:bold'>{f['type']}</td>"
                f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;font-family:monospace;"
                f"font-size:11px;word-break:break-all'>{f['value'][:200]}</td>"
                f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;font-size:11px'>{f['source']}</td>"
                f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a'>{f.get('line','')}</td>"
                f"</tr>"
            )

        def vuln_rows(items, color):
            out = ""
            for x in items:
                out += (
                    f"<tr>"
                    f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;"
                    f"color:{color};font-weight:bold'>{x['type']}</td>"
                    f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;"
                    f"font-size:11px;word-break:break-all'>{x['url']}</td>"
                    f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a'>{x['param']}</td>"
                    f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;"
                    f"font-size:11px'>{x['detail']}</td>"
                    f"<td style='padding:7px 10px;border-bottom:1px solid #1a1a1a;"
                    f"font-size:11px'>{x.get('evidence','')[:120]}</td>"
                    f"</tr>"
                )
            return out

        sev_counts = {}
        for f in self.findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        stat_html = "".join(
            f'<span style="background:{self._sev_bg(s)};color:{self._sev_fg(s)};'
            f'padding:6px 14px;border-radius:4px;margin:4px;display:inline-block;'
            f'font-weight:bold">{s}: {c}</span>'
            for s, c in sev_counts.items()
        )

        html = (
            f'<!DOCTYPE html><html><head><meta charset="utf-8">'
            f'<title>HackLens — {domain}</title>'
            f'<style>body{{background:#0d0d0d;color:#ddd;font-family:"Courier New",monospace;'
            f'padding:24px;margin:0}} h1{{color:#c44dff}} h2{{color:#ff6b6b;margin-top:32px}}'
            f'table{{width:100%;border-collapse:collapse;margin-top:12px}}'
            f'th{{{th}}} tr:hover{{background:#111}}</style></head><body>'
            f'<h1>🔍 HackLens Report</h1>'
            f'<p style="color:#888">Domain: <b style="color:#0ff">{domain}</b> &nbsp;|&nbsp; '
            f'Scan: {ts} &nbsp;|&nbsp; '
            f'Secrets: <b style="color:#f44">{len(self.findings)}</b> &nbsp;|&nbsp; '
            f'XSS: <b style="color:#f44">{len(self.xss)}</b> &nbsp;|&nbsp; '
            f'Redirects: <b style="color:#fa4">{len(self.redirs)}</b></p>'
            f'{stat_html}'
            f'<h2>🔑 Secrets ({len(self.findings)})</h2>'
            f'<table><tr>'
            f'<th style="{th}">Severity</th><th style="{th}">Type</th>'
            f'<th style="{th}">Value</th><th style="{th}">Source</th>'
            f'<th style="{th}">Line</th></tr>'
            f'{secret_rows}</table>'
            f'<h2>⚡ Reflected XSS ({len(self.xss)})</h2>'
            f'<table><tr>'
            f'<th style="{th}">Type</th><th style="{th}">URL</th>'
            f'<th style="{th}">Param</th><th style="{th}">Detail</th>'
            f'<th style="{th}">Evidence</th></tr>'
            f'{vuln_rows(self.xss, "#ff4444")}</table>'
            f'<h2>↩ Open Redirects ({len(self.redirs)})</h2>'
            f'<table><tr>'
            f'<th style="{th}">Type</th><th style="{th}">URL</th>'
            f'<th style="{th}">Param</th><th style="{th}">Detail</th>'
            f'<th style="{th}">Evidence</th></tr>'
            f'{vuln_rows(self.redirs, "#ff8800")}</table>'
            f'</body></html>'
        )
        with open(path, "w") as f:
            f.write(html)

# ─────────────────────────────────────────────
#  FALSE POSITIVE FILTER
# ─────────────────────────────────────────────

# JS code reference patterns — these are variable/property accesses, not real values
_CODE_RE = re.compile(
    r'this\.|self\.|config\.|options\.|settings\.|props\.|state\.'
    r'|process\.env|window\.|document\.|global\.\w'
    r'|\$\{[^}]*\}'        # template literals
    r'|function\s*[\(\{]'
    r'|=>\s*[\{\(]'
    r'|new\s+[A-Z]\w'
    r'|\.prototype\.'
    r'|require\s*\('
    r'|import\s+\w'
    r'|return\s+\w+'
    r'|typeof\s+\w'
    r'|instanceof\s+\w',
    re.IGNORECASE
)

_PLACEHOLDER_RE = re.compile(
    r'\byour[_\-]?\b|<\w+>|\[.*?\]'
    r'|\bexample\b|\bplaceholder\b|\bdummy\b'
    r'|\bchangeme\b|\breplace[_\-]?me\b|\binsert[_\-]?\b'
    r'|\benter[_\-]?\b|\btodo\b|\bfixme\b|\btest123\b'
    r'|\bmy[_\-]?(api|secret|key|token|password)\b'
    r'|\bhere\b$|\bn/a\b|\bnone\b|\bundefined\b|\bempty\b|\bsample\b',
    re.IGNORECASE
)

def _low_entropy(s):
    core = re.sub(r'[^A-Za-z0-9]', '', s)
    if len(core) < 10:
        return False
    return len(set(core)) <= 3

_VERSION_RE = re.compile(r'^\d+\.\d+[\.\d\-a-z]*$', re.IGNORECASE)

def is_false_positive(value, pattern_name):
    v = value.strip()

    # 0. Skip anything that came from a data: URI (base64 image/font data)
    # These contain random binary-looking sequences that match many patterns
    if re.search(r'^data:[a-z/+]+;base64,', v, re.I):
        return True
    # Skip if value itself looks like raw base64 (long alphanum, no spaces, >80 chars)
    # that doesn't match any specific known format
    if len(v) > 80 and re.match(r'^[A-Za-z0-9+/=]{80,}$', v):
        if pattern_name not in (
            "AWS Secret Key", "Azure Storage Key", "OpenAI Key (old)",
            "OpenAI Key (proj)", "Anthropic Key", "Generic Private Key Val",
        ):
            return True

    # 1. Code reference
    if _CODE_RE.search(v):
        return True

    # 2. Placeholder text
    if _PLACEHOLDER_RE.search(v):
        return True

    # 3. Low entropy (aaaaaaa, 111111111, etc.)
    if _low_entropy(v):
        return True

    # 4. Extract the actual secret portion (strip surrounding context words)
    core = re.sub(
        r'(?i)(?:api[_\-]?key|token|secret|password|heroku|bearer)'
        r'[\s\'"=:,]+', '', v
    ).strip('\'"` ')

    # 5. Version string
    if _VERSION_RE.match(core):
        return True

    # 6. Pure JS identifier (camelCase/snake_case variable name, no digits/specials)
    if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', core) and len(core) < 32:
        return True

    # 7. Value is clearly too short to be a real secret
    if len(core.replace('-', '').replace('_', '')) < 8:
        return True

    # ── Pattern-specific checks ──────────────────
    if pattern_name == "JWT Token":
        parts = v.split(".")
        if len(parts) != 3 or any(len(p) < 10 for p in parts):
            return True

    if pattern_name == "Bearer Token":
        tok = re.sub(r'(?i)bearer\s+', '', v).strip()
        # If it's just a JS identifier or short, it's a variable reference
        if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$.]*$', tok) and len(tok) < 25:
            return True

    if pattern_name == "Basic Auth URL":
        m = re.search(r'://[^:]+:([^@]+)@', v)
        if m:
            pw = m.group(1)
            if _PLACEHOLDER_RE.search(pw) or len(pw) < 6:
                return True

        # If the extracted value matches a JS identifier it's not a real password
        m = re.search(r':\s*["\']([^\'"]+)["\']', v)
        if m and re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', m.group(1)):
            return True

    if pattern_name == "Internal IP":
        # Skip documentation-standard IPs
        if re.search(r'(?:10\.0\.0\.[12]|192\.168\.[01]\.[12])$', v):
            return True

    if pattern_name == "Telegram Bot Token":
        m = re.match(r'(\d+):', v)
        if m and not (8 <= len(m.group(1)) <= 10):
            return True

    if pattern_name == "AWS ARN":
        # ARNs are INFO level — only FP if they look like a template
        if ':*:' in v or v.endswith(':'):
            return True

    return False

# ─────────────────────────────────────────────
#  SCOPE ENFORCEMENT
# ─────────────────────────────────────────────

def is_in_scope(url, target_domain):
    """
    Return True only if the URL belongs to the target domain or a subdomain.
    Prevents scanning/reporting on out-of-scope URLs like twitter.com, youtube.com, etc.
    """
    try:
        host = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
        t    = target_domain.lower().split(":")[0]
        return host == t or host.endswith("." + t)
    except Exception:
        return False

def filter_in_scope(urls, target_domain):
    """Filter a collection of URLs to only in-scope ones."""
    return [u for u in urls if is_in_scope(u, target_domain)]


# ─────────────────────────────────────────────
#  SECRET SCANNER
# ─────────────────────────────────────────────

class SecretScanner:
    def __init__(self, log, session, target_domain=""):
        self.log           = log
        self.session       = session
        self.scanned       = 0
        self.target_domain = target_domain

    # Memory thresholds
    MAX_BEAUTIFY_SIZE = 512 * 1024        # 512 KB — only beautify small JS
                                          # jsbeautifier uses 10-50x input RAM
    CHUNK_SIZE        = 2 * 1024 * 1024   # 2 MB chunks for large file scanning
    # NO hard skip limit — large vendor bundles are prime secret targets

    def scan_content(self, content, source, content_type=""):
        if not content or len(content) < 30:
            return

        ct    = content_type.lower()
        is_js = any(x in source.lower() for x in (".js", ".jsx", ".ts", ".tsx", ".mjs")) or "javascript" in ct or ".map" in source.lower()
        size  = len(content)

        if is_js and size <= self.MAX_BEAUTIFY_SIZE:
            # Small JS — beautify for better line detection
            try:
                text = jsbeautifier.beautify(content)
            except Exception:
                text = content
            self._scan_text(text, source)
            del text

        elif size > self.MAX_BEAUTIFY_SIZE:
            # Large file (JS or otherwise) — scan in overlapping chunks
            # so we never hold the full beautified version in RAM.
            # Secrets in minified code are always in string literals —
            # raw scanning catches them just as reliably.
            self._scan_chunked(content, source)

        else:
            # Small non-JS — scan raw
            self._scan_text(content, source)

        self.scanned += 1

    def _scan_text(self, text, source):
        """Run all 162 patterns against a text string."""
        for pat_name, pattern in SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, text, re.MULTILINE):
                    val      = m.group(0)
                    line_num = text[:m.start()].count('\n') + 1
                    if not is_false_positive(val, pat_name):
                        self.log.finding(pat_name, val, source, line_num)
            except re.error:
                pass

    def _scan_chunked(self, content, source):
        """
        Scan large files in overlapping 2MB chunks.
        Overlap of 500 bytes ensures secrets spanning chunk boundaries
        are never missed.
        Uses a single chunk at a time in memory — O(chunk_size) RAM
        regardless of total file size.
        """
        size    = len(content)
        overlap = 500   # bytes — long enough to cover any single secret
        offset  = 0
        chunk_num = 0

        while offset < size:
            end   = min(offset + self.CHUNK_SIZE, size)
            chunk = content[offset:end]

            for pat_name, pattern in SECRET_PATTERNS.items():
                try:
                    for m in re.finditer(pattern, chunk, re.MULTILINE):
                        val = m.group(0)
                        # Approximate line number relative to start of file
                        approx_line = content[:offset + m.start()].count('\n') + 1
                        if not is_false_positive(val, pat_name):
                            self.log.finding(pat_name, val, source, approx_line)
                except re.error:
                    pass

            del chunk
            chunk_num += 1
            # Advance with overlap so secrets at boundaries aren't missed
            offset = end - overlap if end < size else size

    def scan_url(self, url):
        # Skip out-of-scope URLs
        if self.target_domain and not is_in_scope(url, self.target_domain):
            return
        try:
            # HEAD request first — check content type before downloading
            try:
                head    = self.session.head(url, timeout=8, allow_redirects=True)
                ct_head = head.headers.get("Content-Type", "").lower()
                # Skip purely binary types — no secrets in images/fonts/archives
                if any(x in ct_head for x in (
                    "image/", "video/", "audio/", "font/",
                    "application/zip", "application/pdf",
                    "application/octet-stream",
                )):
                    return
            except Exception:
                pass  # HEAD failed — try GET anyway

            r = self.session.get(url, timeout=20)
            if r.status_code == 200 and len(r.content) > 50:
                ct = r.headers.get("Content-Type", "")
                self.scan_content(r.text, url, ct)
                del r
        except Exception:
            pass
        except Exception:
            pass

    BATCH_SIZE = 200   # Process URLs in batches to prevent memory buildup

    def scan_parallel(self, urls, workers=10):
        total = len(urls)
        self.log.section(f"STEP 3: Scanning {total} files for Secrets")

        # Cap workers to prevent OOM — more workers = more simultaneous
        # JS files loaded in RAM. 5 is a good balance of speed vs memory.
        safe_workers = min(workers, 5)
        if workers > safe_workers:
            self.log.info(f"Workers capped at {safe_workers} (memory safety — use -w 5 to suppress)")

        done = 0
        # Process in batches — completed futures are GC'd between batches
        for i in range(0, total, self.BATCH_SIZE):
            batch = urls[i:i + self.BATCH_SIZE]
            with ThreadPoolExecutor(max_workers=safe_workers) as ex:
                futs = {ex.submit(self.scan_url, u): u for u in batch}
                for fut in as_completed(futs):
                    done += 1
                    if done % 100 == 0:
                        pct = int(done / total * 100)
                        self.log.info(f"Progress: {done}/{total} ({pct}%) scanned…")
            # Force GC between batches
            gc.collect()

# ─────────────────────────────────────────────
#  REFLECTED XSS SCANNER
#
#  Strategy (zero false positives by design):
#
#  Phase 1 — REFLECTION CHECK
#    Inject a unique random canary string (no HTML/JS meaning).
#    If the canary appears VERBATIM and UN-ENCODED in the response
#    we have confirmed reflection. Only then proceed to Phase 2.
#
#  Phase 2 — CONTEXT DETECTION
#    Parse where in the HTML the canary landed:
#      html_body      → between tags
#      attr_double    → inside a double-quoted attribute
#      attr_single    → inside a single-quoted attribute
#      attr_unquoted  → unquoted attribute value
#      js_string_dq   → inside a JS double-quoted string
#      js_string_sq   → inside a JS single-quoted string
#      js_code        → bare inside a <script> block (no quotes)
#      url_param      → reflected inside a href/src/action value
#
#  Phase 3 — CONTEXT-SPECIFIC PAYLOAD
#    Choose the minimal payload that exploits THAT context.
#    Verify the payload is also reflected unencoded.
#    Only report if BOTH canary AND payload are confirmed.
#
#  Result: every finding is a proven exploitable reflection.
# ─────────────────────────────────────────────

import string, random

def _random_canary(n=12):
    """Generate a short alphanumeric canary with no HTML/JS meaning."""
    return "SHXSS" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _html_encode(s):
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
             .replace('"',"&quot;").replace("'","&#x27;"))

def _is_html_response(resp):
    ct = resp.headers.get("Content-Type","").lower()
    return "html" in ct or ("text/" in ct and "javascript" not in ct)

# Context-specific XSS payloads
# Each returns (payload_to_inject, regex_that_proves_execution_context)
def _payload_for_context(ctx, canary):
    if ctx == "html_body":
        # Inject a tag directly
        p = f'<img src=x id={canary} onerror=alert(1)>'
        r = rf'<img\s[^>]*id={canary}[^>]*onerror=alert\(1\)'
        return p, r
    elif ctx in ("attr_double",):
        # Break out of double-quoted attribute
        p = f'" onfocus=alert(1) autofocus data-x="{canary}'
        r = rf'onfocus=alert\(1\)\s+autofocus'
        return p, r
    elif ctx in ("attr_single",):
        p = f"' onfocus=alert(1) autofocus data-x='{canary}"
        r = rf'onfocus=alert\(1\)\s+autofocus'
        return p, r
    elif ctx == "attr_unquoted":
        # For attr_unquoted we need to close the tag first, then inject a new tag.
        # Simply injecting onfocus= is unreliable since we don't know the tag type.
        # Close the current attribute + tag, inject a standalone script-executing tag.
        p = f"><img src=x id={canary} onerror=alert(1)><x "
        r = rf'<img\s[^>]*id={canary}[^>]*onerror=alert\(1\)'
        return p, r
    elif ctx == "js_string_dq":
        # Break out of JS double-quoted string
        p = f'"-alert(1)-"{canary}'
        r = rf'"-alert\(1\)-"'
        return p, r
    elif ctx == "js_string_sq":
        p = f"'-alert(1)-'{canary}"
        r = rf"'-alert\(1\)-'"
        return p, r
    elif ctx == "js_code":
        # Already in JS code context (not a string) — inject statement separator + call
        # Using a unique function name so we can verify it's not inside a string
        p = f";/*{canary}*/alert(1)//"
        r = rf'/\*{re.escape(canary)}\*/alert\(1\)//'
        return p, r
    elif ctx == "url_param":
        # javascript: URI
        p = f'javascript:alert(1)//{canary}'
        r = rf'javascript:alert\(1\)'
        return p, r
    else:
        # Generic fallback — try html_body approach
        p = f'<svg id={canary} onload=alert(1)>'
        r = rf'<svg\s[^>]*id={canary}[^>]*onload=alert\(1\)'
        return p, r


def _detect_context(canary, response_text):
    """
    Find where exactly the canary landed in the HTML.
    Returns context string or None if not reflected / is encoded.
    """
    # Check encoded version is NOT present (would mean safe encoding)
    encoded = _html_encode(canary)
    
    # Find raw canary position
    idx = response_text.find(canary)
    if idx == -1:
        return None  # not reflected at all
    
    # Check if it appears encoded instead
    if encoded != canary and encoded in response_text and canary not in response_text:
        return None  # only appears encoded → not vulnerable
    
    # Get surrounding context (200 chars before)
    before = response_text[max(0, idx-200):idx]
    after  = response_text[idx:idx+200]
    
    # ── Are we inside a <script> block? ──────────────────
    # Find last <script and last </script> before our position
    script_open  = before.rfind("<script")
    script_close = before.rfind("</script")
    in_script = script_open != -1 and script_open > script_close
    
    if in_script:
        # ── Check if this is a JSON data block (not executable JS) ──
        # Next.js: <script id="__NEXT_DATA__" type="application/json">
        # Nuxt:    <script type="application/json" id="__NUXT_DATA__">
        # These embed data as JSON — NOT executable JS code.
        # Injecting ;alert(1) inside JSON just produces invalid JSON, not XSS.
        script_tag_text = response_text[max(0, idx-500):idx]
        script_tag_start = script_tag_text.rfind("<script")
        if script_tag_start != -1:
            script_tag_snippet = script_tag_text[script_tag_start:script_tag_start+200]
            # Detect data-only script blocks
            if re.search(
                r'type=["\'](application/(?:json|ld\+json))["\']|'
                r'id=["\'](?: __NEXT_DATA__|__NUXT_DATA__|__NUXT__|__RELAY_STORE__|__REDUX_STATE__|initial-state)["\']|'
                r'type=["\']text/template["\']',
                script_tag_snippet, re.I
            ):
                return None  # JSON data block — not executable JS

        # Inside executable JS — find string context
        code_before = before[script_open:]
        dq = code_before.count('"') - code_before.count('\"')
        sq = code_before.count("'") - code_before.count("\'")
        if dq % 2 == 1:
            return "js_string_dq"
        if sq % 2 == 1:
            return "js_string_sq"
        return "js_code"
    
    # ── Are we inside an HTML tag attribute? ─────────────
    # Find last < and > before our canary
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    in_tag  = last_lt != -1 and last_lt > last_gt
    
    if in_tag:
        # What kind of attribute quoting?
        tag_content = before[last_lt:]
        # Find last = sign
        last_eq = tag_content.rfind("=")
        if last_eq != -1:
            after_eq = tag_content[last_eq+1:].lstrip()
            if after_eq.startswith('"'):
                return "attr_double"
            elif after_eq.startswith("'"):
                return "attr_single"
            else:
                return "attr_unquoted"
        return "attr_unquoted"
    
    # ── Are we inside href/src/action (URL context)? ─────
    if re.search(r'(?:href|src|action|data)\s*=\s*["\'][^"\']*$', before, re.I):
        return "url_param"
    
    # ── Default: HTML body ────────────────────────────────
    return "html_body"


# Params most likely to reflect user input into HTML
XSS_REFLECT_PARAMS = {
    'q','query','search','s','keyword','term','text','name','title',
    'message','msg','content','data','input','value','val','username',
    'user','email','callback','jsonp','ref','referrer','page','id',
    'error','code','status','action','filter','sort','order','category',
    'tag','label','from','subject','body','comment','description',
    'template','tpl','lang','locale','format','type','view','src',
    'source','dest','target','file','path','item','product','article',
    'post','slug','token','key','hash','param','output','render',
    'return','next','redirect',
}


class XSSScanner:
    def __init__(self, log, session, target_domain=""):
        self.log           = log
        self.session       = session
        self.tested        = set()
        self.target_domain = target_domain

    def _build_url(self, base_url, params, param, value):
        parsed = urllib.parse.urlparse(base_url)
        qs = dict(params)
        qs[param] = value
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    @staticmethod
    def _normalize_url(url):
        """
        Strip scheme + sort query params for dedup purposes.
        http://example.com/page?b=1&a=2  ==  https://example.com/page?a=2&b=1
        """
        p = urllib.parse.urlparse(url)
        qs = sorted(urllib.parse.parse_qsl(p.query))
        norm = f"{p.netloc}{p.path}?{urllib.parse.urlencode(qs)}"
        return norm

    def _test_param(self, base_url, all_params, param):
        # Skip out-of-scope URLs entirely
        if self.target_domain and not is_in_scope(base_url, self.target_domain):
            return

        # Deduplicate by normalised URL + param — ignores http/https duplicates
        norm = self._normalize_url(base_url)
        dedup = f"xss:{norm}:{param}"
        if dedup in self.tested:
            return
        self.tested.add(dedup)

        # ── Phase 1: Reflection check with canary ────────
        canary   = _random_canary()
        test_url = self._build_url(base_url, all_params, param, canary)
        try:
            r1 = self.session.get(test_url, timeout=10, allow_redirects=True)
        except Exception:
            return

        if not _is_html_response(r1):
            return  # not HTML, skip

        # ── Phase 2: Context detection ───────────────────
        ctx = _detect_context(canary, r1.text)
        if ctx is None:
            return  # canary not reflected or was encoded

        # ── Phase 3: Context-specific payload ────────────
        payload, pattern = _payload_for_context(ctx, canary)
        payload_url = self._build_url(base_url, all_params, param, payload)
        try:
            r2 = self.session.get(payload_url, timeout=10, allow_redirects=True)
        except Exception:
            return

        if not _is_html_response(r2):
            return

        # Payload must appear unencoded in response — pattern must match
        if not re.search(pattern, r2.text, re.IGNORECASE):
            return  # payload not confirmed in response → not reporting

        # Extra check for attribute contexts: verify the payload broke out
        if ctx in ("attr_double", "attr_single", "attr_unquoted"):
            encoded_payload = _html_encode(payload)
            if payload not in r2.text and encoded_payload in r2.text:
                return  # only appears HTML-encoded → safe
            if not re.search(rf'<img[^>]*id={canary}[^>]*onerror', r2.text, re.I):
                if not re.search(rf'onfocus=alert\(1\)', r2.text, re.I):
                    return

        # Extra check for js_code: verify it's NOT inside a quoted string
        # (i.e. the semicolon must not appear inside "value":"payload" JSON)
        if ctx == "js_code":
            m = re.search(re.escape(payload[:20]), r2.text)
            if m:
                idx = m.start()
                before_payload = r2.text[max(0, idx-30):idx]
                # If the char before our payload is a quote, it's still inside a string
                if re.search(r'["\'\`]\s*$', before_payload):
                    return  # inside a quoted string → not executable JS code

        # ── Confirmed XSS — report ONCE with clean PoC URL ──
        # Build a clean PoC URL using https and a fixed canary for readability
        clean_payload = payload.replace(canary, "SHXSS")
        clean_url = self._build_url(
            base_url.replace("http://", "https://"), all_params, param, clean_payload
        )
        self.log.vuln(
            "Reflected XSS",
            clean_url,
            param,
            f"Context: {ctx} | Reflected unencoded | Payload verified in response",
            f"PoC: {clean_url}"
        )

    def scan_urls(self, urls, workers=8):
        self.log.section(f"STEP 4: XSS Scanning {len(urls)} URLs")

        # Build task list — test ALL params, prioritise known-reflection ones first
        priority_tasks = []   # known reflection params → test first
        secondary_tasks = []  # all other params
        seen_norm = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            if not params:
                continue
            norm = self._normalize_url(url)
            for param in params:
                key = f"{norm}:{param}"
                if key in seen_norm:
                    continue
                seen_norm.add(key)
                if param.lower() in XSS_REFLECT_PARAMS:
                    priority_tasks.append((url, params, param))
                else:
                    secondary_tasks.append((url, params, param))

        # Priority params first, then all others
        tasks = priority_tasks + secondary_tasks

        if not tasks:
            self.log.warn("No URL params found to test for XSS")
            return

        self.log.info(
            f"Testing {len(tasks)} unique param/URL combinations for XSS "
            f"({len(priority_tasks)} priority + {len(secondary_tasks)} secondary)…"
        )
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self._test_param, u, p, param) for u, p, param in tasks]
            for fut in as_completed(futs):
                pass

# ─────────────────────────────────────────────
#  OPEN REDIRECT SCANNER
# ─────────────────────────────────────────────

# Params that are NEVER open redirect sinks regardless of their value
# They may contain URLs but only for analytics/tracking, not actual redirects
_NON_REDIRECT_PARAMS = {
    # Analytics / tracking — carry URLs but never redirect the browser
    'utm_source','utm_medium','utm_campaign','utm_term','utm_content',
    'utm_id','utm_name','fbclid','gclid','msclkid','twclid',
    'ref','referrer','referer','source','medium','campaign',
    # Sharing / social metadata
    'og_url','canonical','share_url','share','via',
    # Pagination / display — numeric/text, not URL sinks
    'page','per_page','limit','offset','sort','order','dir',
    'tab','section','anchor','hash','view','layout','theme',
    # Search / filter — reflect text into results, not redirects
    'q','query','search','keyword','filter','labels','tags',
    # Content identifiers
    'id','slug','post','article','item','product','category',
    'sku','asin','isbn','code',
    # Misc non-redirect
    'format','type','lang','locale','currency','country',
    'secret','param','key','token','nonce','csrf',
}


REDIRECT_PARAMS = {
    'next','redirect','redirect_uri','redirect_url','redirecturi','redirecturl',
    'return','return_url','returnurl','returnto','return_to','goto','go',
    'url','uri','dest','destination','target','redir','r','link','forward',
    'fwd','location','continue','cont','back','backurl','success_url',
    'cancel_url','checkout_url','exit','out','view','ref','referrer',
    'callback','next_url','nexturl','to','from','origin','path','homepage',
}

# Canary domain — totally external, easy to detect in Location header
_CANARY = "evil.com"

REDIRECT_PROBES = [
    f"https://{_CANARY}",              # standard https
    f"http://{_CANARY}",               # standard http
    f"//{_CANARY}",                    # protocol-relative
    f"https://{_CANARY}/",             # trailing slash variant
    f"https://{_CANARY}/%2F..",        # path traversal
    f"@{_CANARY}",                     # @ confusion
    f"////{_CANARY}",                  # multiple slashes
    f"\t{_CANARY}",                    # tab prefix bypass
    f"https:{_CANARY}",                # no-slash variant
    f"/%09/{_CANARY}",                 # horizontal tab in path
    f"https://{_CANARY}@target.com",   # credential confusion
    f"https://target.com@{_CANARY}",   # reversed credential confusion
    f"https://{_CANARY}%23.target.com",# fragment confusion
]


class RedirectScanner:
    def __init__(self, log, session, target_domain):
        self.log    = log
        self.sess   = session
        self.target = target_domain
        self.tested = set()

    # ── Domain helpers ────────────────────────────────────────────────────

    def _root_domain(self, host):
        """Extract root domain from host: sub.example.com → example.com"""
        host = host.lower().split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    def _is_offsite(self, netloc):
        """True if netloc is NOT the target domain or a subdomain."""
        if not netloc:
            return False
        host = netloc.lower().split(":")[0]
        t    = self.target.lower().split(":")[0]
        return not (host == t or host.endswith("." + t))

    def _is_canary_host(self, netloc):
        """True if netloc IS the canary domain (evil.com), not just contains it."""
        host = netloc.lower().split(":")[0]
        return host == _CANARY.lower() or host.endswith("." + _CANARY.lower())

    def _canary_is_only_param(self, url):
        """
        Returns True if evil.com appears ONLY as a query parameter value,
        not as the actual host. This is the core FP check.
        e.g. https://gcore.com/login?return=https://evil.com → True (FP)
             https://evil.com/malicious                      → False (real)
        """
        parsed = urllib.parse.urlparse(url)
        # If evil.com IS the host — it's a real redirect
        if self._is_canary_host(parsed.netloc):
            return False
        # If evil.com appears in query string but host is something else — FP
        if _CANARY in parsed.query or _CANARY in parsed.path:
            return True
        return False

    # ── Known benign redirect pairs ───────────────────────────────────────
    # Same company domain migrations / aliases — NOT vulnerabilities
    _BENIGN_PAIRS = [
        ("twitter.com",   "x.com"),
        ("x.com",         "twitter.com"),
        ("fb.com",        "facebook.com"),
        ("youtu.be",      "youtube.com"),
        ("goo.gl",        "google.com"),
    ]

    def _is_benign_alias(self, from_host, to_host):
        """True if this is a known domain alias/migration, not a vuln."""
        from_root = self._root_domain(from_host)
        to_root   = self._root_domain(to_host)
        # Same root domain (gcorelabs.com → gcore.com are DIFFERENT roots)
        # Only flag known pairs
        for a, b in self._BENIGN_PAIRS:
            if from_root == a and to_root == b:
                return True
            if from_root == b and to_root == a:
                return True
        return False

    # ── Three confirmed detection layers ─────────────────────────────────

    def _check_layer1_location(self, r, test_url, param, probe):
        """
        Layer 1 — Raw Location header (allow_redirects=False).

        CONFIRMED: Location header HOST is evil.com
        SKIP:      Location header HOST is anything else (even if query contains evil.com)

        This eliminates 100% of the gcorelabs→gcore FP pattern because:
          Location: https://gcore.com/login?return=https://evil.com
          → host = gcore.com (NOT evil.com) → SKIP
        """
        if r.status_code not in (301, 302, 303, 307, 308):
            return False
        loc = r.headers.get("Location", "").strip()
        if not loc:
            return False

        pl = urllib.parse.urlparse(loc)

        # Relative redirect — always on-site
        if not pl.scheme and not pl.netloc:
            return False

        dest_host = pl.netloc.lower().split(":")[0]

        # RULE: canary must BE the destination host
        if self._is_canary_host(pl.netloc):
            self.log.vuln(
                "Open Redirect [CONFIRMED]", test_url, param,
                f"Browser redirected TO evil.com | HTTP {r.status_code}",
                f"Location: {loc}"
            )
            return True

        return False

    def _check_layer2_chain(self, r, test_url, param, probe):
        """
        Layer 2 — Follow full redirect chain (allow_redirects=True).

        CONFIRMED: Final URL host IS evil.com after all redirects
        CONFIRMED: Any hop in the chain has Location host = evil.com

        Skips hops where evil.com is only in query params.
        """
        # Check final landing URL
        final = urllib.parse.urlparse(r.url)
        if self._is_canary_host(final.netloc):
            self.log.vuln(
                "Open Redirect [CONFIRMED]", test_url, param,
                f"Final URL after redirect chain IS evil.com",
                f"Final: {r.url}"
            )
            return True

        # Check each hop in history
        for hop in r.history:
            loc = hop.headers.get("Location", "").strip()
            if not loc:
                continue
            pl = urllib.parse.urlparse(loc)
            if not pl.netloc:
                continue
            # ONLY report if evil.com is the actual host, not a param value
            if self._is_canary_host(pl.netloc):
                self.log.vuln(
                    "Open Redirect [CONFIRMED]", test_url, param,
                    f"Redirect chain hop to evil.com | HTTP {hop.status_code}",
                    f"Location: {loc}"
                )
                return True

        return False

    def _check_layer3_body(self, r, test_url, param, probe):
        """
        Layer 3 — Response body analysis.

        CONFIRMED [LOW]: evil.com in <meta http-equiv=refresh> destination
        ONE-CLICK [LOW]: evil.com in <a href> — user must click to be redirected
        ONE-CLICK [LOW]: evil.com in window.location / location.href JS assignment
                         that is triggered by user action (not auto-executed)

        NOT REPORTED: evil.com just reflected in page text / input values
        """
        ct = r.headers.get("Content-Type", "").lower()
        if "html" not in ct:
            return False

        body = r.text

        if _CANARY not in body:
            return False

        # ── Meta-refresh (auto-executes) → CONFIRMED ──────────────────
        m = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+'
            r'content=["\']?[^"\']*url\s*=\s*([^"\'>\s;]+)',
            body, re.I
        )
        if m:
            dest = m.group(1).strip().strip('"\')')
            pd = urllib.parse.urlparse(dest)
            if self._is_canary_host(pd.netloc):
                self.log.vuln(
                    "Open Redirect [CONFIRMED]", test_url, param,
                    f"Meta-refresh auto-redirects to evil.com",
                    f"<meta refresh> → {dest[:120]}"
                )
                return True

        # ── <a href> with evil.com → ONE-CLICK LOW ─────────────────────
        # Must be a proper anchor tag href pointing to evil.com
        a_matches = re.findall(
            rf'<a\s[^>]*href=["\']?(https?://[^"\'\s>]*{re.escape(_CANARY)}[^"\'\s>]*)["\']?[^>]*>',
            body, re.I
        )
        for href in a_matches:
            ph = urllib.parse.urlparse(href)
            if self._is_canary_host(ph.netloc):
                self.log.vuln(
                    "One-Click Redirect [LOW]", test_url, param,
                    f"evil.com in <a href> — user click required to redirect",
                    f'<a href="{href[:120]}">'
                )
                return True

        # ── window.location / location.href JS assignment ──────────────
        # Only report if it's directly assigned (not inside a function condition)
        _q = r'''["\']'''
        js_redirect_patterns = [
            rf'window\.location\.href\s*=\s*{_q}[^"\']*{re.escape(_CANARY)}[^"\']*{_q}',
            rf'window\.location\.replace\s*\(\s*{_q}[^"\']*{re.escape(_CANARY)}[^"\']*{_q}\s*\)',
            rf'window\.location\.assign\s*\(\s*{_q}[^"\']*{re.escape(_CANARY)}[^"\']*{_q}\s*\)',
            rf'window\.location\s*=\s*{_q}[^"\']*{re.escape(_CANARY)}[^"\']*{_q}',
            rf'location\.href\s*=\s*{_q}[^"\']*{re.escape(_CANARY)}[^"\']*{_q}',
        ]
        for pat in js_redirect_patterns:
            m = re.search(pat, body, re.I)
            if m:
                snippet = m.group(0)
                # Make sure evil.com is the HOST in this URL, not just in params
                urls_in_snippet = re.findall(r'https?://[^\s\'"]+', snippet)
                for u in urls_in_snippet:
                    pu = urllib.parse.urlparse(u)
                    if self._is_canary_host(pu.netloc):
                        self.log.vuln(
                            "One-Click Redirect [LOW]", test_url, param,
                            f"evil.com in JS location assignment",
                            f"{snippet[:120]}"
                        )
                        return True

        return False

    # ── Main test ─────────────────────────────────────────────────────────

    def _build_url(self, base_url, params, param, value):
        parsed = urllib.parse.urlparse(base_url)
        qs = dict(params)
        qs[param] = value
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    def _test_param(self, base_url, all_params, param):
        """Test one parameter against all redirect probes."""
        # Skip out-of-scope
        if self.target and not is_in_scope(base_url, self.target):
            return

        # Skip analytics / non-redirect params
        if param.lower().rstrip("[]") in _NON_REDIRECT_PARAMS:
            return

        # One confirmed hit per param is enough
        param_key = f"redir:{base_url}:{param}"
        if param_key in self.tested:
            return
        self.tested.add(param_key)

        for probe in REDIRECT_PROBES:
            test_url = self._build_url(base_url, all_params, param, probe)
            try:
                # Pass 1: no redirect following — see raw Location header
                r_raw = self.sess.get(test_url, timeout=10, allow_redirects=False)

                if self._check_layer1_location(r_raw, test_url, param, probe):
                    return  # confirmed

                # If server redirected (3xx), also check body for meta-refresh
                if self._check_layer3_body(r_raw, test_url, param, probe):
                    return

                # Pass 2: follow full chain — see where we actually land
                if r_raw.status_code in (301, 302, 303, 307, 308):
                    try:
                        r_follow = self.sess.get(
                            test_url, timeout=10,
                            allow_redirects=True, max_redirects=8
                        )
                        if self._check_layer2_chain(r_follow, test_url, param, probe):
                            return
                        # Also check body of final page
                        if self._check_layer3_body(r_follow, test_url, param, probe):
                            return
                    except requests.TooManyRedirects:
                        pass

            except requests.TooManyRedirects:
                pass
            except Exception:
                pass

    def _generate_extra_urls(self, base_domain):
        """Test common auth endpoints proactively."""
        paths = [
            "/login", "/logout", "/signin", "/signout", "/auth",
            "/oauth/authorize", "/sso", "/redirect", "/go", "/out",
            "/exit", "/saml/sso", "/auth/callback", "/account/login",
            "/user/login", "/admin/login", "/api/auth/login",
        ]
        top_params = [
            "url", "next", "redirect", "return", "goto", "dest",
            "target", "redir", "redirect_url", "return_url",
            "redirect_uri", "back", "continue",
        ]
        extra = []
        for path in paths:
            for param in top_params:
                url = f"https://{base_domain}{path}"
                extra.append((url, {param: f"https://{_CANARY}"}, param))
        return extra

    def scan_urls(self, urls, workers=8):
        self.log.section(f"STEP 5: Open Redirect Scanning {len(urls)} URLs")

        priority  = []
        secondary = []
        seen      = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for param, value in params.items():
                pkey = f"{parsed.netloc}{parsed.path}:{param}"
                if pkey in seen:
                    continue
                seen.add(pkey)
                is_redir   = param.lower().rstrip("[]") in REDIRECT_PARAMS
                looks_like = value.lower().startswith(("http://","https://","//","www."))
                if is_redir or looks_like:
                    priority.append((url, params, param))
                else:
                    secondary.append((url, params, param))

        # Add proactive auth endpoint tests
        domain = urllib.parse.urlparse(urls[0]).netloc if urls else ""
        if domain:
            for item in self._generate_extra_urls(domain):
                pkey = f"{urllib.parse.urlparse(item[0]).path}:{item[2]}"
                if pkey not in seen:
                    seen.add(pkey)
                    priority.append(item)

        tasks = priority + secondary
        if not tasks:
            self.log.warn("No URLs found for redirect testing")
            return

        self.log.info(
            f"Testing {len(tasks)} redirect combinations "
            f"({len(priority)} priority + {len(secondary)} secondary)…"
        )
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self._test_param, u, p, param) for u, p, param in tasks]
            for fut in as_completed(futs):
                pass


# ─────────────────────────────────────────────
#  ENDPOINT & URL EXTRACTOR
# ─────────────────────────────────────────────

class EndpointExtractor:
    PATTERNS = [
        r'[\'"`](/api/[^\'"` \n\r\)>]+)',
        r'[\'"`](/v[0-9]+/[^\'"` \n\r\)>]+)',
        r'fetch\s*\(\s*[\'"`]([^\'"` \n\r\)]+)[\'"`]',
        r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"` \n\r\)]+)[\'"`]',
        r'(?:url|endpoint|path|href)\s*:\s*[\'"`]([^\'"` \n\r\)]+)[\'"`]',
        r'(?:BASE_URL|API_URL|API_ENDPOINT|BASE_PATH)\s*[=:]\s*[\'"`]([^\'"` \n\r\)]+)[\'"`]',
        r'(?:window\.location|location\.href)\s*=\s*[\'"`]([^\'"` \n\r\)]+)[\'"`]',
    ]

    def __init__(self, log):
        self.log       = log
        self.endpoints = set()
        self.all_urls  = set()

    # Patterns that are never real API endpoints
    _EP_SKIP_RE = re.compile(
        r'^#'               # fragment anchors (#cart, #image0)
        r'|^data:'          # data: URIs (data:image/png;base64,...)
        r'|^javascript:'    # js: URIs
        r'|^mailto:'        # mailto links
        r'|^tel:'           # phone links
        r'|\.(?:png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|pdf|zip)(?:\?|$)'
        , re.IGNORECASE
    )

    def extract(self, content, source, base_url=""):
        # Skip base64/data URIs in content entirely
        content_clean = re.sub(r'data:[a-z/+]+;base64,[A-Za-z0-9+/=]+', '', content, flags=re.I)

        for pat in self.PATTERNS:
            for m in re.finditer(pat, content_clean, re.IGNORECASE):
                ep = m.group(1).strip()

                # Basic length + template literal check
                if len(ep) < 4 or any(c in ep for c in ('`', '{', '}')):
                    continue

                # Skip fragments, data URIs, media files
                if self._EP_SKIP_RE.search(ep):
                    continue

                # Skip SVG-style IDs (#image0, #image0_1305_3534)
                if re.match(r'#[a-z]+\d', ep, re.I):
                    continue

                # Make absolute URL if relative
                if ep.startswith("/") and base_url:
                    p = urllib.parse.urlparse(base_url)
                    ep = f"{p.scheme}://{p.netloc}{ep}"

                # Skip if it looks like a base64 blob
                if len(ep) > 100 and re.match(r'[A-Za-z0-9+/=]{80,}', ep):
                    continue

                self.endpoints.add(ep)
                if ep.startswith("http") and "?" in ep:
                    self.all_urls.add(ep)

    def print_summary(self):
        # Final filter: only show meaningful endpoints (paths + full URLs)
        meaningful = sorted(
            ep for ep in self.endpoints
            if (ep.startswith("/") or ep.startswith("http")) and len(ep) > 4
        )
        if meaningful:
            self.log.section(f"EXTRACTED ENDPOINTS ({len(meaningful)})")
            for ep in meaningful[:100]:
                print(f"  {C}→{RESET} {ep}")
            if len(meaningful) > 100:
                print(f"  {DIM}… and {len(meaningful)-100} more (all saved to endpoints.txt){RESET}")

# ─────────────────────────────────────────────
#  JS COLLECTOR
# ─────────────────────────────────────────────

class JSCollector:
    def __init__(self, domain, session, log):
        self.domain    = domain
        self.session   = session
        self.log       = log
        self.js_urls   = set()
        self.page_urls = set()  # URLs with params for XSS/redirect testing

    def fetch(self, url, timeout=10):
        try:
            r = self.session.get(url, timeout=timeout, allow_redirects=True)
            return r.text if r.status_code == 200 else None
        except Exception:
            return None

    def _collect_page(self, url):
        html = self.fetch(url)
        if not html:
            return
        soup = BeautifulSoup(html, "html.parser")
        # External JS files
        for tag in soup.find_all("script", src=True):
            full = urllib.parse.urljoin(url, tag["src"])
            if self.domain in full:
                # Collect JS, TS, JSX, TSX, MJS, source maps
                if any(ext in full.lower() for ext in
                       ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.js.map')):
                    self.js_urls.add(full)
        # JS paths referenced in inline scripts
        for tag in soup.find_all("script", src=False):
            for m in re.finditer(r'[\'"`]([^\'"`]*\.js(?:\?[^\'"`]*)?)[\'"`]',
                                 tag.get_text()):
                p = m.group(1)
                full = p if p.startswith("http") else urllib.parse.urljoin(url, p)
                if self.domain in full:
                    self.js_urls.add(full)
        # Anchor links with query params (for XSS/redirect testing)
        for a in soup.find_all("a", href=True):
            href = urllib.parse.urljoin(url, a["href"])
            if self.domain in href and "?" in href:
                self.page_urls.add(href)
        # GET forms
        for form in soup.find_all("form"):
            if form.get("method", "get").lower() == "get":
                action = urllib.parse.urljoin(url, form.get("action", url))
                if self.domain in action:
                    inputs = {
                        i["name"]: i.get("value", "test")
                        for i in form.find_all("input", {"name": True})
                        if i.get("type", "text").lower()
                        not in ("submit", "button", "hidden", "checkbox", "radio")
                    }
                    if inputs:
                        self.page_urls.add(
                            f"{action}?{urllib.parse.urlencode(inputs)}"
                        )

    def _collect_common_paths(self):
        common = [
            "/static/js/main.chunk.js", "/static/js/bundle.js",
            "/static/js/vendors~main.chunk.js",
            "/assets/js/app.js", "/assets/js/main.js",
            "/dist/bundle.js", "/dist/main.js",
            "/build/static/js/main.chunk.js",
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/pages/_app.js",
            "/nuxt/_nuxt/app.js",
            "/js/app.js", "/js/main.js",
        ]
        base = f"https://{self.domain}"
        for path in common:
            url = base + path
            try:
                r = self.session.head(url, timeout=5)
                if r.status_code == 200:
                    self.js_urls.add(url)
            except Exception:
                pass

    def run(self):
        for scheme in ("https", "http"):
            self._collect_page(f"{scheme}://{self.domain}")
        self._collect_common_paths()
        self.log.success(
            f"Page crawl [{self.domain}]: "
            f"{len(self.js_urls)} JS, {len(self.page_urls)} page URLs"
        )
        return list(self.js_urls), list(self.page_urls)

# ─────────────────────────────────────────────
#  EXTERNAL TOOL RUNNERS
# ─────────────────────────────────────────────

def _run(cmd, log, label, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        if lines:
            # Return results even on non-zero exit — some tools (amass, chaos)
            # exit 1 but still write valid output to stdout
            if log:
                log.success(f"{label}: {len(lines)} results")
            return lines
        if p.returncode != 0:
            if log:
                log.warn(f"{label} returned no results")
    except FileNotFoundError:
        if log:
            log.warn(f"{label} not installed")
    except subprocess.TimeoutExpired:
        if log:
            log.warn(f"{label} timed out (partial results may be available)")
    return []

def _run_stdin(cmd, stdin_data, log, label, timeout=120):
    """Run tool that reads target from stdin (e.g. hakrawler, waybackurls)."""
    try:
        p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                           text=True, timeout=timeout)
        lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        if lines:
            log.success(f"{label}: {len(lines)} URLs")
            return lines
        if p.returncode != 0 and p.stderr:
            log.warn(f"{label}: {p.stderr.strip()[:80]}")
        return lines
    except FileNotFoundError:
        log.warn(f"{label} not installed")
    except subprocess.TimeoutExpired:
        log.warn(f"{label} timed out")
    return []

def collect_wayback(domain, log):
    log.info("Querying Wayback Machine CDX API…")
    urls = set()
    apis = [
        f"http://web.archive.org/cdx/search/cdx?url={domain}/*.js&output=text&fl=original&collapse=urlkey&limit=500",
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=1000&matchType=domain",
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*.js&output=text&fl=original&collapse=urlkey&limit=500",
    ]
    for api in apis:
        try:
            r = requests.get(api, timeout=30)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and ".js" in line:
                        urls.add(line)
        except Exception:
            pass
    log.success(f"Wayback Machine: {len(urls)} JS URLs")
    return list(urls)

def collect_with_katana(domain, log):
    for cmd in [
        ["katana", "-u", f"https://{domain}", "-jc", "-silent", "-d", "3", "-timeout", "30"],
        ["katana", "-u", f"http://{domain}", "-silent", "-d", "2"],
    ]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
            if lines:
                log.success(f"Katana: {len(lines)} URLs")
                return lines
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    log.warn("Katana not available")
    return []

def collect_with_subjs(domain, log):
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write(f"https://{domain}\nhttp://{domain}\n")
            tmp_path = tmp.name
        p = subprocess.run(["subjs", "-i", tmp_path, "-c", "10"],
                           capture_output=True, text=True, timeout=60)
        os.unlink(tmp_path)
        if p.returncode == 0:
            lines = [l.strip() for l in p.stdout.splitlines() if ".js" in l]
            log.success(f"SubJS: {len(lines)} JS URLs")
            return lines
    except FileNotFoundError:
        log.warn("SubJS not available")
    except Exception as e:
        log.warn(f"SubJS error: {e}")
    return []

def collect_subdomains(domain, log, session, out_dir=None):
    log.section("STEP 0: Subdomain Enumeration")
    subs = set()

    # ── Passive API Sources ───────────────────────────────────────────────

    # 1. crt.sh — certificate transparency logs
    try:
        r = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r.status_code == 200:
            for entry in r.json():
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if domain in n and n:
                        subs.add(n)
            log.success(f"crt.sh: {len(subs)} subdomains")
    except Exception as e:
        log.warn(f"crt.sh: {e}")

    # 2. HackerTarget — fast passive DNS
    try:
        r = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            before = len(subs)
            for line in r.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if domain in sub:
                        subs.add(sub)
            log.success(f"HackerTarget: {len(subs)-before} subdomains")
    except Exception:
        pass

    # 3. RapidDNS
    try:
        r = session.get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15)
        if r.status_code == 200:
            before = len(subs)
            for m in re.finditer(rf'([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.{re.escape(domain)})', r.text):
                subs.add(m.group(1).lower())
            log.success(f"RapidDNS: {len(subs)-before} subdomains")
    except Exception:
        pass

    # 4. AlienVault OTX
    try:
        r = session.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15
        )
        if r.status_code == 200:
            before = len(subs)
            for entry in r.json().get("passive_dns", []):
                host = entry.get("hostname", "")
                if domain in host:
                    subs.add(host.strip().lstrip("*."))
            log.success(f"AlienVault OTX: {len(subs)-before} subdomains")
    except Exception:
        pass

    # 5. URLScan.io
    try:
        r = session.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
            timeout=15
        )
        if r.status_code == 200:
            before = len(subs)
            for result in r.json().get("results", []):
                page_domain = result.get("page", {}).get("domain", "")
                if domain in page_domain:
                    subs.add(page_domain)
            log.success(f"URLScan.io: {len(subs)-before} subdomains")
    except Exception:
        pass

    # 6. ThreatCrowd
    try:
        r = session.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=15
        )
        if r.status_code == 200:
            before = len(subs)
            for sub in r.json().get("subdomains", []):
                if domain in sub:
                    subs.add(sub.strip())
            log.success(f"ThreatCrowd: {len(subs)-before} subdomains")
    except Exception:
        pass

    # 7. SecurityTrails (no key needed for basic)
    try:
        r = session.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"apikey": ""},
            timeout=15
        )
        if r.status_code == 200:
            before = len(subs)
            for sub in r.json().get("subdomains", []):
                subs.add(f"{sub}.{domain}")
            log.success(f"SecurityTrails: {len(subs)-before} subdomains")
    except Exception:
        pass

    # 8. DNS Dumpster (scrape)
    try:
        s2 = requests.Session()
        r1 = s2.get("https://dnsdumpster.com", timeout=10)
        csrf = re.search(r'csrfmiddlewaretoken.*?value=["\'](\w+)["\']', r1.text)
        if csrf:
            token = csrf.group(1)
            r2 = s2.post(
                "https://dnsdumpster.com",
                data={"csrfmiddlewaretoken": token, "targetip": domain, "user": "free"},
                headers={"Referer": "https://dnsdumpster.com"},
                timeout=15
            )
            before = len(subs)
            for m in re.finditer(rf'([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.{re.escape(domain)})', r2.text):
                subs.add(m.group(1).lower())
            log.success(f"DNSDumpster: {len(subs)-before} subdomains")
    except Exception:
        pass

    # ── Tool-Based Sources ────────────────────────────────────────────────

    tool_configs = [
        # (tool_name, command, timeout_seconds)
        ("Subfinder",   ["subfinder",   "-d", domain, "-silent", "-all"],      180),
        ("Assetfinder", ["assetfinder", "--subs-only", domain],                 60),
        ("Amass",       ["amass", "enum", "-passive", "-d", domain],            300),
        ("Chaos",       ["chaos", "-d", domain, "-silent"],                     60),
    ]
    for tool, cmd, timeout in tool_configs:
        results = _run(cmd, log, tool, timeout=timeout)
        subs.update(r.strip() for r in results if domain in r)

    # ── MassDNS bruteforce (if installed) ───────────────────────────────
    # massdns does DNS brute-force using a wordlist — finds subdomains
    # that passive sources miss. Only runs if massdns is installed.
    if shutil.which("massdns"):
        wordlist_paths = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
            os.path.expanduser("~/wordlists/subdomains.txt"),
        ]
        wl = next((w for w in wordlist_paths if os.path.isfile(w)), None)
        resolvers = "/etc/resolv.conf"
        if wl:
            try:
                log.info(f"MassDNS bruteforce with wordlist: {wl}")
                # Build target list: word.domain for each word in wordlist
                with open(wl) as wf:
                    targets = [f"{w.strip()}.{domain}\n" for w in wf if w.strip()]
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    tf.writelines(targets[:5000])  # cap at 5000 for speed
                    tf_path = tf.name
                proc = subprocess.run(
                    ["massdns", "-r", resolvers, "-t", "A", "-o", "S", tf_path],
                    capture_output=True, text=True, timeout=120
                )
                os.unlink(tf_path)
                before = len(subs)
                for line in proc.stdout.splitlines():
                    # massdns output: sub.domain. A 1.2.3.4
                    parts = line.split()
                    if parts and parts[0].endswith("."):
                        host = parts[0].rstrip(".")
                        if domain in host:
                            subs.add(host)
                log.success(f"MassDNS: {len(subs)-before} additional subdomains")
            except Exception as e:
                log.warn(f"MassDNS: {e}")
        else:
            log.warn("MassDNS installed but no wordlist found — install SecLists")
    else:
        log.info("MassDNS not installed — skipping bruteforce (optional, install for more coverage)")

    # ── Filter & Save ─────────────────────────────────────────────────────

    # Remove wildcards, empties, and non-subdomains
    subs = {s.strip().lstrip("*.") for s in subs
            if s and domain in s and s != domain}

    log.success(f"Total unique subdomains: {len(subs)}")

    # ── Alive check with httpx ────────────────────────────────────────────
    alive_subs = list(subs)
    if shutil.which("httpx") and subs:
        log.info(f"Checking which subdomains are alive with httpx...")
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(sorted(subs)))
                tf_path = tf.name
            proc = subprocess.run(
                ["httpx", "-l", tf_path, "-silent", "-no-color"],
                capture_output=True, text=True, timeout=180
            )
            os.unlink(tf_path)
            if proc.stdout.strip():
                alive_lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                # Extract just hostnames from httpx output (strips https://)
                alive_hosts = set()
                for line in alive_lines:
                    host = line.replace("https://","").replace("http://","").rstrip("/")
                    alive_hosts.add(host)
                alive_subs = [s for s in subs if s in alive_hosts]
                log.success(f"Alive subdomains: {len(alive_subs)}/{len(subs)}")
        except Exception as e:
            log.warn(f"httpx alive check failed: {e} — using all subdomains")
    else:
        if not shutil.which("httpx"):
            log.warn("httpx not installed — skipping alive check (install for faster scans)")

    if out_dir:
        # Save ALL subdomains
        sub_file = Path(out_dir) / "total_subdomains.txt"
        with open(sub_file, "w") as f:
            f.write("\n".join(sorted(subs)) + "\n")
        log.success(f"All subdomains saved → {sub_file} ({len(subs)} total)")

        # Save alive subdomains separately
        if alive_subs and len(alive_subs) != len(subs):
            alive_file = Path(out_dir) / "alive_subdomains.txt"
            with open(alive_file, "w") as f:
                f.write("\n".join(sorted(alive_subs)) + "\n")
            log.success(f"Alive subdomains saved → {alive_file} ({len(alive_subs)} alive)")

    return alive_subs

def make_session(cookies=None, headers=None, proxy=None):
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if headers:
        s.headers.update(headers)
    if cookies:
        for pair in cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s

# ─────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

def run_scan_from_list(args):
    """
    -l mode: load a pre-crawled URL list and go straight to
    secrets + XSS + redirect scanning. Skips subdomain enum
    and crawling entirely.
    """
    list_file = args.list

    # Validate file
    if not os.path.isfile(list_file):
        print(f"{R}[!] File not found: {list_file}{RESET}")
        sys.exit(1)

    # Read URLs
    with open(list_file, "r") as f:
        raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    urls = [u for u in raw_lines if u.startswith(("http://", "https://"))]
    if not urls:
        print(f"{R}[!] No valid URLs found in {list_file}{RESET}")
        sys.exit(1)

    # Extract domain from first URL for output folder naming
    domain = args.domain if args.domain else urllib.parse.urlparse(urls[0]).netloc
    domain = domain.replace("https://","").replace("http://","").rstrip("/")

    out_dir = make_output_dir(domain)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    log     = Logger(out_dir)
    session = make_session(
        cookies=args.cookies,
        headers=dict(h.split(":",1) for h in args.headers) if args.headers else None,
        proxy=args.proxy
    )

    banner()
    print(f"{C}  Mode       :{RESET} {BOLD}{Y}--list mode (pre-crawled URLs){RESET}")
    print(f"{C}  List file  :{RESET} {BOLD}{list_file}{RESET}")
    print(f"{C}  URLs loaded:{RESET} {BOLD}{len(urls)}{RESET}")
    print(f"{C}  Domain     :{RESET} {BOLD}{domain}{RESET}")
    print(f"{C}  Output dir :{RESET} {BOLD}{out_dir}/{RESET}")
    _ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{C}  Started    :{RESET} {_ts}")
    print()

    # Split into JS and page URLs
    js_urls   = [u for u in urls if ".js" in urllib.parse.urlparse(u).path.lower()]
    page_urls = [u for u in urls if u not in js_urls]

    log.success(f"JS files: {len(js_urls)} | Page URLs: {len(page_urls)}")

    # Save crawled-urls.txt
    crawl_file = out_dir / "crawled-urls.txt"
    with open(crawl_file, "w") as f:
        f.write("\n".join(sorted(urls)) + "\n")
    log.success(f"URLs saved → {crawl_file}")

    # ── Step 1: Extract endpoints from JS ─────────────────────────────
    ep = EndpointExtractor(log)
    log.section("STEP 1: Extracting Endpoints from JS")
    def do_extract(url):
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                ep.extract(r.text, url, url)
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(do_extract, js_urls[:300]))
    page_urls_all = list(set(page_urls) | ep.all_urls)
    ep.print_summary()
    if ep.endpoints:
        ep_file = out_dir / "endpoints.txt"
        with open(ep_file, "w") as f:
            f.write("\n".join(sorted(ep.endpoints)) + "\n")
        log.success(f"Endpoints saved → {ep_file}")

    # ── Step 2: Secret Scanning ────────────────────────────────────────
    scanner = SecretScanner(log, session, target_domain=domain)
    all_targets = js_urls + [u for u in page_urls if u not in js_urls]
    scanner.scan_parallel(all_targets, workers=args.workers)

    # ── Step 3: XSS Scanning ──────────────────────────────────────────
    if not args.no_xss:
        if page_urls_all:
            XSSScanner(log, session, target_domain=domain).scan_urls(
                page_urls_all[:500], workers=args.workers)
        else:
            log.warn("No page URLs with params found for XSS testing")

    # ── Step 4: Open Redirect Scanning ────────────────────────────────
    if not args.no_redirect:
        if page_urls_all:
            RedirectScanner(log, session, domain).scan_urls(
                page_urls_all[:500], workers=args.workers)
        else:
            log.warn("No page URLs found for redirect testing")

    # ── Summary ───────────────────────────────────────────────────────
    log.section("SCAN COMPLETE")
    ns = len(log.findings)
    nx = len(log.xss)
    nr = len(log.redirs)

    if ns == nx == nr == 0:
        print(f"{G}  Nothing found{RESET}")
    else:
        if ns: print(f"{R}{BOLD}  🔑 {ns} secret(s){RESET}")
        if nx: print(f"{R}{BOLD}  ⚡ {nx} XSS finding(s){RESET}")
        if nr: print(f"{BR}{BOLD}  ↩  {nr} open redirect finding(s){RESET}")

    print(f"\n  {DIM}Files scanned: {scanner.scanned}{RESET}")
    print(f"  {DIM}Output dir   : {out_dir}/{RESET}")
    log.save(domain, ts)
    print(f"\n{M}{BOLD}  Done! 🎯{RESET}\n")


def run_scan(args):
    domain  = (args.domain or "").strip().replace("https://","").replace("http://","").rstrip("/")
    out_dir = make_output_dir(domain)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    log     = Logger(out_dir)
    session = make_session(
        cookies=args.cookies,
        headers=dict(h.split(":",1) for h in args.headers) if args.headers else None,
        proxy=args.proxy
    )

    banner()
    print(f"{C}  Target     :{RESET} {BOLD}{domain}{RESET}")
    print(f"{C}  Output dir :{RESET} {BOLD}{out_dir}/{RESET}")
    print(f"{C}  Started    :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    mode = ("Deep" if args.deep else "Standard")
    mode += " + Subdomains" if args.subs else ""
    mode += "" if args.no_xss      else " + XSS"
    mode += "" if args.no_redirect else " + OpenRedirect"
    print(f"{C}  Mode       :{RESET} {mode}\n")

    all_js    = set()
    all_pages = set()
    ep        = EndpointExtractor(log)

    # ── 0. Subdomain enum ─────────────────────────
    scan_domains = [domain]
    if args.subs:
        subs = collect_subdomains(domain, log, session, out_dir=out_dir)
        scan_domains += subs[:30]

    # ── 1 & 2. Collect JS + page URLs ─────────────
    log.section("STEP 1 & 2: Collecting JS Files & URLs")
    for d in scan_domains:
        coll = JSCollector(d, session, log)
        js, pages = coll.run()
        all_js.update(js)
        all_pages.update(pages)

        kat = collect_with_katana(d, log)
        all_js.update(u for u in kat if ".js" in u)
        all_pages.update(u for u in kat if "?" in u and ".js" not in u)

        # hakrawler reads URLs from stdin
        hak_results = _run_stdin(
            ["hakrawler", "-d", "3", "-t", "15"],
            f"https://{d}\n",
            log, "Hakrawler"
        )
        all_js.update(u for u in hak_results if ".js" in u)
        all_pages.update(u for u in hak_results if "?" in u and ".js" not in u)
        subjs_results = collect_with_subjs(d, log)
        all_js.update(subjs_results)
        # Feed any already-discovered page URLs back into subjs for deeper JS discovery
        if all_pages:
            try:
                import tempfile as _tf, os as _os
                with _tf.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                    tmp.write("\n".join(list(all_pages)[:100]) + "\n")
                    tpath = tmp.name
                p2 = subprocess.run(["subjs", "-i", tpath, "-c", "15"],
                                    capture_output=True, text=True, timeout=60)
                _os.unlink(tpath)
                if p2.returncode == 0:
                    extra = [l.strip() for l in p2.stdout.splitlines()
                             if ".js" in l and l.strip()]
                    if extra:
                        log.success(f"SubJS (deep): {len(extra)} more JS URLs")
                        all_js.update(extra)
            except Exception:
                pass

        # GAU — always run (limit for speed, use --blacklist for noise reduction)
        gau = _run([
            "gau", d,
            "--blacklist", "png,jpg,gif,svg,ico,woff,woff2,ttf,eot,css,pdf",
            "--threads", "5",
        ], log, "GAU")
        all_js.update(u for u in gau if ".js" in u)
        all_pages.update(u for u in gau if "?" in u and ".js" not in u)

        if args.deep:
            all_js.update(collect_wayback(d, log))
            # waybackurls tool (if installed) — reads from stdin
            wb_tool = _run_stdin(["waybackurls"], f"{d}\n", log, "waybackurls")
            all_js.update(u for u in wb_tool if ".js" in u)
            all_pages.update(u for u in wb_tool if "?" in u and ".js" not in u)

    log.success(f"JS files: {len(all_js)}  |  Page URLs: {len(all_pages)}")

    # Save crawled URLs — split into in-scope and out-of-scope
    all_crawled = all_js | all_pages
    inscope_crawled   = sorted(u for u in all_crawled if is_in_scope(u, domain))
    outofscope_crawled= sorted(u for u in all_crawled if not is_in_scope(u, domain))

    if inscope_crawled:
        crawl_file = out_dir / "crawled-urls.txt"
        with open(crawl_file, "w") as f:
            f.write("\n".join(inscope_crawled) + "\n")
        log.success(f"Crawled URLs (in-scope) saved → {crawl_file} ({len(inscope_crawled)} URLs)")

    if outofscope_crawled:
        oos_file = out_dir / "crawled-urls-outofscope.txt"
        with open(oos_file, "w") as f:
            f.write("\n".join(outofscope_crawled) + "\n")
        log.success(f"Out-of-scope URLs saved → {oos_file} ({len(outofscope_crawled)} URLs)")

    if not all_js and not all_pages:
        log.warn("Nothing collected. Try --deep or check the domain.")
        return

    # ── 2.5. Endpoint extraction ───────────────────
    log.section("STEP 2.5: Extracting Endpoints from JS")
    def do_extract(url):
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                ep.extract(r.text, url, url)
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(do_extract, list(all_js)[:300]))
    all_pages.update(ep.all_urls)
    ep.print_summary()

    # Save endpoints to file
    if ep.endpoints:
        # Split endpoints: in-scope (full URLs) vs relative paths
        inscope_eps  = sorted(
            e for e in ep.endpoints
            if (e.startswith("/") or is_in_scope(e, domain))
        )
        ep_file = out_dir / "endpoints.txt"
        with open(ep_file, "w") as f:
            f.write("\n".join(inscope_eps) + "\n")
        log.success(f"Endpoints saved → {ep_file} ({len(inscope_eps)} endpoints)")

    # ── 3. Secret scanning — JS files + ALL page URLs ─────────────────
    # Secrets can appear in: JS bundles, HTML pages, JSON APIs,
    # config endpoints (/config.json, /env, /api/settings),
    # error pages, source map files (.js.map), etc.
    scanner = SecretScanner(log, session, target_domain=domain)

    # Build full scan target list
    # JS files: beautified before scanning
    # Non-JS pages: HTML, JSON, XML, config files — scanned raw
    # Deduplicate and split into JS vs other for logging clarity
    non_js_pages = set()
    for u in all_pages:
        ext = u.split("?")[0].lower()
        # Skip obviously binary or style resources
        if not any(ext.endswith(x) for x in (
            ".png",".jpg",".jpeg",".gif",".svg",".ico",
            ".woff",".woff2",".ttf",".eot",".css",".pdf",
            ".zip",".tar",".gz",".mp4",".mp3",".webp",
        )):
            non_js_pages.add(u)

    # Also add common secret-leaking endpoints proactively
    for d in scan_domains:
        for path in [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/.env.development", "/.env.staging", "/.env.test", "/.env.example",
            "/.env.sample", "/.env.orig", "/.env.bak", "/.env.old", "/.env.save",
            "/config.json", "/config.js", "/settings.json",
            "/api/config", "/api/settings", "/api/env",
            "/app/config", "/static/config.json",
            "/robots.txt", "/sitemap.xml",
            "/.git/config", "/.git/HEAD",
            "/wp-config.php.bak", "/config.php.bak",
            "/server-status", "/phpinfo.php",
            "/actuator/env", "/actuator/configprops",   # Spring Boot
            "/api/v1/config", "/api/v2/config",
            "/_config.yml", "/config.yml",
            "/package.json", "/composer.json",
        ]:
            non_js_pages.add(f"https://{d}{path}")
            non_js_pages.add(f"http://{d}{path}")

    # Enforce scope: only scan in-scope URLs for secrets
    js_inscope    = [u for u in all_js      if is_in_scope(u, domain)]
    pages_inscope = [u for u in non_js_pages if is_in_scope(u, domain) and u not in all_js]

    # ── Smart deduplication ──────────────────────────────────────────
    # Many tools (Wayback, GAU) return thousands of historical JS URLs
    # that are just the same file with different timestamps/versions.
    # Dedup by path (ignore query string for JS files) to avoid
    # scanning the same bundle 50 times across archive snapshots.
    def dedup_by_path(urls):
        seen_paths = set()
        unique = []
        for u in urls:
            p = urllib.parse.urlparse(u)
            # For JS files: deduplicate by host+path (ignore ?v=123 cache busters)
            key = f"{p.netloc}{p.path}"
            if key not in seen_paths:
                seen_paths.add(key)
                unique.append(u)
        return unique

    js_inscope    = dedup_by_path(js_inscope)
    pages_inscope = dedup_by_path(pages_inscope)

    # ── Smart caps ───────────────────────────────────────────────────
    # Cap at reasonable limits — beyond these, marginal value drops sharply
    # Priority: deduplicated unique paths first
    JS_CAP    = args.max_js
    PAGES_CAP = args.max_pages

    if len(js_inscope) > JS_CAP:
        log.warn(f"Capping JS scan: {len(js_inscope)} → {JS_CAP} (unique paths after dedup)")
        js_inscope = js_inscope[:JS_CAP]

    if len(pages_inscope) > PAGES_CAP:
        log.warn(f"Capping pages scan: {len(pages_inscope)} → {PAGES_CAP}")
        pages_inscope = pages_inscope[:PAGES_CAP]

    all_scan_targets = js_inscope + pages_inscope
    log.info(f"Secret scan targets: {len(js_inscope)} JS + {len(pages_inscope)} pages/endpoints")
    scanner.scan_parallel(all_scan_targets, workers=args.workers)

    # ── 4. XSS scanning ───────────────────────────
    if not args.no_xss:
        if all_pages:
            XSSScanner(log, session, target_domain=domain).scan_urls(
            list(all_pages)[:500], workers=args.workers)
        else:
            log.warn("No page URLs with params found for XSS testing")

    # ── 5. Open redirect scanning ──────────────────
    if not args.no_redirect:
        if all_pages:
            # Only test in-scope URLs for redirects
            inscope_pages = filter_in_scope(list(all_pages), domain)
            RedirectScanner(log, session, domain).scan_urls(
                inscope_pages[:500], workers=args.workers)
        else:
            log.warn("No page URLs found for redirect testing")

    # ── Summary ────────────────────────────────────
    log.section("SCAN COMPLETE")
    ns = len(log.findings)
    nx = len(log.xss)
    nr = len(log.redirs)

    if ns == nx == nr == 0:
        print(f"{G}  Nothing found (target may be clean — try --deep){RESET}")
    else:
        if ns:
            print(f"{R}{BOLD}  🔑 {ns} secret(s){RESET}")
            by_sev = {}
            for f in log.findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
                if sev in by_sev:
                    print(f"     {SEV_COLOR[sev]}[{sev}]{RESET} {by_sev[sev]}")
        if nx:
            print(f"{R}{BOLD}  ⚡ {nx} reflected XSS finding(s){RESET}")
        if nr:
            print(f"{BR}{BOLD}  ↩  {nr} open redirect finding(s){RESET}")

    print(f"\n  {DIM}JS scanned  : {scanner.scanned}{RESET}")
    print(f"  {DIM}Endpoints   : {len(ep.endpoints)}{RESET}")
    print(f"  {DIM}Pages tested: {len(all_pages)}{RESET}")
    print(f"  {DIM}Output dir  : {out_dir}/{RESET}")

    log.save(domain, ts)
    print(f"\n{M}{BOLD}  Done! Happy hunting 🎯{RESET}\n")

# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

VERSION = "2.0.0"

def main():
    p = argparse.ArgumentParser(
        description=f"HackLens v{VERSION} — Web Recon & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard scan (auto crawl + recon)
  python3 hacklens.py -d example.com

  # Deep scan with subdomain enumeration
  python3 hacklens.py -d example.com --deep --subs

  # Use pre-crawled URL list (skip recon, go straight to scanning)
  python3 hacklens.py -d example.com -l crawled_urls.txt

  # Authenticated scan through Burp
  python3 hacklens.py -d example.com -c "session=abc" -p http://127.0.0.1:8080
        """
    )
    # Target — one of -d or -l is required
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-d", "--domain",
        help="Target domain (e.g. example.com)"
    )
    target_group.add_argument(
        "-l", "--list",
        metavar="FILE",
        help="Pre-crawled URL list file — skips recon/crawling, "
             "directly scans all URLs for secrets, XSS, redirects"
    )

    p.add_argument("--deep",        action="store_true", help="Use Wayback, GAU, extra sources (with -d)")
    p.add_argument("--subs",        action="store_true", help="Enumerate subdomains (with -d)")
    p.add_argument("--no-xss",      action="store_true", help="Skip XSS scanning")
    p.add_argument("--no-redirect", action="store_true", help="Skip open redirect scanning")
    p.add_argument("-c","--cookies", help="Cookie string")
    p.add_argument("-H","--headers", nargs="+",          help="Extra headers")
    p.add_argument("-p","--proxy",   help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("-w","--workers", type=int, default=5, help="Parallel workers (default: 5)")
    p.add_argument("--max-js",       type=int, default=2000, help="Max JS files to scan")
    p.add_argument("--max-pages",    type=int, default=1000, help="Max page URLs to scan")
    p.add_argument("--version",      action="version", version=f"HackLens v{VERSION}")

    args = p.parse_args()
    if args.list:
        run_scan_from_list(args)
    else:
        run_scan(args)

if __name__ == "__main__":
    main()
