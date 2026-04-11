#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          HACKLENS - Web Recon & Vulnerability Scanner        ║
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
    "AWS Secret Key":         r'(?i)aws.{0,30}["\']([A-Za-z0-9/+=]{40})["\']',
    "AWS ARN":                r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\'"]+',
    # Google key always starts AIza + exactly 35 chars, no continuation
    "Google API Key":         r'AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9\-_])',
    # Google OAuth: numeric id + hyphen + 32 alphanum + fixed suffix
    "Google OAuth Client":    r'[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Google Service Account": r'"type"\s*:\s*"service_account"',
    # Azure: AccountKey= followed by 88-char base64 + ==
    "Azure Storage Key":      r'AccountKey=[A-Za-z0-9+/]{88}==',
    "Azure Client Secret":    r'(?i)(?:clientsecret|client_secret)\s*[=:]\s*["\']([A-Za-z0-9\-_~.]{34,})["\']',

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
    "JWT Token":              r'eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}',
    # Bearer: must have actual long token value (not a variable name)
    "Bearer Token":           r'[Bb]earer\s+([A-Za-z0-9\-_\.]{30,})',
    # Basic auth embedded in URL — must have real-looking credentials
    "Basic Auth URL":         r'https?://[A-Za-z0-9_\-\.%]+:[A-Za-z0-9_\-\.%!@#$]{6,}@[A-Za-z0-9\-\.]+\.[a-z]{2,}',
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
    "Discord Token":          r'[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}',
    # Discord webhook: specific URL format with snowflake ID length
    "Discord Webhook":        r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{60,}',
    # Telegram: numeric bot id : 35-char token — no adjoining digits
    "Telegram Bot Token":     r'(?<!\d)[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])',
    # Twilio SID: AC + 32 lowercase hex
    "Twilio Account SID":     r'AC[a-f0-9]{32}',
    "Twilio Auth Token":      r'(?i)twilio.{0,30}["\']([a-f0-9]{32})["\']',
    # SendGrid: SG. + 22 chars + . + 43 chars (deterministic structure)
    "SendGrid API Key":       r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    "Mailgun API Key":        r'key-[0-9a-zA-Z]{32}',

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
    "Username":               r'(?i)["\'](?:username|user_name|login|uname|usr)["\']\s*[:=]\s*["\']([^\s\'"<>{},\\\\]{3,40})["\']',
    "Password":               r'(?i)["\'](?:password|passwd|pass|pwd)["\']\s*[:=]\s*["\']([^\s\'"<>{},\\\\]{6,})["\']',
    "Hardcoded Credential":   r'(?i)(?:username|user|login)\s*[=:]\s*["\']([^\s\'"]{3,30})["\']\s*[,;]?\s*(?:password|passwd|pass|pwd)\s*[=:]\s*["\']([^\s\'"]{4,})["\']',
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
    "Heroku API Key":         r'(?i)heroku[A-Za-z0-9_\-\s\'":.]{0,30}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
    "Firebase URL":           r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Firebase API Key":       r'(?i)["\'](?:firebase[_\-]?api[_\-]?key|FIREBASE_API_KEY)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{35,40})["\']',
    # S3: must be amazonaws.com subdomain
    "S3 Bucket":              r'[A-Za-z0-9\-_\.]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com',
    # Internal IP: must be in a string context (quoted or in a URL)
    "Internal IP":            r'(?:["\']|//\s*)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:["\']|[/\s])',

    # ── DevOps ─────────────────────────────────────────────────────────
    "Vault Token":            r'(?i)["\']vault[_\-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
    "Docker Hub Token":       r'(?i)["\']docker[_\-]?(?:token|password)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,})["\']',

    # ── Social / SaaS ──────────────────────────────────────────────────
    "Twitter Bearer":         r'AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}',
    "Facebook Token":         r'EAACEdEose0cBA[0-9A-Za-z]+',
    "Mapbox Token":           r'pk\.eyJ1[A-Za-z0-9\-_\.]{10,}',
    "Shopify Token":          r'shpat_[a-fA-F0-9]{32}',
    "Shopify Secret":         r'shpss_[a-fA-F0-9]{32}',
    "WordPress Auth Key":     r'define\s*\(\s*["\']AUTH_KEY["\']\s*,\s*["\'](.{30,})["\']',
    "Algolia App ID":         r'(?i)["\']algolia[_\-]?app[_\-]?id["\']\s*[:=]\s*["\']([A-Z0-9]{10})["\']',
    "Algolia API Key":        r'(?i)["\']algolia[_\-]?api[_\-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']',
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
#  SECRET SCANNER
# ─────────────────────────────────────────────

class SecretScanner:
    def __init__(self, log, session):
        self.log     = log
        self.session = session
        self.scanned = 0

    def scan_content(self, content, source, content_type=""):
        if not content or len(content) < 30:
            return

        ct = content_type.lower()

        # Beautify JS files for better scanning — skip for HTML/JSON/XML
        if ".js" in source.lower() or "javascript" in ct:
            try:
                text = jsbeautifier.beautify(content)
            except Exception:
                text = content
        else:
            # HTML/JSON/XML/plain — scan as-is, no beautifier
            text = content

        for pat_name, pattern in SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, text, re.MULTILINE):
                    val      = m.group(0)
                    line_num = text[:m.start()].count('\n') + 1
                    if not is_false_positive(val, pat_name):
                        self.log.finding(pat_name, val, source, line_num)
            except re.error:
                pass
        self.scanned += 1

    def scan_url(self, url):
        try:
            r = self.session.get(url, timeout=15)
            if r.status_code == 200 and len(r.text) > 50:
                ct = r.headers.get("Content-Type", "")
                self.scan_content(r.text, url, ct)
        except Exception:
            pass

    def scan_parallel(self, urls, workers=10):
        self.log.section(f"STEP 3: Scanning {len(urls)} files for Secrets")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.scan_url, u): u for u in urls}
            done = 0
            for fut in as_completed(futs):
                done += 1
                if done % 25 == 0:
                    self.log.info(f"Progress: {done}/{len(urls)} scanned…")

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
        p = f" onfocus=alert(1) data-x={canary}"
        r = rf'onfocus=alert\(1\)'
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
        # Already in JS context, just call alert
        p = f";alert(1)//{canary}"
        r = rf'alert\(1\)//{canary}'
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
        # Inside a script block — find string context
        # Look backwards for unescaped quote
        code_before = before[script_open:]
        # Count unescaped double quotes
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
    def __init__(self, log, session):
        self.log     = log
        self.session = session
        self.tested  = set()

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
        # Deduplicate by normalised URL + param — ignores http/https duplicates
        # and URLs that differ only in param order or value
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

        # Payload must appear unencoded in response
        if not re.search(pattern, r2.text, re.IGNORECASE):
            encoded_payload = _html_encode(payload)
            if encoded_payload in r2.text and payload not in r2.text:
                return  # only appears HTML-encoded → safe, not exploitable
            # pattern didn't match but also not encoded — skip to be safe
            return

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

REDIRECT_PARAMS = {
    'next','redirect','redirect_uri','redirect_url','redirecturi','redirecturl',
    'return','return_url','returnurl','returnto','return_to','goto','go',
    'url','uri','dest','destination','target','redir','r','link','forward',
    'fwd','location','continue','cont','back','backurl','success_url',
    'cancel_url','checkout_url','exit','out','view','ref','referrer',
    'callback','next_url','nexturl','to','from','origin','path','homepage',
}

# Canary domain — totally external, easy to detect in Location header
_CANARY = "yogeshbhandage.com"

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

    # ── Helpers ──────────────────────────────────────────────────────────

    def _is_offsite(self, netloc):
        """True if netloc is NOT the target domain or a subdomain of it."""
        if not netloc:
            return False
        host = netloc.lower().split(":")[0]
        t    = self.target.lower().split(":")[0]
        return not (host == t or host.endswith("." + t))

    def _build_url(self, base_url, params, param, value):
        parsed = urllib.parse.urlparse(base_url)
        qs = dict(params)
        qs[param] = value
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    # ── Three detection layers ────────────────────────────────────────────

    def _check_location_header(self, r, test_url, param, probe):
        """
        Layer 1: Check raw Location header — highest confidence.
        If Location header points off-site → CONFIRMED open redirect.
        """
        if r.status_code not in (301, 302, 303, 307, 308):
            return False
        loc = r.headers.get("Location", "").strip()
        if not loc:
            return False

        # Canary in Location = confirmed
        if _CANARY in loc:
            self.log.vuln(
                "Open Redirect [CONFIRMED]", test_url, param,
                f"canary found in Location header | HTTP {r.status_code}",
                f"Location: {loc}"
            )
            return True

        # Off-site absolute URL in Location = confirmed
        pl = urllib.parse.urlparse(loc)
        if pl.scheme in ("http", "https") and self._is_offsite(pl.netloc):
            self.log.vuln(
                "Open Redirect [CONFIRMED]", test_url, param,
                f"off-site Location header | HTTP {r.status_code} | probe={probe[:50]}",
                f"Location: {loc}"
            )
            return True

        return False

    def _check_body_reflection(self, r, test_url, param, probe):
        """
        Layer 2: Check response body for canary in redirect context.
        If canary URL appears in href/window.location/meta-refresh → POSSIBLE.
        """
        ct = r.headers.get("Content-Type", "").lower()
        if "html" not in ct:
            return False

        body = r.text

        # Meta-refresh
        m = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?[^"\']*url=([^"\'>\s]+)',
            body, re.I
        )
        if m:
            dest = m.group(1).strip()
            pd = urllib.parse.urlparse(dest)
            if _CANARY in dest or (pd.netloc and self._is_offsite(pd.netloc)):
                self.log.vuln(
                    "Open Redirect [CONFIRMED]", test_url, param,
                    f"meta-refresh redirect to off-site URL | probe={probe[:40]}",
                    f"Meta-refresh → {dest[:120]}"
                )
                return True

        # Canary in body in a URL context
        if _CANARY in body:
            patterns = [
                rf'(?:href|src|action|url|location)\s*[=:]\s*["\']?[^"\'<\s]*{re.escape(_CANARY)}',
                rf'window\.location\s*=\s*["\'][^"\']*{re.escape(_CANARY)}',
                rf'location\.href\s*=\s*["\'][^"\']*{re.escape(_CANARY)}',
                rf'<a[^>]+href=[^>]*{re.escape(_CANARY)}',
            ]
            for pat in patterns:
                if re.search(pat, body, re.I):
                    self.log.vuln(
                        "Open Redirect [POSSIBLE]", test_url, param,
                        f"canary URL reflected in body redirect context | probe={probe[:40]}",
                        f"Canary found in redirect-like context in response body"
                    )
                    return True

        return False

    def _check_redirect_chain(self, r, test_url, param, probe):
        """
        Layer 3: After following all redirects, check if we ended up off-site.
        """
        if _CANARY in r.url:
            self.log.vuln(
                "Open Redirect [CONFIRMED]", test_url, param,
                f"final URL after redirect chain contains canary",
                f"Final URL: {r.url}"
            )
            return True

        for h in r.history:
            loc = h.headers.get("Location", "")
            if not loc:
                continue
            if _CANARY in loc:
                self.log.vuln(
                    "Open Redirect [CONFIRMED]", test_url, param,
                    f"canary in redirect chain | HTTP {h.status_code}",
                    f"Location: {loc}"
                )
                return True
            pl = urllib.parse.urlparse(loc)
            if pl.scheme in ("http", "https") and self._is_offsite(pl.netloc):
                self.log.vuln(
                    "Open Redirect [CONFIRMED]", test_url, param,
                    f"off-site redirect in chain | HTTP {h.status_code} | probe={probe[:40]}",
                    f"Location: {loc}"
                )
                return True

        return False

    def _test_param(self, base_url, all_params, param):
        """Test one param — one confirmed hit stops all further probes for that param."""
        # Dedup at param level so same endpoint+param only tested once
        param_key = f"redir:{base_url}:{param}"
        if param_key in self.tested:
            return
        self.tested.add(param_key)

        for probe in REDIRECT_PROBES:
            test_url = self._build_url(base_url, all_params, param, probe)
            try:
                # Pass 1: raw (no redirect following) — catch Location header directly
                r_raw = self.sess.get(test_url, timeout=10, allow_redirects=False)

                if self._check_location_header(r_raw, test_url, param, probe):
                    return  # confirmed

                if self._check_body_reflection(r_raw, test_url, param, probe):
                    return  # possible (body context)

                # Pass 2: follow redirect chain
                if r_raw.status_code in (301, 302, 303, 307, 308):
                    r_follow = self.sess.get(test_url, timeout=10,
                                             allow_redirects=True, max_redirects=8)
                    if self._check_redirect_chain(r_follow, test_url, param, probe):
                        return

            except requests.TooManyRedirects:
                pass
            except Exception:
                pass

    def _generate_extra_urls(self, base_domain):
        """
        Proactively test common auth/redirect endpoints
        even if not discovered by the crawler.
        """
        common_paths = [
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
        for path in common_paths:
            for param in top_params:
                url = f"https://{base_domain}{path}"
                extra.append((url, {param: f"https://{_CANARY}"}, param))
        return extra

    def scan_urls(self, urls, workers=8):
        self.log.section(f"STEP 5: Open Redirect Scanning {len(urls)} URLs")

        priority = []   # known redirect param names or value looks like a URL
        secondary = []  # all other params (still tested — apps use non-standard names)
        seen = set()

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            for param, value in params.items():
                pkey = f"{parsed.netloc}{parsed.path}:{param}"
                if pkey in seen:
                    continue
                seen.add(pkey)
                is_redir_param = param.lower().rstrip("[]") in REDIRECT_PARAMS
                looks_like_url  = value.lower().startswith(("http://", "https://", "//", "www."))
                if is_redir_param or looks_like_url:
                    priority.append((url, params, param))
                else:
                    secondary.append((url, params, param))

        # Proactively test common auth endpoints
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
            futs = [ex.submit(self._test_param, u, p, param)
                    for u, p, param in tasks]
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

    def extract(self, content, source, base_url=""):
        for pat in self.PATTERNS:
            for m in re.finditer(pat, content, re.IGNORECASE):
                ep = m.group(1).strip()
                if len(ep) < 3 or any(c in ep for c in ('`', '{', '}')):
                    continue
                if ep.startswith("/") and base_url:
                    p = urllib.parse.urlparse(base_url)
                    ep = f"{p.scheme}://{p.netloc}{ep}"
                self.endpoints.add(ep)
                if ep.startswith("http") and "?" in ep:
                    self.all_urls.add(ep)

    def print_summary(self):
        if self.endpoints:
            self.log.section("EXTRACTED ENDPOINTS")
            for ep in sorted(self.endpoints)[:80]:
                print(f"  {C}→{RESET} {ep}")
            if len(self.endpoints) > 80:
                print(f"  {DIM}… and {len(self.endpoints)-80} more{RESET}")

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
        if p.returncode == 0:
            lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
            log.success(f"{label}: {len(lines)} URLs")
            return lines
        log.warn(f"{label} non-zero exit")
    except FileNotFoundError:
        log.warn(f"{label} not installed")
    except subprocess.TimeoutExpired:
        log.warn(f"{label} timed out")
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
    for tool, cmd in [
        ("Subfinder",   ["subfinder",   "-d", domain, "-silent"]),
        ("Assetfinder", ["assetfinder", "--subs-only", domain]),
        ("Amass",       ["amass", "enum", "-passive", "-d", domain]),
    ]:
        subs.update(_run(cmd, log, tool))
    log.success(f"Total subdomains: {len(subs)}")

    # Save to file
    if out_dir and subs:
        sub_file = Path(out_dir) / "total_subdomains.txt"
        with open(sub_file, "w") as f:
            f.write("\n".join(sorted(subs)) + "\n")
        log.success(f"Subdomains saved → {sub_file}")

    return list(subs)

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

def run_scan(args):
    domain  = args.domain.strip().replace("https://","").replace("http://","").rstrip("/")
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

    # Save ALL crawled URLs (JS + pages) to file
    all_crawled = all_js | all_pages
    if all_crawled:
        crawl_file = out_dir / "crawled-urls.txt"
        with open(crawl_file, "w") as f:
            f.write("\n".join(sorted(all_crawled)) + "\n")
        log.success(f"Crawled URLs saved → {crawl_file}")

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
        ep_file = out_dir / "endpoints.txt"
        with open(ep_file, "w") as f:
            f.write("\n".join(sorted(ep.endpoints)) + "\n")
        log.success(f"Endpoints saved → {ep_file}")

    # ── 3. Secret scanning — JS files + ALL page URLs ─────────────────
    # Secrets can appear in: JS bundles, HTML pages, JSON APIs,
    # config endpoints (/config.json, /env, /api/settings),
    # error pages, source map files (.js.map), etc.
    scanner = SecretScanner(log, session)

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

    all_scan_targets = list(all_js) + list(non_js_pages - all_js)
    log.info(f"Secret scan targets: {len(list(all_js))} JS + {len(non_js_pages - all_js)} pages/endpoints")
    scanner.scan_parallel(all_scan_targets, workers=args.workers)

    # ── 4. XSS scanning ───────────────────────────
    if not args.no_xss:
        if all_pages:
            XSSScanner(log, session).scan_urls(list(all_pages)[:500],
                                               workers=args.workers)
        else:
            log.warn("No page URLs with params found for XSS testing")

    # ── 5. Open redirect scanning ──────────────────
    if not args.no_redirect:
        if all_pages:
            RedirectScanner(log, session, domain).scan_urls(
                list(all_pages)[:500], workers=args.workers)
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

def main():
    p = argparse.ArgumentParser(
        description="HackLens — JS Secrets + XSS + Open Redirect Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hacklens.py -d example.com
  python3 hacklens.py -d example.com --deep --subs
  python3 hacklens.py -d example.com --no-xss --no-redirect
  python3 hacklens.py -d example.com -c "session=abc" -p http://127.0.0.1:8080
  python3 hacklens.py -d example.com -w 20 --deep --subs
        """
    )
    p.add_argument("-d","--domain",      required=True,       help="Target domain (e.g. example.com)")
    p.add_argument("--deep",             action="store_true",  help="Use Wayback, GAU, extra sources")
    p.add_argument("--subs",             action="store_true",  help="Enumerate & scan subdomains")
    p.add_argument("--no-xss",           action="store_true",  help="Skip XSS scanning")
    p.add_argument("--no-redirect",      action="store_true",  help="Skip open redirect scanning")
    p.add_argument("-c","--cookies",     help="Cookie string (e.g. 'session=abc;csrf=xyz')")
    p.add_argument("-H","--headers",     nargs="+",            help="Extra headers (e.g. 'X-Auth: token')")
    p.add_argument("-p","--proxy",       help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("-w","--workers",     type=int, default=10, help="Parallel workers (default: 10)")
    run_scan(p.parse_args())

if __name__ == "__main__":
    main()
