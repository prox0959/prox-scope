"""
modules/source_scan.py — Static Source Code Secret & Credential Leak Analysis.
Inspects page HTML and linked JavaScript bundles for leaked API keys, tokens, and database URIs.
"""

import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

LEAK_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", CRITICAL),
    (r"(?:aws)?_?secret_?(?:access)?_?key.*?['\"][0-9a-zA-Z/+]{40}['\"]", "AWS Secret Key", CRITICAL),

    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", CRITICAL),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", HIGH),

    # Firebase
    (r"firebase[A-Za-z0-9._/-]*\.firebaseio\.com", "Firebase Database URL", HIGH),
    (r"firebase[A-Za-z0-9._/-]*\.firebaseapp\.com", "Firebase App URL", MEDIUM),

    # Generic API keys
    (r"""(?:api[_-]?key|apikey)\s*[=:]\s*['"][a-zA-Z0-9_\-]{16,}['"]""", "Generic API Key", CRITICAL),
    (r"""(?:api[_-]?secret|apisecret)\s*[=:]\s*['"][a-zA-Z0-9_\-]{16,}['"]""", "Generic API Secret", CRITICAL),

    # Database connection strings
    (r"mongodb(?:\+srv)?://[^\s'\"<]+", "MongoDB Connection URI", CRITICAL),
    (r"mysql://[^\s'\"<]+", "MySQL Connection URI", CRITICAL),
    (r"postgres(?:ql)?://[^\s'\"<]+", "PostgreSQL Connection URI", CRITICAL),
    (r"redis://[^\s'\"<]+", "Redis Connection URI", CRITICAL),

    # Private keys
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Cryptographic Key", CRITICAL),

    # JWT tokens
    (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+", "JWT Token", MEDIUM),

    # Password / secrets in code
    (r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]""", "Hardcoded Password", CRITICAL),
    (r"""(?:secret|secret_key)\s*[=:]\s*['"][^'"]{8,}['"]""", "Hardcoded Secret", CRITICAL),
    (r"""(?:token|auth_token|access_token)\s*[=:]\s*['"][a-zA-Z0-9_\-]{16,}['"]""", "Hardcoded Auth Token", HIGH),

    # Slack
    (r"xox[baprs]-[0-9a-zA-Z-]+", "Slack Token", HIGH),
    (r"https://hooks\.slack\.com/services/[^\s'\"<]+", "Slack Webhook", HIGH),

    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", CRITICAL),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Publishable Key", MEDIUM),

    # Twilio & SendGrid
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", HIGH),
    (r"SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}", "SendGrid API Key", HIGH),

    # Internal IPs
    (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", "Internal IP Address", MEDIUM),
]


def _scan_text(text: str, source_name: str, seen: set) -> list:
    """Scan string buffer for known credential patterns."""
    findings = []

    for pattern, name, severity in LEAK_PATTERNS:
        try:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:3]:
                key = f"{name}:{match[:30]}"
                if key in seen:
                    continue
                seen.add(key)

                evidence_text = match if len(match) <= 50 else match[:25] + "..." + match[-10:]

                if name == "JWT Token":
                    desc = f"JWT token identified in client code ({source_name}). " \
                           f"May represent a public/storefront guest session, but verify it contains no elevated claims."
                else:
                    desc = f"Hardcoded {name} exposed in client-facing asset ({source_name})."

                findings.append(Finding(
                    module="Source Code Analysis",
                    severity=severity,
                    title=f"Hardcoded Credential Exposure: {name}",
                    description=desc,
                    evidence=evidence_text,
                ))
        except re.error:
            continue

    return findings


def scan(target: str, session: requests.Session) -> list:
    """Analyze page source code and linked scripts for sensitive leaks."""
    findings = []
    seen = set()

    try:
        resp = session.get(target, timeout=session.timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    findings.extend(_scan_text(resp.text, "Index HTML", seen))

    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        scripts = soup.find_all("script", src=True)

        js_count = 0
        for script in scripts:
            if js_count >= 5:
                break

            src = script["src"]
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = urljoin(target, src)
            elif not src.startswith("http"):
                src = urljoin(target + "/", src)

            try:
                js_resp = session.get(src, timeout=4)
                if js_resp.status_code == 200 and len(js_resp.text) > 0:
                    js_name = src.split("/")[-1].split("?")[0][:35]
                    findings.extend(_scan_text(js_resp.text, f"Script: {js_name}", seen))
                    js_count += 1
            except requests.RequestException:
                continue
    except Exception:
        pass

    return findings
