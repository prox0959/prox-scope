"""
modules/header_scan.py — HTTP Security Headers Audit Module.
Inspects security response headers (CSP, HSTS, X-Frame-Options, etc.).
"""

import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": MEDIUM,
        "title": "Missing Content-Security-Policy Header",
        "desc": "CSP header is missing — no protection against Cross-Site Scripting (XSS) and data injection.",
    },
    "X-Frame-Options": {
        "severity": MEDIUM,
        "title": "Missing X-Frame-Options Header",
        "desc": "X-Frame-Options is missing — website can be embedded in iframes (clickjacking risk).",
    },
    "X-Content-Type-Options": {
        "severity": MEDIUM,
        "title": "Missing X-Content-Type-Options Header",
        "desc": "X-Content-Type-Options is missing — browser may perform MIME type sniffing.",
    },
    "Strict-Transport-Security": {
        "severity": HIGH,
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "desc": "HSTS header is missing on HTTPS — connections can be downgraded to plaintext HTTP.",
    },
    "Referrer-Policy": {
        "severity": LOW,
        "title": "Missing Referrer-Policy Header",
        "desc": "Referrer-Policy is missing — sensitive URL parameters may leak to third-party referrers.",
    },
    "Permissions-Policy": {
        "severity": LOW,
        "title": "Missing Permissions-Policy Header",
        "desc": "Permissions-Policy is missing — browser features like camera and microphone are not explicitly restricted.",
    },
    "X-XSS-Protection": {
        "severity": INFO,
        "title": "Missing X-XSS-Protection Header",
        "desc": "Legacy XSS protection header is missing (deprecated in modern browsers).",
    },
}


def scan(target: str, session: requests.Session) -> list:
    """Audit HTTP security headers."""
    findings = []

    try:
        resp = session.get(target, timeout=session.timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    headers = resp.headers
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}
    is_https = target.startswith("https://")

    for header_name, info in SECURITY_HEADERS.items():
        if header_name == "Strict-Transport-Security" and not is_https:
            continue

        if header_name.lower() not in headers_lower:
            findings.append(Finding(
                module="Security Headers",
                severity=info["severity"],
                title=info["title"],
                description=info["desc"],
            ))
        else:
            actual_key, val = headers_lower[header_name.lower()]
            if header_name == "Content-Security-Policy":
                if "report-only" in actual_key.lower():
                    findings.append(Finding(
                        module="Security Headers",
                        severity=LOW,
                        title="CSP configured in Report-Only mode",
                        description="Content-Security-Policy-Report-Only is active; directives are not enforced.",
                        evidence=f"{actual_key}: {val[:100]}",
                    ))
                if "unsafe-inline" in val or "unsafe-eval" in val:
                    findings.append(Finding(
                        module="Security Headers",
                        severity=MEDIUM,
                        title="CSP contains unsafe directives",
                        description="CSP allows 'unsafe-inline' or 'unsafe-eval', weakening XSS defenses.",
                        evidence=f"CSP: {val[:120]}",
                    ))

    critical_headers = ["Content-Security-Policy", "X-Frame-Options",
                        "X-Content-Type-Options", "Strict-Transport-Security"]
    missing_crit = sum(1 for h in critical_headers if h.lower() not in headers_lower)
    if missing_crit >= (4 if is_https else 3):
        findings.append(Finding(
            module="Security Headers",
            severity=HIGH,
            title="Zero Essential Security Headers Configured",
            description="The website does not implement any foundational security headers.",
        ))

    return findings
