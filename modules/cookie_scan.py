"""
modules/cookie_scan.py — Cookie Security Flags & Attributes Audit.
Inspects session and application cookies for HttpOnly, Secure, and SameSite flags.
"""

import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "phpsessid", "jsessionid",
    "connect.sid", "sid", "sess", "session", "token",
    "auth_token", "access_token", "laravel_session",
    "asp.net_sessionid", "aspsessionid", "_session_id",
    "ci_session", "cfid", "cftoken",
}


def scan(target: str, session: requests.Session) -> list:
    """Audit cookie security flags."""
    findings = []
    is_https = target.startswith("https://")

    try:
        resp = session.get(target, timeout=session.timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    cookies = resp.cookies
    raw_set_cookie = resp.headers.get("Set-Cookie", "")

    if not cookies and not raw_set_cookie:
        return findings

    for cookie in cookies:
        name = cookie.name
        is_session = name.lower() in SESSION_COOKIE_NAMES

        # HttpOnly flag
        if not cookie.has_nonstandard_attr("httponly") and not cookie.has_nonstandard_attr("HttpOnly"):
            severity = HIGH if is_session else MEDIUM
            findings.append(Finding(
                module="Cookie Security",
                severity=severity,
                title=f"Missing HttpOnly Flag: {name}",
                description=f"Cookie '{name}' lacks the HttpOnly attribute and can be accessed via client-side scripts (XSS session hijacking risk)."
                            + (" High risk: this appears to be an authentication/session cookie." if is_session else ""),
                evidence=f"Cookie: {name}={cookie.value[:30]}...",
            ))

        # Secure flag
        if is_https and not cookie.secure:
            severity = HIGH if is_session else MEDIUM
            findings.append(Finding(
                module="Cookie Security",
                severity=severity,
                title=f"Missing Secure Flag: {name}",
                description=f"Cookie '{name}' was set over HTTPS without the Secure flag. Browsers may transmit it over unencrypted HTTP.",
                evidence=f"Cookie: {name}",
            ))

        # SameSite attribute
        cookie_header = ""
        for line in raw_set_cookie.split("\n"):
            if name in line:
                cookie_header = line
                break

        if "samesite" not in cookie_header.lower():
            findings.append(Finding(
                module="Cookie Security",
                severity=LOW,
                title=f"Missing SameSite Attribute: {name}",
                description=f"Cookie '{name}' lacks SameSite restrictions, reducing defense-in-depth against Cross-Site Request Forgery (CSRF).",
                evidence=f"Cookie: {name}",
            ))

    return findings
