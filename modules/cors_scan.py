"""
modules/cors_scan.py — Cross-Origin Resource Sharing (CORS) Misconfiguration Audit.
Tests for wildcard origins, origin reflection, null origin bypass, and unsafe HTTP methods.
"""

import requests
from urllib.parse import urlparse
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO


def scan(target: str, session: requests.Session) -> list:
    """Audit CORS configuration policies."""
    findings = []
    parsed = urlparse(target)

    # Test 1: Arbitrary Evil Origin
    try:
        resp = session.get(
            target,
            headers={"Origin": "https://evil-attacker.com"},
            timeout=session.timeout,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            findings.append(Finding(
                module="CORS",
                severity=HIGH,
                title="CORS Wildcard Origin (*) Enabled",
                description="Access-Control-Allow-Origin is set to '*' wildcard, permitting any external domain to read responses.",
                evidence=f"ACAO: {acao}",
            ))

        if "evil-attacker.com" in acao:
            severity = CRITICAL if acac == "true" else HIGH
            findings.append(Finding(
                module="CORS",
                severity=severity,
                title="CORS Arbitrary Origin Reflection" + (" with Credentials!" if acac == "true" else ""),
                description="The server blindly reflects untrusted Origin headers. "
                            + ("Credentials (cookies/auth) are explicitly permitted — full account takeover possible!" if acac == "true" else "Untrusted origins can read authenticated data."),
                evidence=f"ACAO: {acao}, ACAC: {acac}",
            ))
    except requests.RequestException:
        pass

    # Test 2: Null Origin Bypass
    try:
        resp = session.get(
            target,
            headers={"Origin": "null"},
            timeout=session.timeout,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "null":
            findings.append(Finding(
                module="CORS",
                severity=HIGH,
                title="CORS Null Origin Whitelisted",
                description="Access-Control-Allow-Origin accepts 'null' origin. Sandboxed iframes can exploit this to perform cross-origin requests.",
                evidence="ACAO: null",
            ))
    except requests.RequestException:
        pass

    # Test 3: Preflight Method Inspection
    try:
        resp = session.options(
            target,
            headers={
                "Origin": "https://evil-attacker.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header",
            },
            timeout=session.timeout,
        )
        allow_methods = resp.headers.get("Access-Control-Allow-Methods", "")
        dangerous = [m.strip() for m in allow_methods.split(",") if m.strip().upper() in ("PUT", "DELETE", "PATCH")]
        if dangerous:
            findings.append(Finding(
                module="CORS",
                severity=MEDIUM,
                title=f"Dangerous HTTP Methods Permitted via CORS: {', '.join(dangerous)}",
                description="CORS preflight configuration exposes sensitive state-altering HTTP verbs across origins.",
                evidence=f"Allow-Methods: {allow_methods}",
            ))
    except requests.RequestException:
        pass

    return findings
