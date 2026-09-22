"""
modules/ssl_scan.py — SSL/TLS Certificate & Transport Layer Security Audit.
Verifies certificate validity, expiration, common name matching, and HTTP-to-HTTPS redirection.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO


def scan(target: str, session: requests.Session) -> list:
    """Verify SSL/TLS certificate and transport security."""
    findings = []
    parsed = urlparse(target)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme == "http":
        findings.append(Finding(
            module="SSL/TLS",
            severity=HIGH,
            title="Insecure Plaintext Transport (No HTTPS)",
            description="The site is served over unencrypted HTTP. All communications are susceptible to MITM attacks.",
            evidence=f"Scheme: {parsed.scheme}",
        ))
        try:
            https_url = target.replace("http://", "https://", 1)
            resp = session.get(https_url, timeout=4, allow_redirects=False)
            findings.append(Finding(
                module="SSL/TLS",
                severity=MEDIUM,
                title="Missing Automatic HTTP to HTTPS Redirection",
                description="HTTPS is available but plaintext HTTP traffic is not automatically redirected.",
            ))
        except Exception:
            pass
        return findings

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days

                if days_left < 0:
                    findings.append(Finding(
                        module="SSL/TLS",
                        severity=CRITICAL,
                        title="SSL Certificate Expired",
                        description=f"The certificate expired {abs(days_left)} days ago.",
                        evidence=f"Expired on: {not_after.strftime('%Y-%m-%d')}",
                    ))
                elif days_left < 7:
                    findings.append(Finding(
                        module="SSL/TLS",
                        severity=HIGH,
                        title=f"SSL Certificate Expiring in {days_left} Days",
                        description="Certificate expiration is imminent; immediate renewal required.",
                        evidence=f"Expires: {not_after.strftime('%Y-%m-%d')}",
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        module="SSL/TLS",
                        severity=MEDIUM,
                        title=f"SSL Certificate Expiring Soon ({days_left} Days)",
                        description="Certificate renewal should be scheduled.",
                        evidence=f"Expires: {not_after.strftime('%Y-%m-%d')}",
                    ))

                # Subject CN matching
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")
                san = [entry[1] for entry in cert.get("subjectAltName", [])]

                if hostname not in san and hostname != cn:
                    if not any(s.startswith("*.") and hostname.endswith(s[1:]) for s in san):
                        findings.append(Finding(
                            module="SSL/TLS",
                            severity=HIGH,
                            title="SSL Certificate Hostname Mismatch",
                            description="Certificate Common Name or Subject Alternative Names do not match the target host.",
                            evidence=f"Host: {hostname} | CN: {cn} | SAN: {', '.join(san[:4])}",
                        ))

                tls_version = ssock.version()
                if tls_version in ("TLSv1", "TLSv1.1"):
                    findings.append(Finding(
                        module="SSL/TLS",
                        severity=HIGH,
                        title=f"Obsolete TLS Protocol in Use: {tls_version}",
                        description="TLSv1.0 and TLSv1.1 are cryptographically broken. Migrate to TLSv1.2 or TLSv1.3.",
                        evidence=f"Protocol: {tls_version}",
                    ))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            module="SSL/TLS",
            severity=CRITICAL,
            title="SSL Certificate Verification Failed",
            description="The certificate could not be validated against trusted root authorities.",
            evidence=str(e)[:120],
        ))
    except Exception:
        pass

    # Check HTTP to HTTPS redirect
    try:
        http_url = target.replace("https://", "http://", 1)
        resp = session.get(http_url, timeout=4, allow_redirects=False)
        if resp.status_code not in (301, 302, 307, 308):
            findings.append(Finding(
                module="SSL/TLS",
                severity=MEDIUM,
                title="Missing Automatic HTTP to HTTPS Redirection",
                description="Plaintext HTTP does not redirect to HTTPS automatically.",
            ))
    except Exception:
        pass

    return findings
