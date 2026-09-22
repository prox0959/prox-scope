"""
modules/subdomain_finder.py — Passive Subdomain Enumeration via Certificate Transparency.
Queries crt.sh public CT logs to rapidly enumerate valid subdomains without brute force.
"""

from urllib.parse import urlparse
import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO
from core.learning import LearningEngine

learning = LearningEngine()


def scan(target: str, session: requests.Session) -> list:
    """Passively discover subdomains using Certificate Transparency logs."""
    findings = []
    parsed = urlparse(target)
    hostname = parsed.hostname

    if not hostname or hostname in ("localhost", "127.0.0.1"):
        return findings

    # Extract root domain (e.g. sub.example.com -> example.com)
    parts = hostname.split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = hostname

    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%.{root_domain}&output=json"
        resp = session.get(url, timeout=7)

        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if "*" not in sub and sub.endswith(root_domain):
                        subdomains.add(sub)
                        learning.learn_subdomain(sub)
    except Exception:
        pass

    if subdomains:
        sub_list = sorted(list(subdomains))
        preview = ", ".join(sub_list[:8])
        findings.append(Finding(
            module="Subdomain Discovery",
            severity=INFO,
            title=f"Discovered {len(subdomains)} active subdomains via CT logs",
            description=f"Public Certificate Transparency logs revealed {len(subdomains)} subdomains for {root_domain}.",
            evidence=f"Hosts: {preview}" + (f" (+{len(subdomains)-8} more)" if len(subdomains) > 8 else ""),
        ))

    return findings
