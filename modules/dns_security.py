"""
modules/dns_security.py — DNS & Email Spoofing Protections Audit (SPF, DMARC, RFC 9116).
Audits SPF and DMARC records via DoH (DNS over HTTPS) to detect email spoofing vectors.
"""

from urllib.parse import urlparse
import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO


def _query_txt_records(domain: str, session: requests.Session) -> list:
    """Query TXT DNS records via Cloudflare DoH."""
    records = []
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT"
        resp = session.get(url, headers={"Accept": "application/dns-json"}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            for ans in data.get("Answer", []):
                txt = ans.get("data", "").strip('"')
                records.append(txt)
    except Exception:
        pass
    return records


def scan(target: str, session: requests.Session) -> list:
    """Audit DNS and email security configurations."""
    findings = []
    parsed = urlparse(target)
    domain = parsed.hostname

    if not domain or domain in ("localhost", "127.0.0.1"):
        return findings

    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) > 2 else domain

    # ── SPF Record Check ────────────────────────────────────────────────
    txt_records = _query_txt_records(root_domain, session)
    spf_found = False
    spf_record = ""

    for rec in txt_records:
        if rec.lower().startswith("v=spf1"):
            spf_found = True
            spf_record = rec
            break

    if not spf_found:
        findings.append(Finding(
            module="DNS & Email Security",
            severity=MEDIUM,
            title="Missing SPF (Sender Policy Framework) Record",
            description=f"No SPF record found for '{root_domain}'. Attackers can forge emails from this domain (email spoofing / phishing).",
            evidence=f"Domain: {root_domain}",
        ))
    else:
        if "+all" in spf_record.lower():
            findings.append(Finding(
                module="DNS & Email Security",
                severity=HIGH,
                title="Insecure SPF Configuration (+all)",
                description="SPF record permits all IP addresses to send mail on behalf of the domain.",
                evidence=spf_record,
            ))
        elif "?all" in spf_record.lower():
            findings.append(Finding(
                module="DNS & Email Security",
                severity=LOW,
                title="Weak SPF Policy Mechanism (?all - Neutral)",
                description="SPF policy is configured with neutral '?all' qualifier; spoofed messages will not be rejected.",
                evidence=spf_record,
            ))

    # ── DMARC Record Check ──────────────────────────────────────────────
    dmarc_domain = f"_dmarc.{root_domain}"
    dmarc_records = _query_txt_records(dmarc_domain, session)
    dmarc_found = False
    dmarc_record = ""

    for rec in dmarc_records:
        if rec.lower().startswith("v=dmarc1"):
            dmarc_found = True
            dmarc_record = rec
            break

    if not dmarc_found:
        findings.append(Finding(
            module="DNS & Email Security",
            severity=MEDIUM,
            title="Missing DMARC Policy Record",
            description=f"No DMARC record found at '{dmarc_domain}'. Receiving mail servers cannot verify authenticity of incoming mail.",
            evidence=f"DNS: {dmarc_domain}",
        ))
    elif "p=none" in dmarc_record.lower():
        findings.append(Finding(
            module="DNS & Email Security",
            severity=LOW,
            title="DMARC Policy Configured in Non-Enforcing Mode (p=none)",
            description="DMARC policy is set to 'p=none' (monitoring only). Spoofed emails are neither quarantined nor rejected.",
            evidence=dmarc_record,
        ))

    # ── RFC 9116 security.txt Check ─────────────────────────────────────
    try:
        sec_url = f"{parsed.scheme}://{domain}/.well-known/security.txt"
        sec_resp = session.get(sec_url, timeout=4)
        if sec_resp.status_code == 200 and "contact:" in sec_resp.text.lower():
            findings.append(Finding(
                module="DNS & Email Security",
                severity=INFO,
                title="RFC 9116 security.txt Discovered",
                description="Target implements standard vulnerability disclosure and security contact policy.",
                evidence=sec_url,
            ))
    except Exception:
        pass

    return findings
