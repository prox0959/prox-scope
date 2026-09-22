"""
core/scanner.py — Modular Scan Engine with Adaptive Knowledge Learning.
Orchestrates 16 security and reconnaissance modules, manages concurrent checks,
and extracts novel endpoints and parameters into the persistent knowledge base.
"""

import time
import importlib
from urllib.parse import urljoin
from typing import List
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console

from core.utils import Finding, make_session, normalize_url
from core.learning import LearningEngine

console = Console()

# 16 Specialized Scan & Reconnaissance Modules
SCAN_MODULES = [
    ("modules.waf_detect",       "WAF & Firewall Detection"),
    ("modules.subdomain_finder", "Subdomain Discovery (CT Logs)"),
    ("modules.port_scan",        "Port & Service Scanner"),
    ("modules.header_scan",      "Security Headers"),
    ("modules.ssl_scan",         "SSL/TLS Certificate"),
    ("modules.dns_security",     "DNS & Email Security (SPF/DMARC)"),
    ("modules.sensitive_files",  "Sensitive Files & Credentials"),
    ("modules.tech_detect",      "Technology Fingerprinting"),
    ("modules.cookie_scan",      "Cookie Security Flags"),
    ("modules.cors_scan",        "CORS Configuration"),
    ("modules.info_disclosure",  "Information Disclosure"),
    ("modules.source_scan",      "Source Code Leak Analysis"),
    ("modules.xss_scan",         "Reflected XSS & SSTI Detection"),
    ("modules.sqli_scan",        "SQL Injection Detection"),
    ("modules.dir_listing",      "Directory Listing"),
    ("modules.open_redirect",    "Open Redirect Analysis"),
]


class ScanEngine:
    """Core security scan engine orchestrating all modules."""

    def __init__(self, target: str, timeout: int = 10, enable_learning: bool = True):
        self.target = normalize_url(target)
        self.session = make_session(timeout)
        self.findings: List[Finding] = []
        self.enable_learning = enable_learning
        self.learning = LearningEngine()

    def _discover_and_learn(self):
        """Actively inspect sitemap and robots to discover and learn novel assets."""
        if not self.enable_learning:
            return

        # Sitemaps
        for sm in ["sitemap.xml", "sitemap_index.xml"]:
            try:
                resp = self.session.get(urljoin(self.target + "/", sm), timeout=4)
                if resp.status_code == 200 and "<loc>" in resp.text:
                    self.learning.process_sitemap(resp.text, self.target)
                    break
            except Exception:
                pass

        # robots.txt
        try:
            r_resp = self.session.get(urljoin(self.target + "/", "robots.txt"), timeout=4)
            if r_resp.status_code == 200 and "disallow" in r_resp.text.lower():
                self.learning.process_robots(r_resp.text, self.target)
        except Exception:
            pass

    def run(self) -> List[Finding]:
        """Execute all modules with progress visualization."""
        self.findings = []

        console.print(f"\n[bright_cyan]🎯 Target:[/bright_cyan] [bold white]{self.target}[/bold white]")
        stats = self.learning.get_stats()
        console.print(f"[dim]🧠 Knowledge Base: {stats['endpoints']} endpoints | {stats['subdomains']} subdomains learned[/dim]")
        console.print(f"[dim]{'━' * 55}[/dim]\n")

        # Background learning pass
        self._discover_and_learn()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            task = progress.add_task("[cyan]Auditing target...", total=len(SCAN_MODULES))

            for module_path, module_name in SCAN_MODULES:
                progress.update(task, description=f"[cyan]⟫ {module_name}")

                try:
                    mod = importlib.import_module(module_path)
                    results = mod.scan(self.target, self.session)
                    if results:
                        self.findings.extend(results)
                except Exception as e:
                    console.print(f"  [dim]⚠ {module_name} error: {e}[/dim]")

                progress.advance(task)

        # Smart Deduplication across all findings
        unique_findings = []
        seen_keys = set()
        seen_evidence = set()
        for f in self.findings:
            title_clean = f.title.strip().lower()
            ev_clean = (f.evidence or "").strip().lower()
            dedup_key = (f.severity, title_clean)

            if dedup_key in seen_keys:
                continue

            if ev_clean and len(ev_clean) > 8 and ev_clean in seen_evidence:
                continue

            seen_keys.add(dedup_key)
            if ev_clean:
                seen_evidence.add(ev_clean)
            unique_findings.append(f)

        self.findings = unique_findings
        self.findings.sort(key=lambda f: f.severity, reverse=True)
        return self.findings
