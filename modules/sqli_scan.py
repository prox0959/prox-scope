"""
modules/sqli_scan.py — SQL Injection Detection (High Accuracy & Low False-Positive).
Tests parameters against specific database syntax error signatures with baseline response comparison.
"""

import time
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' ORDER BY 1--",
    "') OR ('1'='1",
    "1 UNION SELECT NULL--",
]

TIME_PAYLOAD = "' OR SLEEP(3)--"
TIME_THRESHOLD = 3.0

SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"valid mysql result",
    r"check the manual that corresponds to your (?:mysql|mariadb) server version",
    r"mySqlClient\.",
    r"com\.mysql\.jdbc\.exceptions",

    # PostgreSQL
    r"postgresql.*?error",
    r"warning:\s*pg_",
    r"pg_query\(\):\s*Query failed",
    r"psycopg2\.errors",

    # Microsoft SQL Server / MSSQL
    r"driver.*?sql[\-\_\ ]*server",
    r"ole db provider for (?:odbc drivers|sql server)",
    r"unclosed quotation mark after the character string",
    r"microsoft sql native client error",

    # Oracle
    r"\bORA-[0-9]{4,5}\b",
    r"oracle error",
    r"quoted string not properly terminated",

    # SQLite
    r"sqlite3\.OperationalError",
    r"sqlite error",
    r"near \".*?\": syntax error",

    # Generic & ORM
    r"(?:sql|database)\s+syntax\s+error.*?(?:near|at line)",
    r"unterminated\s+(?:quoted\s+string|string\s+constant)",
    r"org\.hibernate\.exception\.SQLGrammarException",
    r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
]

BOT_CHALLENGE_PATTERNS = [
    r"phantomjs",
    r"node:electron",
    r"py-scrap",
    r"cf-chl-",
    r"challenge-platform",
    r"checking your browser",
    r"attention required! \| cloudflare",
    r"security check to access",
    r"ddos protection by",
    r"waf-block",
    r"access denied",
    r"sucuri webproxy",
]


def _is_bot_or_waf_challenge(text: str) -> bool:
    """Filter out anti-scraping and WAF JS challenge bodies."""
    text_lower = text.lower()
    return any(re.search(p, text_lower) for p in BOT_CHALLENGE_PATTERNS)


def _find_injectable_params(html: str, target: str) -> list:
    """Extract query parameters from target URL and anchor tags."""
    params = []
    seen = set()

    parsed = urlparse(target)
    if parsed.query:
        for name in parse_qs(parsed.query):
            key = f"{parsed.path}:{name}"
            if key not in seen:
                seen.add(key)
                params.append({
                    "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    "param": name,
                })

    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(target, href)
            p = urlparse(full)
            if p.query:
                for name in parse_qs(p.query):
                    key = f"{p.path}:{name}"
                    if key not in seen:
                        seen.add(key)
                        params.append({
                            "url": f"{p.scheme}://{p.netloc}{p.path}",
                            "param": name,
                        })
    except Exception:
        pass

    return params[:8]


def scan(target: str, session: requests.Session) -> list:
    """Audit for SQL injection vulnerabilities."""
    findings = []

    try:
        start_base = time.time()
        base_resp = session.get(target, timeout=session.timeout, allow_redirects=True)
        baseline_time = time.time() - start_base
    except requests.RequestException:
        return findings

    base_html = base_resp.text
    base_html_lower = base_html.lower()

    if _is_bot_or_waf_challenge(base_html):
        return findings

    params = _find_injectable_params(base_html, target)
    if not params:
        return findings

    tested = 0

    for param_info in params:
        if tested >= 8:
            break

        sqli_found = False

        # Error-based test
        for payload in SQLI_PAYLOADS:
            if sqli_found:
                break

            try:
                test_url = f"{param_info['url']}?{urlencode({param_info['param']: payload})}"
                test_resp = session.get(test_url, timeout=5)

                if test_resp.status_code in (403, 429, 503):
                    continue

                resp_text = test_resp.text
                resp_text_lower = resp_text.lower()

                if _is_bot_or_waf_challenge(resp_text):
                    continue

                for sig in SQL_ERROR_PATTERNS:
                    if re.search(sig, resp_text_lower):
                        # Avoid false positive if string was already present in baseline
                        if re.search(sig, base_html_lower):
                            continue

                        error_snippet = ""
                        for line in resp_text.split("\n"):
                            if re.search(sig, line.lower()):
                                cleaned = line.strip()
                                if not cleaned.startswith(("<script", "//", "/*", "function", "var ", "let ", "const ")):
                                    error_snippet = cleaned[:100]
                                    break
                                elif not error_snippet:
                                    error_snippet = cleaned[:100]

                        if not error_snippet:
                            error_snippet = f"Database syntax error matched: {sig}"

                        findings.append(Finding(
                            module="SQL Injection",
                            severity=CRITICAL,
                            title=f"SQL Database Error Leak: {param_info['param']}",
                            description=f"Parameter '{param_info['param']}' produced an unhandled database syntax error. Potential SQL injection.",
                            evidence=f"Payload: {payload} | Error: {error_snippet}",
                        ))
                        sqli_found = True
                        tested += 1
                        break
            except requests.RequestException:
                continue

        # Time-based test
        if not sqli_found:
            try:
                test_url = f"{param_info['url']}?{urlencode({param_info['param']: TIME_PAYLOAD})}"
                start = time.time()
                t_resp = session.get(test_url, timeout=8)
                elapsed = time.time() - start

                if elapsed >= (baseline_time + 2.5) and elapsed >= TIME_THRESHOLD:
                    if t_resp.status_code not in (403, 429, 503) and not _is_bot_or_waf_challenge(t_resp.text):
                        findings.append(Finding(
                            module="SQL Injection",
                            severity=CRITICAL,
                            title=f"Time-Based SQL Injection Anomaly: {param_info['param']}",
                            description=f"Sleep payload triggered significant server processing delay ({elapsed:.1f}s vs baseline {baseline_time:.1f}s).",
                            evidence=f"Payload: {TIME_PAYLOAD} | Elapsed: {elapsed:.1f}s",
                        ))
                        tested += 1
            except requests.RequestException:
                pass

    return findings
