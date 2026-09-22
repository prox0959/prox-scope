"""
modules/open_redirect.py — Arbitrary Open URL Redirection Audit.
Inspects navigation and callback parameters for unvalidated external redirects.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "returnto", "return_to",
    "goto", "target", "rurl", "destination", "dest", "continue",
    "link", "redirect_uri", "redirect_url", "callback", "redir",
    "forward", "forward_url", "out", "view", "ref", "page",
]

EVIL_URL = "https://evil-prox-test.com"

COMMON_REDIRECT_PATHS = [
    "/redirect?url=",
    "/login?next=",
    "/login?return=",
    "/logout?redirect=",
    "/auth/callback?redirect_uri=",
    "/out?url=",
    "/go?to=",
    "/link?url=",
]


def scan(target: str, session: requests.Session) -> list:
    """Audit for unvalidated URL redirection vulnerabilities."""
    findings = []

    try:
        resp = session.get(target, timeout=session.timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    tested = 0
    max_tests = 8

    # Parameter extraction from links
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        seen_params = set()

        for a in soup.find_all("a", href=True):
            if tested >= max_tests:
                break

            href = a["href"]
            full_url = urljoin(target, href)
            parsed = urlparse(full_url)

            if not parsed.query:
                continue

            qs = parse_qs(parsed.query)
            for param_name, values in qs.items():
                if tested >= max_tests:
                    break

                key = f"{parsed.path}:{param_name}"
                if key in seen_params:
                    continue

                if param_name.lower() in REDIRECT_PARAMS:
                    seen_params.add(key)

                    try:
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode({param_name: EVIL_URL})}"
                        test_resp = session.get(test_url, timeout=3, allow_redirects=False)

                        if test_resp.status_code in (301, 302, 303, 307, 308):
                            location = test_resp.headers.get("Location", "")
                            if "evil-prox-test.com" in location:
                                findings.append(Finding(
                                    module="Open Redirect",
                                    severity=HIGH,
                                    title=f"Open Redirection via Parameter: {param_name}",
                                    description=f"Parameter '{param_name}' accepts arbitrary external URLs and redirects the client.",
                                    evidence=f"Target: {test_url[:70]} → Location: {location[:70]}",
                                ))
                                tested += 1
                                continue

                        body = test_resp.text.lower()
                        if "evil-prox-test.com" in body and ('meta http-equiv="refresh"' in body or "window.location" in body):
                            findings.append(Finding(
                                module="Open Redirect",
                                severity=HIGH,
                                title=f"Client-Side Open Redirect: {param_name}",
                                description=f"Parameter '{param_name}' controls client-side redirect via JavaScript or meta refresh.",
                                evidence=f"Param: {param_name} → evil-prox-test.com",
                            ))
                            tested += 1
                    except requests.RequestException:
                        continue
    except Exception:
        pass

    # Common endpoint checks
    for path_template in COMMON_REDIRECT_PATHS:
        if tested >= max_tests:
            break

        try:
            test_url = urljoin(target, path_template + EVIL_URL)
            test_resp = session.get(test_url, timeout=3, allow_redirects=False)

            if test_resp.status_code in (301, 302, 303, 307, 308):
                location = test_resp.headers.get("Location", "")
                if "evil-prox-test.com" in location:
                    findings.append(Finding(
                        module="Open Redirect",
                        severity=HIGH,
                        title=f"Open Redirection Endpoint: {path_template.split('?')[0]}",
                        description="Common redirection endpoint permits unvalidated forwarding to external domains.",
                        evidence=f"Path: {path_template} → {location[:70]}",
                    ))
                    tested += 1
        except requests.RequestException:
            continue

    return findings
