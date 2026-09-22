"""
modules/xss_scan.py — Cross-Site Scripting (XSS) & Template Injection (SSTI) Audit.
Audits form inputs and URL parameters using unique canary markers to avoid false positives.
"""

import random
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

XSS_CANARY = "px_sec_check_991"
XSS_PAYLOADS = [
    (f'<script>{XSS_CANARY}</script>',           f'<script>{XSS_CANARY}</script>'),
    (f'"><img src=x onerror={XSS_CANARY}>',       f'onerror={XSS_CANARY}'),
    (f"'\"><svg/onload={XSS_CANARY}>",           f'onload={XSS_CANARY}'),
]


def _extract_forms(html: str, base_url: str) -> list:
    """Extract form structures and input fields."""
    forms = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(base_url, action) if action else base_url

            inputs = []
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if name:
                    inp_type = inp.get("type", "text").lower()
                    value = inp.get("value", "test")
                    inputs.append({"name": name, "type": inp_type, "value": value})

            if inputs:
                forms.append({
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                })
    except Exception:
        pass

    return forms


def _extract_params_from_links(html: str, base_url: str) -> list:
    """Extract query parameters from links."""
    params = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        seen = set()

        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)

            if parsed.query:
                qs = parse_qs(parsed.query)
                for param_name in qs:
                    key = f"{parsed.path}:{param_name}"
                    if key not in seen:
                        seen.add(key)
                        params.append({
                            "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            "param": param_name,
                        })
    except Exception:
        pass

    return params


def scan(target: str, session: requests.Session) -> list:
    """Audit for reflected inputs and template engine expression evaluation."""
    findings = []

    try:
        base_resp = session.get(target, timeout=session.timeout, allow_redirects=True)
        base_html = base_resp.text
    except requests.RequestException:
        return findings

    tested_count = 0
    max_tests = 8

    # Form testing
    forms = _extract_forms(base_html, target)
    for form in forms[:4]:
        if tested_count >= max_tests:
            break

        for inp in form["inputs"]:
            if tested_count >= max_tests:
                break
            if inp["type"] in ("hidden", "submit", "button", "file", "image"):
                continue

            for payload, check_str in XSS_PAYLOADS:
                if check_str in base_html:
                    continue

                try:
                    data = {i["name"]: i["value"] for i in form["inputs"]}
                    data[inp["name"]] = payload

                    if form["method"] == "post":
                        test_resp = session.post(form["action"], data=data, timeout=4)
                    else:
                        test_resp = session.get(form["action"], params=data, timeout=4)

                    if test_resp.status_code in (403, 429, 503):
                        continue

                    if check_str in test_resp.text:
                        findings.append(Finding(
                            module="XSS Scanner",
                            severity=HIGH,
                            title=f"Reflected Input in Form: {inp['name']}",
                            description=f"Form input '{inp['name']}' reflects raw HTML/script payload without adequate sanitization.",
                            evidence=f"Form: {form['action']} | Input: {inp['name']}",
                        ))
                        tested_count += 1
                        break
                except requests.RequestException:
                    continue

    # URL Parameter testing
    url_params = _extract_params_from_links(base_html, target)
    parsed_target = urlparse(target)
    if parsed_target.query:
        for param_name in parse_qs(parsed_target.query):
            url_params.append({
                "url": f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}",
                "param": param_name,
            })

    for param_info in url_params[:5]:
        if tested_count >= max_tests:
            break

        for payload, check_str in XSS_PAYLOADS:
            if check_str in base_html:
                continue

            try:
                test_url = f"{param_info['url']}?{urlencode({param_info['param']: payload})}"
                test_resp = session.get(test_url, timeout=4)

                if test_resp.status_code in (403, 429, 503):
                    continue

                if check_str in test_resp.text:
                    findings.append(Finding(
                        module="XSS Scanner",
                        severity=HIGH,
                        title=f"Reflected Input in Parameter: {param_info['param']}",
                        description=f"Query parameter '{param_info['param']}' reflects unencoded HTML tags into response.",
                        evidence=f"URL: {param_info['url']} | Param: {param_info['param']}",
                    ))
                    tested_count += 1
                    break
            except requests.RequestException:
                continue

    # SSTI dynamic evaluation check
    for param_info in url_params[:3]:
        try:
            num1 = random.randint(1234, 4321)
            num2 = random.randint(1234, 4321)
            expected_val = str(num1 * num2)
            ssti_payload = f"{{{{{num1}*{num2}}}}}"

            if expected_val in base_html:
                continue

            test_url = f"{param_info['url']}?{urlencode({param_info['param']: ssti_payload})}"
            test_resp = session.get(test_url, timeout=4)

            if test_resp.status_code in (403, 429, 503):
                continue

            if expected_val in test_resp.text and ssti_payload not in test_resp.text:
                findings.append(Finding(
                    module="XSS Scanner",
                    severity=CRITICAL,
                    title=f"Server-Side Template Injection (SSTI): {param_info['param']}",
                    description=f"Parameter '{param_info['param']}' evaluated template expression on the server. Remote code execution risk.",
                    evidence=f"Expression: {ssti_payload} → Computed Result: {expected_val}",
                ))
                break
        except requests.RequestException:
            continue

    return findings
