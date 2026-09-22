"""
modules/info_disclosure.py — Information Disclosure & Debug Endpoint Audit.
Inspects HTML comments, stack traces, exposed administrative consoles, and robots.txt.
"""

import re
import requests
from urllib.parse import urljoin
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

DEBUG_ENDPOINTS = [
    ("/debug",           "Debug Endpoint"),
    ("/trace",           "Trace Endpoint"),
    ("/actuator",        "Spring Boot Actuator"),
    ("/actuator/env",    "Spring Boot Actuator Environment"),
    ("/actuator/health", "Spring Boot Actuator Health"),
    ("/elmah.axd",       "ELMAH Error Log (.NET)"),
    ("/__debug__/",      "Django Debug Toolbar"),
    ("/api/debug",       "API Debug Endpoint"),
    ("/_debugbar",       "Laravel Debugbar"),
    ("/telescope",       "Laravel Telescope"),
    ("/adminer.php",     "Adminer DB Management"),
    ("/phpmyadmin",      "phpMyAdmin Database Panel"),
    ("/console",         "Interactive Debugger Console"),
    ("/_profiler",       "Symfony Profiler"),
    ("/graphql",         "GraphQL API Endpoint"),
    ("/graphiql",        "GraphiQL IDE Interface"),
    ("/swagger",         "Swagger API Docs"),
    ("/api-docs",        "API Documentation Endpoint"),
    ("/swagger-ui.html", "Swagger UI Dashboard"),
    ("/redoc",           "ReDoc API Documentation"),
]

SENSITIVE_COMMENT_KEYWORDS = [
    "todo", "fixme", "hack", "password", "secret", "api_key",
    "api key", "token", "debug", "admin", "credential", "private",
    "internal", "temp", "temporary", "remove this", "do not deploy",
]


def scan(target: str, session: requests.Session) -> list:
    """Scan for information leaks, debug endpoints, and robots.txt directives."""
    findings = []

    try:
        resp = session.get(target, timeout=session.timeout, allow_redirects=True)
        body = resp.text

        # Inspect HTML comments for developer notes
        comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        for comment in comments:
            comment_lower = comment.lower()
            for keyword in SENSITIVE_COMMENT_KEYWORDS:
                if keyword in comment_lower:
                    findings.append(Finding(
                        module="Info Disclosure",
                        severity=MEDIUM,
                        title=f"Sensitive Developer Comment: '{keyword}'",
                        description="HTML source code contains developer comments mentioning credentials, debug instructions, or internal notes.",
                        evidence=f"<!-- {comment.strip()[:100]} -->",
                    ))
                    break
    except requests.RequestException:
        pass

    # Error page stack trace inspection
    try:
        error_resp = session.get(
            urljoin(target + "/", "prox_trigger_error_404_xyz"),
            timeout=session.timeout,
        )
        error_text = error_resp.text.lower()

        stack_indicators = [
            ("traceback", "Python Stack Trace"),
            ("debug mode", "Active Debug Mode"),
            ("laravel", "Laravel Framework Stack Trace"),
            ("werkzeug", "Werkzeug Interactive Debugger"),
            ("django", "Django Debug Page"),
            ("spring framework", "Spring Boot Error Page"),
        ]

        for indicator, desc in stack_indicators:
            if indicator in error_text:
                findings.append(Finding(
                    module="Info Disclosure",
                    severity=MEDIUM,
                    title=f"Detailed Error Stack Trace Disclosed: {desc}",
                    description="Custom 404/error page discloses detailed runtime stack trace or framework internals.",
                    evidence=f"Matched: '{indicator}' in error response",
                ))
                break
    except requests.RequestException:
        pass

    # Inspect debug endpoints
    for path, desc in DEBUG_ENDPOINTS:
        try:
            url = urljoin(target + "/", path.lstrip("/"))
            resp = session.get(url, timeout=3, allow_redirects=False)

            if resp.status_code == 200 and len(resp.content) > 50:
                findings.append(Finding(
                    module="Info Disclosure",
                    severity=HIGH,
                    title=f"Publicly Accessible Debug/Admin Console: {path}",
                    description=f"{desc} is publicly accessible without authentication.",
                    evidence=f"Status: {resp.status_code}, Length: {len(resp.content)} bytes",
                ))
        except requests.RequestException:
            continue

    # Inspect robots.txt
    try:
        robots_resp = session.get(urljoin(target + "/", "robots.txt"), timeout=4)
        if robots_resp.status_code == 200 and "disallow" in robots_resp.text.lower():
            disallowed = re.findall(r"Disallow:\s*(.+)", robots_resp.text, re.I)
            filtered_paths = [d.strip() for d in disallowed
                             if any(k in d.lower() for k in ["admin", "api", "private", "secret", "backup", "config", "dashboard", "panel"])]
            interesting = list(dict.fromkeys(filtered_paths))

            if interesting:
                findings.append(Finding(
                    module="Info Disclosure",
                    severity=INFO,
                    title="robots.txt Discloses Sensitive Target Paths",
                    description="The robots.txt file reveals hidden or restricted internal administrative paths.",
                    evidence=f"Disallow: {', '.join(interesting[:5])}",
                ))
    except requests.RequestException:
        pass

    return findings
