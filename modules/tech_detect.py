"""
modules/tech_detect.py — Web Technology Fingerprinting & Version Disclosure Audit.
Identifies underlying CMS, frameworks, JavaScript libraries, and server version leaks.
"""

import re
import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

TECH_SIGNATURES = {
    # React / Next.js
    "__NEXT_DATA__":        "Next.js",
    "_next/static":         "Next.js",
    "react-root":           "React",
    "data-reactroot":       "React",
    "__REACT_DEVTOOLS":     "React (DevTools Active)",

    # Vue / Nuxt
    "__vue":                "Vue.js",
    "data-v-":              "Vue.js",
    "__NUXT__":             "Nuxt.js",
    "nuxt":                 "Nuxt.js",

    # Angular
    "ng-version":           "Angular",
    "ng-app":               "AngularJS",
    "angular.js":           "AngularJS",

    # WordPress
    "wp-content":           "WordPress",
    "wp-includes":          "WordPress",
    "wp-json":              "WordPress",

    # Other CMS
    "joomla":               "Joomla",
    "drupal":               "Drupal",

    # Python frameworks
    "csrfmiddlewaretoken":  "Django",
    "django":               "Django",
    "flask":                "Flask",

    # PHP frameworks
    "laravel_session":      "Laravel",
    "symfony":              "Symfony",

    # JS Runtimes
    "express":              "Express.js",

    # Static site generators
    "gatsby":               "Gatsby",
    "hugo":                 "Hugo",
    "jekyll":               "Jekyll",

    # Cloud & No-code builders
    "wix.com":              "Wix",
    "squarespace":          "Squarespace",
    "webflow":              "Webflow",
    "bubble.io":            "Bubble",
    "framer":               "Framer",
    "vercel":               "Vercel",
    "netlify":              "Netlify",
}


def scan(target: str, session: requests.Session) -> list:
    """Fingerprint web technologies and software versions."""
    findings = []
    detected_techs = set()

    try:
        resp = session.get(target, timeout=session.timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    headers = resp.headers
    body = resp.text.lower()

    # Server header version check
    server = headers.get("Server", "")
    if server:
        detected_techs.add(f"Server: {server}")
        if re.search(r"[\d]+\.[\d]+", server):
            findings.append(Finding(
                module="Tech Detection",
                severity=LOW,
                title=f"Server Version Disclosure: {server}",
                description="Server header reveals exact software version. Attackers can cross-reference known CVEs.",
                evidence=f"Server: {server}",
            ))

    # X-Powered-By
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        detected_techs.add(f"X-Powered-By: {powered_by}")
        findings.append(Finding(
            module="Tech Detection",
            severity=LOW,
            title=f"Backend Framework Disclosed: {powered_by}",
            description="X-Powered-By header discloses backend technology stack.",
            evidence=f"X-Powered-By: {powered_by}",
        ))

    # HTML meta generator
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text, re.I)
    if gen_match:
        gen = gen_match.group(1)
        detected_techs.add(f"Generator: {gen}")
        findings.append(Finding(
            module="Tech Detection",
            severity=INFO,
            title=f"Meta Generator Fingerprint: {gen}",
            description="HTML meta tag reveals website build generator and version.",
            evidence=f"<meta name='generator' content='{gen}'>",
        ))

    # Framework signatures
    for signature, tech_name in TECH_SIGNATURES.items():
        if signature.lower() in body and tech_name not in detected_techs:
            detected_techs.add(tech_name)

    # Cookie headers
    set_cookie = headers.get("Set-Cookie", "").lower()
    if "laravel_session" in set_cookie:
        detected_techs.add("Laravel")
    if "phpsessid" in set_cookie:
        detected_techs.add("PHP")
    if "jsessionid" in set_cookie:
        detected_techs.add("Java")
    if "connect.sid" in set_cookie:
        detected_techs.add("Express.js")
    if "asp.net" in set_cookie or "aspnet" in set_cookie.replace(".", ""):
        detected_techs.add("ASP.NET")

    # jQuery version audit
    jquery_match = re.search(r'jquery[.-]?([\d]+\.[\d]+\.[\d]+)', body)
    if jquery_match:
        version = jquery_match.group(1)
        detected_techs.add(f"jQuery {version}")
        try:
            parts = [int(x) for x in version.split(".")]
            if parts[0] < 3 or (parts[0] == 3 and parts[1] < 5):
                findings.append(Finding(
                    module="Tech Detection",
                    severity=MEDIUM,
                    title=f"Outdated jQuery Version Detected: {version}",
                    description="jQuery versions prior to 3.5.0 contain known cross-site scripting flaws (CVE-2020-11022).",
                    evidence=f"jQuery v{version}",
                ))
        except (ValueError, IndexError):
            pass

    if detected_techs:
        findings.append(Finding(
            module="Tech Detection",
            severity=INFO,
            title="Technology Stack Fingerprint",
            description="Identified software, runtime, and framework components running on the target.",
            evidence=", ".join(sorted(detected_techs)),
        ))

    return findings
