"""
modules/sensitive_files.py — Sensitive File & Credential Exposure Audit (Multithreaded).
Scans for exposed environment variables, configuration backups, source code, and log files.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import requests

from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

SENSITIVE_PATHS = {
    # CRITICAL — Credentials, database dumps, source code
    ".env":                  CRITICAL,
    ".env.local":            CRITICAL,
    ".env.production":       CRITICAL,
    ".env.backup":           CRITICAL,
    ".git/HEAD":             CRITICAL,
    ".git/config":           CRITICAL,
    "wp-config.php":         CRITICAL,
    "wp-config.php.bak":     CRITICAL,
    "config.php":            CRITICAL,
    "backup.sql":            CRITICAL,
    "dump.sql":              CRITICAL,
    "database.sql":          CRITICAL,
    ".htpasswd":             CRITICAL,

    # HIGH — Configuration files & debug logs
    ".htaccess":             HIGH,
    "configuration.php":     HIGH,
    "config.yml":            HIGH,
    "config.json":           HIGH,
    "docker-compose.yml":    HIGH,
    "Dockerfile":            HIGH,
    ".svn/entries":          HIGH,
    "phpinfo.php":           HIGH,
    "info.php":              HIGH,
    "web.config":            HIGH,
    ".npmrc":                HIGH,
    "server-status":         HIGH,
    "server-info":           HIGH,
    "debug.log":             HIGH,
    "error.log":             HIGH,

    # MEDIUM — Package & build manifests
    "package.json":          MEDIUM,
    "package-lock.json":     MEDIUM,
    "composer.json":         MEDIUM,
    "composer.lock":         MEDIUM,
    "Gruntfile.js":          MEDIUM,
    "gulpfile.js":           MEDIUM,
    "webpack.config.js":     MEDIUM,
    ".babelrc":              MEDIUM,
    "access.log":            MEDIUM,

    # LOW — Developer artifacts
    ".DS_Store":             LOW,
    ".editorconfig":         LOW,
    ".gitignore":            LOW,
    "Makefile":              LOW,
    "crossdomain.xml":       LOW,
}


def _is_false_positive(resp, not_found_resp) -> bool:
    """Detect custom or soft 404 responses."""
    if not_found_resp and abs(len(resp.content) - len(not_found_resp.content)) < 60:
        return True
    text = resp.text.lower()
    if resp.status_code == 200 and any(k in text for k in ["page not found", "404 not found", "doesn't exist"]):
        return True
    return False


def _check_single_path(target: str, path: str, severity: int, session: requests.Session, not_found_resp) -> Finding | None:
    """Test a single sensitive path."""
    try:
        url = urljoin(target + "/", path)
        resp = session.get(url, timeout=4, allow_redirects=False)

        if resp.status_code != 200:
            return None

        if _is_false_positive(resp, not_found_resp):
            return None

        if len(resp.content) < 5:
            return None

        content_preview = resp.text[:200].strip().replace("\n", " ")
        content_type = resp.headers.get("Content-Type", "unknown")

        return Finding(
            module="Sensitive Files",
            severity=severity,
            title=f"Exposed Sensitive File: /{path}",
            description=f"File '{path}' is publicly accessible without authentication. "
                        f"Size: {len(resp.content)} bytes, Type: {content_type}",
            evidence=content_preview[:120] if content_preview else None,
        )
    except requests.RequestException:
        return None


def scan(target: str, session: requests.Session) -> list:
    """Concurrently probe sensitive paths."""
    findings = []

    not_found_resp = None
    try:
        not_found_resp = session.get(
            urljoin(target + "/", "prox_random_nonexistent_xyz_404_check"),
            timeout=4,
        )
    except Exception:
        pass

    wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "sensitive_files.txt")
    paths_to_check = {}

    if os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
                        paths_to_check[line] = SENSITIVE_PATHS.get(line, MEDIUM)
        except Exception:
            paths_to_check = SENSITIVE_PATHS
    else:
        paths_to_check = SENSITIVE_PATHS

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {
            executor.submit(_check_single_path, target, path, severity, session, not_found_resp): path
            for path, severity in paths_to_check.items()
        }

        for future in as_completed(future_to_path):
            result = future.result()
            if result:
                findings.append(result)

    return findings
