"""
modules/dir_listing.py — Directory Listing & Web Indexing Audit (Multithreaded).
Detects exposed directory trees where web servers permit public file browsing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import urljoin
import requests
from core.utils import Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

DIRECTORIES = {
    "backup/":    MEDIUM,
    "backups/":   MEDIUM,
    "logs/":      MEDIUM,
    "log/":       MEDIUM,
    "admin/":     MEDIUM,
    "data/":      MEDIUM,
    "database/":  MEDIUM,
    "db/":        MEDIUM,
    "private/":   MEDIUM,
    "config/":    MEDIUM,
    "uploads/":   LOW,
    "upload/":    LOW,
    "images/":    LOW,
    "img/":       LOW,
    "css/":       LOW,
    "js/":        LOW,
    "static/":    LOW,
    "media/":     LOW,
    "assets/":    LOW,
    "files/":     LOW,
    "tmp/":       LOW,
    "temp/":      LOW,
    "includes/":  LOW,
    "inc/":       LOW,
    "public/":    LOW,
}

LISTING_INDICATORS = [
    "index of /",
    "<title>index of",
    "directory listing",
    "parent directory",
    "[to parent directory]",
    "<h1>index of",
    "directory listing for",
    "apache server at",
    "nginx/",
    "<address>apache",
    "last modified</a>",
]


def _check_dir(target: str, dir_path: str, severity: int, session: requests.Session) -> Finding | None:
    """Audit single path for directory index."""
    try:
        url = urljoin(target + "/", dir_path)
        resp = session.get(url, timeout=4, allow_redirects=True)

        if resp.status_code != 200:
            return None

        body_lower = resp.text.lower()
        if any(indicator in body_lower for indicator in LISTING_INDICATORS):
            files = re.findall(r'<a[^>]+href="([^"]+)"', resp.text)
            files = [f for f in files if f not in ("../", "/", "?C=N;O=D", "?C=M;O=A",
                                                    "?C=S;O=A", "?C=D;O=A")]
            files_preview = ", ".join(files[:6])

            return Finding(
                module="Directory Listing",
                severity=severity,
                title=f"Open Directory Listing Enabled: /{dir_path}",
                description=f"Path '/{dir_path}' allows public index traversal, exposing directory contents.",
                evidence=f"Exposed files: {files_preview}" if files_preview else None,
            )
    except requests.RequestException:
        return None
    return None


def scan(target: str, session: requests.Session) -> list:
    """Concurrently check common paths for directory indexing."""
    findings = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_dir = {
            executor.submit(_check_dir, target, dir_path, severity, session): dir_path
            for dir_path, severity in DIRECTORIES.items()
        }

        for future in as_completed(future_to_dir):
            res = future.result()
            if res:
                findings.append(res)

    return findings
