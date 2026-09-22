"""
core/utils.py — ProxScope shared utilities, data structures, and constants.
"""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
import random
import requests
import urllib3

# Suppress insecure SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Severity Levels ──────────────────────────────────────────────────────────
CRITICAL = 5
HIGH     = 4
MEDIUM   = 3
LOW      = 2
INFO     = 1

SEVERITY_LABELS = {
    5: "CRITICAL",
    4: "HIGH",
    3: "MEDIUM",
    2: "LOW",
    1: "INFO",
}

SEVERITY_STARS = {
    5: "★★★★★",
    4: "★★★★☆",
    3: "★★★☆☆",
    2: "★★☆☆☆",
    1: "★☆☆☆☆",
}

SEVERITY_COLORS = {
    5: "red",
    4: "bright_red",
    3: "yellow",
    2: "blue",
    1: "dim",
}

# ── Finding Data Structure ───────────────────────────────────────────────────
@dataclass
class Finding:
    """Represents an individual security finding."""
    module: str
    severity: int        # 1-5
    title: str
    description: str
    evidence: Optional[str] = None


# ── ASCII Banner ─────────────────────────────────────────────────────────────
BANNER = r"""
[bright_cyan]
  ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝██████╔╝██║   ██║ ╚███╔╝ ███████╗██║     ██║   ██║██████╔╝█████╗  
  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗ ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
  ██║     ██║  ██║╚██████╔╝██╔╝ ██╗███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
[/bright_cyan]
[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
[bright_white]  PROXSCOPE — Adaptive Web Security Scanner & Recon Suite v2.0[/bright_white]
[dim]  by @prox0959 — github.com/prox0959/proxscope[/dim]
[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
"""

# ── Rotating User-Agents ─────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


def normalize_url(url: str) -> str:
    """Normalize URL by ensuring scheme and removing trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_domain(url: str) -> str:
    """Extract domain or hostname from URL."""
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc or url


def make_session(timeout: int = 10) -> requests.Session:
    """Create a configured requests Session."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    session.verify = False
    session.timeout = timeout
    return session
