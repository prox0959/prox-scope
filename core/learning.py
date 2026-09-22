"""
core/learning.py — Adaptive Asset Discovery & Self-Learning Engine.
Mimics AI knowledge accumulation: discovers new endpoints, parameters, and paths
from sitemaps, robots.txt, and link graphs, persists them to a local knowledge base,
and feeds them into future security scans.
"""

import os
import json
import re
from urllib.parse import urlparse
from typing import List, Set, Dict
from rich.console import Console

console = Console()

KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "knowledge")
KNOWLEDGE_FILE = os.path.join(KNOWLEDGE_DIR, "learned_assets.json")


class LearningEngine:
    """Self-learning engine that stores discovered endpoints and parameters."""

    def __init__(self, auto_save: bool = True):
        self.auto_save = auto_save
        self.endpoints: Set[str] = set()
        self.parameters: Set[str] = set()
        self.subdomains: Set[str] = set()
        self._load()

    def _load(self):
        """Load persistent knowledge from disk."""
        if os.path.exists(KNOWLEDGE_FILE):
            try:
                with open(KNOWLEDGE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.endpoints = set(data.get("endpoints", []))
                    self.parameters = set(data.get("parameters", []))
                    self.subdomains = set(data.get("subdomains", []))
            except Exception:
                pass

    def save(self):
        """Save current knowledge state to disk."""
        os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
        data = {
            "endpoints": sorted(list(self.endpoints)),
            "parameters": sorted(list(self.parameters)),
            "subdomains": sorted(list(self.subdomains)),
        }
        try:
            with open(KNOWLEDGE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            console.print(f"[dim]Failed to save knowledge base: {e}[/dim]")

    def learn_endpoint(self, path: str, source: str = "") -> bool:
        """Register a newly discovered path. Returns True if novel."""
        clean_path = path.strip().lstrip("/").split("?")[0].split("#")[0]
        if not clean_path or clean_path in self.endpoints or len(clean_path) > 80:
            return False

        # Ignore noisy static assets
        if any(clean_path.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".ico"]):
            return False

        self.endpoints.add(clean_path)
        console.print(f"[bold green]★ [LEARNED NEW ASSET][/bold green] Discovered novel endpoint: [green]/{clean_path}[/green] [dim]({source})[/dim]")

        if self.auto_save:
            self.save()
        return True

    def learn_parameter(self, param: str, source: str = "") -> bool:
        """Register a newly discovered parameter. Returns True if novel."""
        clean_param = param.strip()
        if not clean_param or clean_param in self.parameters or len(clean_param) > 40:
            return False

        self.parameters.add(clean_param)
        console.print(f"[bold green]★ [LEARNED NEW PARAM][/bold green] Discovered novel parameter: [green]{clean_param}[/green] [dim]({source})[/dim]")

        if self.auto_save:
            self.save()
        return True

    def learn_subdomain(self, subdomain: str) -> bool:
        """Register a newly discovered subdomain."""
        sub = subdomain.strip().lower()
        if not sub or sub in self.subdomains:
            return False

        self.subdomains.add(sub)
        console.print(f"[bold green]★ [LEARNED SUBDOMAIN][/bold green] Discovered host: [green]{sub}[/green]")

        if self.auto_save:
            self.save()
        return True

    def process_sitemap(self, xml_text: str, target: str):
        """Extract URLs from sitemap.xml and learn novel paths."""
        locs = re.findall(r"<loc>(.*?)</loc>", xml_text, re.IGNORECASE)
        for loc in locs[:30]:
            parsed = urlparse(loc)
            if parsed.path:
                self.learn_endpoint(parsed.path, "sitemap.xml")

    def process_robots(self, robots_text: str, target: str):
        """Extract paths from robots.txt and learn novel paths."""
        paths = re.findall(r"(?:Disallow|Allow):\s*([^\s#]+)", robots_text, re.IGNORECASE)
        for p in paths:
            self.learn_endpoint(p, "robots.txt")

    def get_learned_endpoints(self) -> List[str]:
        """Return all learned endpoints for testing."""
        return sorted(list(self.endpoints))

    def get_stats(self) -> Dict[str, int]:
        """Return knowledge base counts."""
        return {
            "endpoints": len(self.endpoints),
            "parameters": len(self.parameters),
            "subdomains": len(self.subdomains),
        }
