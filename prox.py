#!/usr/bin/env python3
"""
prox.py — Main CLI Entry Point for ProxScope.
Adaptive Security Scanner & Recon Suite v2.0 by @prox0959
"""

import sys
import time
import argparse

# UTF-8 terminal encoding configuration
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from core.utils import BANNER
from core.scanner import ScanEngine
from core.reporter import Reporter

console = Console()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="ProxScope — Adaptive Web Security Scanner & Recon Suite",
        epilog="Example: python proxscope.py https://example.com -o report.html",
    )
    parser.add_argument(
        "target",
        help="Target URL to audit (e.g., https://example.com)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=8,
        help="HTTP request timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Export findings to file (.html, .json, or .md)",
    )
    parser.add_argument(
        "--no-learn",
        action="store_true",
        help="Disable automatic endpoint and parameter learning",
    )
    return parser.parse_args()


def main():
    """Main execution flow."""
    args = parse_args()

    # Clear screen and display banner
    console.clear()
    console.print(BANNER)

    start_time = time.time()
    engine = ScanEngine(
        target=args.target,
        timeout=args.timeout,
        enable_learning=not args.no_learn,
    )

    try:
        findings = engine.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]✗ Fatal error: {e}[/red]")
        sys.exit(1)

    scan_time = time.time() - start_time

    # Display results
    reporter = Reporter(
        target=engine.target,
        findings=findings,
        scan_time=scan_time,
    )
    reporter.display()

    # Export report if requested
    if args.output:
        reporter.export_report(args.output)

    console.print("\n[dim]ProxScope — @prox0959[/dim]\n")


if __name__ == "__main__":
    main()
