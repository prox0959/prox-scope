"""
core/reporter.py — Comprehensive Security Report Generator.
Renders calibrated star ratings, rich terminal panels, and exports to HTML, JSON, or Markdown.
"""

from typing import List
from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
from rich import box

from core.utils import (
    Finding, SEVERITY_LABELS, SEVERITY_STARS, SEVERITY_COLORS,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
)

console = Console()

SCORE_PENALTIES = {
    CRITICAL: 2.0,
    HIGH:     1.5,
    MEDIUM:   1.0,
    LOW:      0.5,
    INFO:     0.1,
}


class Reporter:
    """Renders formatted scan reports with star ratings and security scores."""

    def __init__(self, target: str, findings: List[Finding], scan_time: float):
        self.target = target
        self.findings = findings
        self.scan_time = scan_time

    def _calculate_score(self) -> float:
        """Calculate non-linear calibrated security score out of 10."""
        if not self.findings:
            return 10.0

        total_penalty = sum(SCORE_PENALTIES.get(f.severity, 0.1) for f in self.findings)
        score = 10.0 / (1.0 + (total_penalty / 6.0))
        return round(max(0.5, min(10.0, score)), 1)

    def _score_color(self, score: float) -> str:
        if score >= 8.0:
            return "green"
        elif score >= 6.0:
            return "yellow"
        elif score >= 4.0:
            return "bright_red"
        else:
            return "red"

    def _make_bar(self, score: float, width: int = 20) -> str:
        filled = int((score / 10.0) * width)
        empty = width - filled
        return "█" * filled + "░" * empty

    def display(self):
        """Render terminal report panel."""
        if not self.findings:
            panel = Panel(
                "[bright_green]✅ No security vulnerabilities identified!\n\n"
                "The target passed baseline security checks.[/bright_green]",
                title="[bold bright_green]PROX SCAN RESULTS[/bold bright_green]",
                border_style="green",
                box=box.DOUBLE,
                padding=(1, 2),
            )
            console.print(panel)
            return

        grouped = defaultdict(list)
        for f in self.findings:
            grouped[f.severity].append(f)

        output_lines = []

        for severity in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
            if severity not in grouped:
                continue

            items = grouped[severity]
            stars = SEVERITY_STARS[severity]
            label = SEVERITY_LABELS[severity]
            color = SEVERITY_COLORS[severity]
            count = len(items)

            output_lines.append(
                f"[bold {color}]{stars} {label} ({count} finding{'s' if count > 1 else ''})[/bold {color}]"
            )

            for i, finding in enumerate(items):
                prefix = "┗━" if i == len(items) - 1 else "┣━"
                output_lines.append(
                    f"[{color}]  {prefix} {finding.title}[/{color}]"
                )
                output_lines.append(
                    f"[dim]     {finding.description}[/dim]"
                )
                if finding.evidence:
                    evidence_short = finding.evidence[:120]
                    output_lines.append(
                        f"[dim italic]     ↳ Evidence: {evidence_short}[/dim italic]"
                    )

            output_lines.append("")

        score = self._calculate_score()
        score_color = self._score_color(score)
        bar = self._make_bar(score)

        output_lines.append(f"[dim]{'━' * 52}[/dim]")
        output_lines.append(
            f"[bold {score_color}]  OVERALL SECURITY SCORE: {score:.1f}/10 {bar}[/bold {score_color}]"
        )

        output_lines.append("")
        output_lines.append(f"[dim]  🎯 Target:   {self.target}[/dim]")
        output_lines.append(f"[dim]  ⏱  Duration: {self.scan_time:.1f}s[/dim]")
        output_lines.append(f"[dim]  📊 Total:    {len(self.findings)} findings[/dim]")

        summary_parts = []
        for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
            if sev in grouped:
                summary_parts.append(f"{SEVERITY_LABELS[sev]}:{len(grouped[sev])}")
        if summary_parts:
            output_lines.append(f"[dim]  📋 Breakdown: {' | '.join(summary_parts)}[/dim]")

        content = "\n".join(output_lines)

        panel = Panel(
            content,
            title="[bold bright_cyan]⚡ PROXSCOPE SECURITY AUDIT RESULTS ⚡[/bold bright_cyan]",
            border_style="bright_cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
        console.print(panel)

    def export_report(self, filepath: str):
        """Export findings to HTML, JSON, or Markdown report."""
        import json
        from datetime import datetime

        score = self._calculate_score()

        if filepath.endswith(".json"):
            data = {
                "scanner": "ProxScope v2.0",
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "scan_time_seconds": round(self.scan_time, 2),
                "security_score": score,
                "total_findings": len(self.findings),
                "findings": [
                    {
                        "module": f.module,
                        "severity": f.severity,
                        "severity_label": SEVERITY_LABELS.get(f.severity, "UNKNOWN"),
                        "title": f.title,
                        "description": f.description,
                        "evidence": f.evidence,
                    }
                    for f in self.findings
                ],
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            console.print(f"[bright_green]✓ JSON report saved to:[/bright_green] [cyan]{filepath}[/cyan]")

        elif filepath.endswith(".md"):
            md_lines = [
                f"# ⚡ ProxScope Security Audit Report",
                f"",
                f"- **Target:** `{self.target}`",
                f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"- **Duration:** {self.scan_time:.1f}s",
                f"- **Security Score:** **{score:.1f} / 10**",
                f"- **Total Findings:** {len(self.findings)}",
                f"",
                f"---",
                f"",
                f"## Findings Summary",
                f"",
            ]
            for f in self.findings:
                stars = SEVERITY_STARS.get(f.severity, "★")
                label = SEVERITY_LABELS.get(f.severity, "INFO")
                md_lines.append(f"### {stars} [{label}] {f.title}")
                md_lines.append(f"- **Module:** `{f.module}`")
                md_lines.append(f"- **Description:** {f.description}")
                if f.evidence:
                    md_lines.append(f"- **Evidence:** `{f.evidence}`")
                md_lines.append("")

            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(md_lines))
            console.print(f"[bright_green]✓ Markdown report saved to:[/bright_green] [cyan]{filepath}[/cyan]")

        elif filepath.endswith(".html"):
            findings_html = ""
            for f in self.findings:
                sev_color = {5: "#ff4d4d", 4: "#ff944d", 3: "#ffd11a", 2: "#4da6ff", 1: "#a6a6a6"}.get(f.severity, "#ccc")
                stars = SEVERITY_STARS.get(f.severity, "★")
                label = SEVERITY_LABELS.get(f.severity, "INFO")
                evidence_box = f'<div class="evidence">↳ Evidence: <code>{f.evidence}</code></div>' if f.evidence else ""

                findings_html += f"""
                <div class="finding-card" style="border-left: 4px solid {sev_color};">
                    <div class="card-header">
                        <span class="badge" style="background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}66;">{stars} {label}</span>
                        <span class="module-tag">{f.module}</span>
                    </div>
                    <div class="card-title">{f.title}</div>
                    <div class="card-desc">{f.description}</div>
                    {evidence_box}
                </div>
                """

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prox Security Report — {self.target}</title>
    <style>
        body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 30px; margin: 0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 25px 0; border-bottom: 1px solid #30363d; margin-bottom: 30px; }}
        h1 {{ color: #58a6ff; margin: 0 0 10px 0; font-size: 28px; }}
        .meta {{ color: #8b949e; font-size: 14px; }}
        .score-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 30px; }}
        .score-val {{ font-size: 42px; font-weight: bold; color: {'#3fb950' if score >= 8 else '#d29922' if score >= 5 else '#f85149'}; }}
        .finding-card {{ background: #161b22; border-radius: 6px; padding: 15px; margin-bottom: 15px; border: 1px solid #30363d; }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .module-tag {{ color: #8b949e; font-size: 12px; }}
        .card-title {{ color: #f0f6fc; font-size: 16px; font-weight: 600; margin-bottom: 6px; }}
        .card-desc {{ color: #8b949e; font-size: 14px; line-height: 1.5; }}
        .evidence {{ margin-top: 10px; padding: 8px; background: #0d1117; border-radius: 4px; font-size: 13px; color: #79c0ff; word-break: break-all; }}
        code {{ font-family: Consolas, monospace; }}
        .footer {{ text-align: center; color: #484f58; font-size: 12px; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ PROXSCOPE SECURITY AUDIT REPORT</h1>
            <div class="meta">Target: <strong>{self.target}</strong> | Duration: {self.scan_time:.1f}s | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        <div class="score-box">
            <div>SECURITY SCORE</div>
            <div class="score-val">{score:.1f} / 10</div>
            <div class="meta">Evaluated across 16 reconnaissance and vulnerability modules.</div>
        </div>
        <h2>Audit Findings</h2>
        {findings_html or '<p style="color: #3fb950; text-align:center;">No vulnerabilities identified!</p>'}
        <div class="footer">Generated by ProxScope v2.0 — @prox0959</div>
    </div>
</body>
</html>"""
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
            console.print(f"[bright_green]✓ HTML report saved to:[/bright_green] [cyan]{filepath}[/cyan]")
