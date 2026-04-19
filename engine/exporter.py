"""
Results export engine for Auto-Cronfig v3.
Exports scan reports to JSON, CSV, HTML, and Markdown.
"""

import csv
import json
import datetime
from pathlib import Path
from typing import Any

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ── HTML Template ──────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-Cronfig v3 Scan Report — {{ report.scan_id }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
         background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; line-height: 1.6; }
  a { color: #58a6ff; text-decoration: none; } a:hover { text-decoration: underline; }
  h1 { color: #f78166; margin: 0 0 8px; font-size: 1.8em; }
  h2 { color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; margin-top: 32px; }
  .subtitle { color: #8b949e; margin-bottom: 24px; font-size: 0.9em; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 16px; margin-bottom: 32px; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
               padding: 16px; text-align: center; }
  .stat-val { font-size: 2em; font-weight: 700; color: #f78166; display: block; }
  .stat-val.green { color: #56d364; } .stat-val.red { color: #f85149; }
  .stat-val.blue { color: #58a6ff; } .stat-val.yellow { color: #e3b341; }
  .stat-label { color: #8b949e; font-size: 0.8em; margin-top: 4px; }
  .severity-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 24px; }
  .sev-pill { padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }
  .sev-critical { background: rgba(248,81,73,0.2); color: #f85149; border: 1px solid #f85149; }
  .sev-high { background: rgba(227,179,65,0.2); color: #e3b341; border: 1px solid #e3b341; }
  .sev-medium { background: rgba(88,166,255,0.2); color: #58a6ff; border: 1px solid #58a6ff; }
  .sev-low { background: rgba(86,211,100,0.2); color: #56d364; border: 1px solid #56d364; }
  .live-section { background: rgba(248,81,73,0.08); border: 1px solid #f85149;
                  border-radius: 10px; padding: 16px; margin-bottom: 24px; }
  .live-section h3 { color: #f85149; margin: 0 0 12px; }
  table { width: 100%; border-collapse: collapse; background: #161b22;
          border-radius: 10px; overflow: hidden; }
  th { background: #21262d; padding: 10px 14px; text-align: left;
       color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 10px 14px; border-top: 1px solid #21262d; font-size: 0.85em; vertical-align: top; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .sev-row-critical td { border-left: 3px solid #f85149; }
  .sev-row-high td { border-left: 3px solid #e3b341; }
  .sev-row-medium td { border-left: 3px solid #58a6ff; }
  .sev-row-low td { border-left: 3px solid #56d364; }
  code { background: #0d1117; padding: 2px 6px; border-radius: 4px;
         font-size: 0.82em; color: #e3b341; word-break: break-all; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
           font-weight: 600; font-size: 0.75em; }
  .badge-critical { background: rgba(248,81,73,0.2); color: #f85149; }
  .badge-high { background: rgba(227,179,65,0.2); color: #e3b341; }
  .badge-medium { background: rgba(88,166,255,0.2); color: #58a6ff; }
  .badge-low { background: rgba(86,211,100,0.2); color: #56d364; }
  .status-live { color: #f85149; font-weight: 700; }
  .status-dead { color: #56d364; }
  .status-unknown { color: #e3b341; }
  .status-error { color: #bc8cff; }
  .status-pending { color: #8b949e; }
  .insights-list { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
                   padding: 16px; list-style: none; margin: 0; }
  .insights-list li { padding: 6px 0; border-bottom: 1px solid #21262d; color: #8b949e; font-size: 0.9em; }
  .insights-list li:last-child { border-bottom: none; }
  .insights-list li::before { content: "💡 "; }
  footer { color: #484f58; font-size: 0.78em; margin-top: 40px; text-align: center; }
  @media (max-width: 768px) { body { padding: 12px; } th, td { padding: 8px; font-size: 0.78em; } }
</style>
</head>
<body>
<h1>🔍 Auto-Cronfig v3 — Scan Report</h1>
<p class="subtitle">
  Scan ID: <code>{{ report.scan_id }}</code> &nbsp;|&nbsp;
  Target: <strong>{{ report.target }}</strong> &nbsp;|&nbsp;
  Generated: {{ generated_at }}
</p>

<div class="stats-grid">
  <div class="stat-card">
    <span class="stat-val blue">{{ report.scan_id }}</span>
    <div class="stat-label">Scan ID</div>
  </div>
  <div class="stat-card">
    <span class="stat-val blue">{{ report.repos_scanned }}</span>
    <div class="stat-label">Repos Scanned</div>
  </div>
  <div class="stat-card">
    <span class="stat-val yellow">{{ findings_count }}</span>
    <div class="stat-label">Total Findings</div>
  </div>
  <div class="stat-card">
    <span class="stat-val {% if live_count > 0 %}red{% else %}green{% endif %}">{{ live_count }}</span>
    <div class="stat-label">🔑 Live Keys</div>
  </div>
  <div class="stat-card">
    <span class="stat-val green">{{ report.duration_seconds|round(1) }}s</span>
    <div class="stat-label">Duration</div>
  </div>
</div>

<!-- Severity breakdown -->
<h2>📊 Severity Breakdown</h2>
<div class="severity-bar">
  {% for sev, count in severity_counts.items() %}
  <span class="sev-pill sev-{{ sev|lower }}">{{ sev }}: {{ count }}</span>
  {% endfor %}
</div>

{% if live_findings %}
<!-- Live keys section -->
<h2>🚨 Live Keys Detected</h2>
<div class="live-section">
  <h3>⚠️ {{ live_findings|length }} Active Credential(s) Found!</h3>
  <table>
    <thead><tr>
      <th>#</th><th>Pattern</th><th>Preview</th><th>Repo</th><th>File</th><th>Verification</th>
    </tr></thead>
    <tbody>
    {% for ef in live_findings %}
    <tr class="sev-row-{{ ef.raw.severity|lower }}">
      <td>{{ loop.index }}</td>
      <td><span class="badge badge-{{ ef.raw.severity|lower }}">{{ ef.raw.severity }}</span> {{ ef.raw.pattern_name }}</td>
      <td><code>{{ ef.raw.match_preview[:60] }}</code></td>
      <td>{{ ef.raw.repo }}</td>
      <td><a href="{{ ef.raw.url }}" target="_blank">{{ ef.raw.file_path }}</a></td>
      <td class="status-live">{{ ef.verification.detail if ef.verification else 'LIVE' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<!-- All findings table -->
<h2>🔑 All Findings</h2>
{% if report.findings %}
<table>
<thead><tr>
  <th>#</th><th>Severity</th><th>Pattern</th><th>Preview</th><th>File</th><th>Status</th><th>Detail</th>
</tr></thead>
<tbody>
{% for ef in report.findings %}
<tr class="sev-row-{{ ef.raw.severity|lower }}">
  <td>{{ ef.finding_id }}</td>
  <td><span class="badge badge-{{ ef.raw.severity|lower }}">{{ ef.raw.severity }}</span></td>
  <td>{{ ef.raw.pattern_name }}</td>
  <td><code>{{ ef.raw.match_preview[:60] }}</code></td>
  <td><a href="{{ ef.raw.url }}" target="_blank">{{ ef.raw.file_path }}</a><br>
    <small style="color:#8b949e">L{{ ef.raw.line_number }} · {{ ef.raw.repo }}</small></td>
  <td class="status-{{ ef.verified_status|lower }}">{{ ef.verified_status }}</td>
  <td>{{ ef.verification.detail if ef.verification else '—' }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p style="color:#8b949e;text-align:center;padding:24px">No findings — repo looks clean!</p>
{% endif %}

{% if report.insights %}
<!-- Insights -->
<h2>💡 Intelligence Insights</h2>
<ul class="insights-list">
{% for insight in report.insights %}
<li>{{ insight }}</li>
{% endfor %}
</ul>
{% endif %}

<footer>
  Generated by <strong>Auto-Cronfig v3</strong> — Enterprise GitHub Secret Scanner<br>
  {{ generated_at }} UTC
</footer>
</body>
</html>
"""


class Exporter:
    def __init__(self, report):
        self.report = report

    def to_json(self, path: str):
        """Full JSON export with all findings and metadata."""
        data = self.report.to_json() if hasattr(self.report, "to_json") else {}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def to_csv(self, path: str):
        """CSV export with all finding details."""
        findings = getattr(self.report, "findings", [])
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "repo", "file", "pattern", "severity",
                "preview", "url", "verified_status", "verified_detail", "timestamp"
            ])
            for ef in findings:
                writer.writerow([
                    ef.finding_id,
                    ef.raw.repo,
                    ef.raw.file_path,
                    ef.raw.pattern_name,
                    ef.raw.severity,
                    ef.raw.match_preview,
                    ef.raw.url,
                    ef.verified_status,
                    ef.verification.detail if ef.verification else "",
                    ef.verification.checked_at if ef.verification else "",
                ])

    def to_html(self, path: str):
        """Beautiful dark-theme HTML report using Jinja2."""
        findings = getattr(self.report, "findings", [])
        live_findings = [ef for ef in findings if ef.verified_status == "LIVE"]

        # Count by severity
        severity_counts: dict = {}
        for ef in findings:
            sev = ef.raw.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Sort severity_counts: CRITICAL first
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_counts = {
            k: severity_counts[k]
            for k in order
            if k in severity_counts
        }

        generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        if HAS_JINJA2:
            template = Template(HTML_TEMPLATE)
            html = template.render(
                report=self.report,
                findings_count=len(findings),
                live_count=len(live_findings),
                live_findings=live_findings,
                severity_counts=severity_counts,
                generated_at=generated_at,
            )
        else:
            # Fallback: use the orchestrator's to_html method
            if hasattr(self.report, "to_html"):
                html = self.report.to_html()
            else:
                html = f"<html><body><h1>Report {getattr(self.report, 'scan_id', '')}</h1><pre>{json.dumps(self.report.to_json() if hasattr(self.report, 'to_json') else {}, indent=2)}</pre></body></html>"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def to_markdown(self, path: str):
        """Markdown report for sharing in GitHub issues or PRs."""
        findings = getattr(self.report, "findings", [])
        live_findings = [ef for ef in findings if ef.verified_status == "LIVE"]
        scan_id = getattr(self.report, "scan_id", "unknown")
        target = getattr(self.report, "target", "unknown")
        duration = round(getattr(self.report, "duration_seconds", 0), 1)
        insights = getattr(self.report, "insights", [])

        lines = [
            f"# 🔍 Auto-Cronfig v3 Scan Report",
            f"",
            f"**Scan ID:** `{scan_id}`  ",
            f"**Target:** `{target}`  ",
            f"**Duration:** {duration}s  ",
            f"**Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | {len(findings)} |",
            f"| 🔴 Live Keys | {len(live_findings)} |",
            f"| Repos Scanned | {getattr(self.report, 'repos_scanned', 0)} |",
            f"",
        ]

        if live_findings:
            lines += [
                f"## 🚨 Live Keys",
                f"",
                f"> ⚠️ **{len(live_findings)} active credential(s) found — revoke immediately!**",
                f"",
                f"| Pattern | Preview | Repo | URL |",
                f"|---------|---------|------|-----|",
            ]
            for ef in live_findings:
                lines.append(
                    f"| {ef.raw.pattern_name} | `{ef.raw.match_preview[:40]}` | {ef.raw.repo} | [link]({ef.raw.url}) |"
                )
            lines.append("")

        if findings:
            lines += [
                f"## Findings",
                f"",
                f"| # | Severity | Pattern | Preview | File | Status |",
                f"|---|----------|---------|---------|------|--------|",
            ]
            for ef in findings:
                lines.append(
                    f"| {ef.finding_id} | {ef.raw.severity} | {ef.raw.pattern_name} | "
                    f"`{ef.raw.match_preview[:30]}` | [{ef.raw.file_path}]({ef.raw.url}) | {ef.verified_status} |"
                )
            lines.append("")

        if insights:
            lines += [
                f"## 💡 Insights",
                f"",
            ]
            for i in insights:
                lines.append(f"- {i}")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by [Auto-Cronfig v3](https://github.com/ITzmeMod/Auto-Cronfig)*")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def print_rich_table(self):
        """Print a beautiful terminal table using rich library."""
        findings = getattr(self.report, "findings", [])

        if not HAS_RICH:
            # Plain fallback
            print(f"\n{'='*70}")
            print(f"  Scan ID: {getattr(self.report, 'scan_id', 'unknown')}")
            print(f"  Findings: {len(findings)}")
            print(f"{'='*70}")
            for ef in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.raw.severity) if x.raw.severity in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99):
                print(f"  [{ef.raw.severity}] {ef.raw.pattern_name}")
                print(f"    {ef.raw.file_path} - {ef.raw.match_preview[:60]}")
                print(f"    Status: {ef.verified_status}")
            return

        console = Console()
        table = Table(
            title=f"🔍 Auto-Cronfig v3 — Scan {getattr(self.report, 'scan_id', '')}",
            show_header=True,
            header_style="bold #8b949e",
            border_style="#30363d",
            expand=True,
        )

        table.add_column("#", style="dim", width=5)
        table.add_column("Severity", width=10)
        table.add_column("Pattern", style="bold", min_width=20)
        table.add_column("Preview", min_width=25)
        table.add_column("File", min_width=20)
        table.add_column("Status", width=10)

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "bold blue",
            "LOW": "bold green",
        }
        status_colors = {
            "LIVE": "bold red",
            "DEAD": "green",
            "UNKNOWN": "yellow",
            "ERROR": "magenta",
            "PENDING": "dim",
        }

        # Sort: CRITICAL first
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sorted_findings = sorted(
            findings,
            key=lambda x: order.index(x.raw.severity) if x.raw.severity in order else 99
        )

        for ef in sorted_findings:
            sev = ef.raw.severity
            status = ef.verified_status
            table.add_row(
                str(ef.finding_id),
                Text(sev, style=severity_colors.get(sev, "white")),
                ef.raw.pattern_name,
                Text(ef.raw.match_preview[:50], style="dim yellow"),
                ef.raw.file_path[:40],
                Text(status, style=status_colors.get(status, "white")),
            )

        console.print(table)
        console.print(f"\n  [bold]Total:[/bold] {len(findings)} findings  |  "
                      f"[bold red]Live:[/bold red] {len([f for f in findings if f.verified_status == 'LIVE'])}")
