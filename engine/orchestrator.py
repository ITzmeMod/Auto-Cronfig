"""
Main orchestration engine for Auto-Cronfig v2.
Ties together scanning, verification, memory, and reporting.
"""

import json
import time
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

from .memory import Memory
from .scanner import RepoScanner, RawFinding
from .verifier import verify, VerificationResult

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def _c(color_code: str, text: str) -> str:
    if HAS_COLOR:
        return color_code + text + Style.RESET_ALL
    return text


SEVERITY_COLOR = {
    "CRITICAL": Fore.RED if HAS_COLOR else "",
    "HIGH": Fore.YELLOW if HAS_COLOR else "",
    "MEDIUM": Fore.CYAN if HAS_COLOR else "",
    "LOW": Fore.WHITE if HAS_COLOR else "",
}

STATUS_COLOR = {
    "LIVE": Fore.RED if HAS_COLOR else "",
    "DEAD": Fore.GREEN if HAS_COLOR else "",
    "UNKNOWN": Fore.YELLOW if HAS_COLOR else "",
    "ERROR": Fore.MAGENTA if HAS_COLOR else "",
    "PENDING": Fore.WHITE if HAS_COLOR else "",
}


@dataclass
class EnrichedFinding:
    """A raw finding enriched with memory ID and verification result."""
    raw: RawFinding
    finding_id: int
    verification: Optional[VerificationResult] = None

    @property
    def verified_status(self) -> str:
        if self.verification:
            return self.verification.status
        return "PENDING"


@dataclass
class ScanReport:
    scan_id: str
    target: str
    target_type: str
    duration_seconds: float
    repos_scanned: int
    files_scanned: int
    findings: List[EnrichedFinding] = field(default_factory=list)
    live_keys: List[EnrichedFinding] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        def finding_dict(ef: EnrichedFinding) -> Dict[str, Any]:
            d = {
                "id": ef.finding_id,
                "repo": ef.raw.repo,
                "file_path": ef.raw.file_path,
                "pattern_name": ef.raw.pattern_name,
                "match_preview": ef.raw.match_preview,
                "severity": ef.raw.severity,
                "url": ef.raw.url,
                "line_number": ef.raw.line_number,
                "verified_status": ef.verified_status,
            }
            if ef.verification:
                d["verified_detail"] = ef.verification.detail
                d["verified_at"] = ef.verification.checked_at
                d["latency_ms"] = ef.verification.latency_ms
            return d

        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "target_type": self.target_type,
            "duration_seconds": round(self.duration_seconds, 2),
            "repos_scanned": self.repos_scanned,
            "files_scanned": self.files_scanned,
            "findings_count": len(self.findings),
            "live_keys_count": len(self.live_keys),
            "findings": [finding_dict(f) for f in self.findings],
            "insights": self.insights,
            "generated_at": datetime.datetime.utcnow().isoformat(),
        }

    def to_html(self) -> str:
        rows = []
        for ef in self.findings:
            sev = ef.raw.severity
            status = ef.verified_status
            sev_class = sev.lower()
            status_class = status.lower()
            rows.append(f"""
            <tr class="sev-{sev_class}">
                <td>{ef.finding_id}</td>
                <td><a href="{ef.raw.url}" target="_blank">{ef.raw.file_path}</a></td>
                <td>{ef.raw.pattern_name}</td>
                <td><code>{ef.raw.match_preview}</code></td>
                <td class="sev-badge">{sev}</td>
                <td class="status-{status_class}">{status}</td>
                <td>{ef.verification.detail if ef.verification else 'Not checked'}</td>
            </tr>""")

        insight_items = "".join(f"<li>{i}</li>" for i in self.insights)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-Cronfig Scan Report — {self.scan_id}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0d1117; color: #e6edf3; margin: 0; padding: 20px; }}
  h1 {{ color: #f78166; }} h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: 16px; display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ text-align: center; }} .stat-val {{ font-size: 2em; font-weight: bold; color: #f78166; }}
  .stat-label {{ color: #8b949e; font-size: 0.85em; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; padding: 10px 12px; text-align: left; color: #8b949e; font-size: 0.85em; }}
  td {{ padding: 8px 12px; border-top: 1px solid #21262d; font-size: 0.88em; }}
  td a {{ color: #58a6ff; text-decoration: none; }} td a:hover {{ text-decoration: underline; }}
  code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  .sev-critical {{ border-left: 3px solid #f85149; }}
  .sev-high {{ border-left: 3px solid #e3b341; }}
  .sev-medium {{ border-left: 3px solid #388bfd; }}
  .sev-low {{ border-left: 3px solid #56d364; }}
  .sev-badge {{ font-weight: bold; }}
  .status-live {{ color: #f85149; font-weight: bold; }}
  .status-dead {{ color: #56d364; }}
  .status-unknown {{ color: #e3b341; }}
  .status-error {{ color: #bc8cff; }}
  ul.insights {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                 padding: 16px 16px 16px 32px; }}
  ul.insights li {{ margin: 4px 0; color: #8b949e; }}
</style>
</head>
<body>
<h1>🔍 Auto-Cronfig Scan Report</h1>
<div class="summary">
  <div class="stat"><div class="stat-val">{self.scan_id}</div><div class="stat-label">Scan ID</div></div>
  <div class="stat"><div class="stat-val">{self.target}</div><div class="stat-label">Target</div></div>
  <div class="stat"><div class="stat-val">{self.repos_scanned}</div><div class="stat-label">Repos Scanned</div></div>
  <div class="stat"><div class="stat-val">{len(self.findings)}</div><div class="stat-label">Findings</div></div>
  <div class="stat" style="color:#f85149"><div class="stat-val">{len(self.live_keys)}</div><div class="stat-label">Live Keys!</div></div>
  <div class="stat"><div class="stat-val">{round(self.duration_seconds, 1)}s</div><div class="stat-label">Duration</div></div>
</div>

<h2>🔑 Findings</h2>
<table>
<thead><tr>
  <th>#</th><th>File</th><th>Pattern</th><th>Preview</th><th>Severity</th><th>Status</th><th>Verification Detail</th>
</tr></thead>
<tbody>
{"".join(rows) if rows else "<tr><td colspan='7' style='text-align:center;color:#8b949e'>No findings</td></tr>"}
</tbody>
</table>

<h2>💡 Intelligence Insights</h2>
<ul class="insights">
{insight_items if insight_items else "<li>Not enough data yet — scan more repos to build intelligence.</li>"}
</ul>

<p style="color:#8b949e;font-size:0.8em;margin-top:32px">
  Generated by <strong>Auto-Cronfig v2</strong> at {datetime.datetime.utcnow().isoformat()} UTC
</p>
</body>
</html>"""


class AutoCronfig:
    def __init__(
        self,
        token: Optional[str] = None,
        workers: int = 8,
        verify_keys: bool = True,
        db_path: Optional[str] = None,
    ):
        self.token = token
        self.workers = workers
        self.verify_keys = verify_keys
        self.memory = Memory(db_path)
        self.scanner = RepoScanner(token=token, workers=workers, memory=self.memory)
        self.scan_id = uuid4().hex[:8]

    def _auto_detect_type(self, target: str) -> str:
        if target.startswith("http") or "/" in target:
            return "repo"
        return "user"

    def _parse_repo_target(self, target: str) -> tuple:
        """Parse 'owner/repo' or full URL into (owner, repo_name)."""
        clean = target.replace("https://github.com/", "").strip("/")
        if "/" in clean:
            parts = clean.split("/")
            return parts[0], parts[1]
        raise ValueError(f"Cannot parse repo target: {target}")

    def run(self, target: str, target_type: str = "auto") -> ScanReport:
        start_time = time.monotonic()

        if target_type == "auto":
            target_type = self._auto_detect_type(target)

        print(f"\n{'='*60}")
        print(f"  Auto-Cronfig v2 | Scan ID: {self.scan_id}")
        print(f"  Target: {target}  ({target_type})")
        print(f"{'='*60}\n")

        raw_findings: List[RawFinding] = []
        repos_scanned = 0
        files_scanned = 0

        # 1. Scan
        if target_type == "repo":
            owner, repo_name = self._parse_repo_target(target)
            raw_findings = self.scanner.scan_repo(owner, repo_name)
            repos_scanned = 1
        elif target_type == "user":
            raw_findings = self.scanner.scan_user(target)
            repos_scanned = -1  # will be updated below
        elif target_type == "global":
            raw_findings = self.scanner.global_search(target)
            repos_scanned = len(set(f.repo for f in raw_findings))
        else:
            raise ValueError(f"Unknown target_type: {target_type}")

        # 2. Save findings to memory and prepare enriched list
        enriched: List[EnrichedFinding] = []
        for rf in raw_findings:
            fid = self.memory.save_finding(
                scan_id=self.scan_id,
                repo=rf.repo,
                file_path=rf.file_path,
                pattern_name=rf.pattern_name,
                match_preview=rf.match_preview,
                severity=rf.severity,
                url=rf.url,
            )
            enriched.append(EnrichedFinding(raw=rf, finding_id=fid))

        # 3. Verify keys concurrently
        if self.verify_keys and enriched:
            print(f"\n[*] Verifying {len(enriched)} findings...")
            verify_workers = min(10, len(enriched))
            with ThreadPoolExecutor(max_workers=verify_workers) as executor:
                future_to_ef = {
                    executor.submit(verify, ef.raw.pattern_name, ef.raw.match): ef
                    for ef in enriched
                }
                for future in as_completed(future_to_ef):
                    ef = future_to_ef[future]
                    try:
                        result = future.result()
                        ef.verification = result
                        self.memory.update_verification(
                            ef.finding_id, result.status, result.detail
                        )
                        self.memory.update_pattern_stats(
                            ef.raw.pattern_name, result.status
                        )
                    except Exception as e:
                        ef.verification = VerificationResult(
                            status="ERROR",
                            detail=f"Verification crashed: {e}",
                        )

        # 4. Separate live keys
        live_keys = [ef for ef in enriched if ef.verified_status == "LIVE"]

        # 5. Update pattern stats for unverified findings
        for ef in enriched:
            if ef.verification is None:
                self.memory.update_pattern_stats(ef.raw.pattern_name, "UNKNOWN")

        # 6. Save scan to history
        duration = time.monotonic() - start_time
        self.memory.save_scan(
            scan_id=self.scan_id,
            target=target,
            target_type=target_type,
            stats={
                "repos_scanned": repos_scanned if repos_scanned >= 0 else len(set(f.repo for f in raw_findings)),
                "files_scanned": files_scanned,
                "findings_count": len(enriched),
                "live_keys_count": len(live_keys),
                "duration_seconds": duration,
            },
        )

        # 7. Get insights
        insights = self.memory.get_insights()

        report = ScanReport(
            scan_id=self.scan_id,
            target=target,
            target_type=target_type,
            duration_seconds=duration,
            repos_scanned=repos_scanned if repos_scanned >= 0 else len(set(f.repo for f in raw_findings)),
            files_scanned=files_scanned,
            findings=enriched,
            live_keys=live_keys,
            insights=insights,
        )

        self._print_report(report)
        return report

    def _print_report(self, report: ScanReport):
        print(f"\n{'─'*60}")
        print(f"  SCAN COMPLETE | ID: {report.scan_id}")
        print(f"  Duration: {report.duration_seconds:.1f}s")
        print(f"{'─'*60}")
        print(f"  Repos scanned : {report.repos_scanned}")
        print(f"  Findings      : {len(report.findings)}")

        live_count = len(report.live_keys)
        live_label = f"{live_count} 🚨 LIVE KEYS" if live_count > 0 else "0"
        if HAS_COLOR and live_count > 0:
            live_label = Fore.RED + live_label + Style.RESET_ALL
        print(f"  Live keys     : {live_label}")
        print(f"{'─'*60}\n")

        if report.findings:
            print("  Findings:\n")
            for ef in report.findings:
                sev = ef.raw.severity
                sev_color = SEVERITY_COLOR.get(sev, "")
                status = ef.verified_status
                status_color = STATUS_COLOR.get(status, "")
                sev_str = _c(sev_color, f"[{sev}]") if HAS_COLOR else f"[{sev}]"
                status_str = _c(status_color, status) if HAS_COLOR else status
                print(f"  {sev_str} {ef.raw.pattern_name}")
                print(f"       File   : {ef.raw.file_path} (line {ef.raw.line_number})")
                print(f"       Preview: {ef.raw.match_preview}")
                print(f"       Status : {status_str}")
                if ef.verification and ef.verification.detail:
                    print(f"       Detail : {ef.verification.detail}")
                print(f"       URL    : {ef.raw.url}")
                print()

        if report.insights:
            print("  💡 Intelligence Insights:")
            for i in report.insights:
                print(f"     • {i}")
            print()
