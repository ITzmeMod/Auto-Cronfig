"""
Main orchestration engine for Auto-Cronfig v3.
Unified scan modes: FAST, STANDARD, DEEP, GLOBAL.
Supports Node.js scraper subprocess integration.
"""

import json
import time
import datetime
import logging
import subprocess  # nosec B404 — used with allowlist validation
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import uuid4

logger = logging.getLogger(__name__)
from concurrent.futures import ThreadPoolExecutor, as_completed

from .memory import Memory
from .scanner import RepoScanner, RawFinding
from .deep_scanner import DeepScanner
from .global_scanner import GlobalScanner
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


class ScanMode(Enum):
    FAST = "fast"        # Files only, no verification, max workers
    STANDARD = "standard"  # Files + verification
    DEEP = "deep"        # Files + commits + PRs + issues + gists + verification
    GLOBAL = "global"    # GitHub code search across all public repos


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
        """Fallback HTML export (used when Jinja2 is not available)."""
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
<title>Auto-Cronfig v3 Report — {self.scan_id}</title>
<style>
  body {{ font-family: sans-serif; background: #0d1117; color: #e6edf3; padding: 20px; }}
  h1 {{ color: #f78166; }} h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px;
              display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ text-align: center; }} .stat-val {{ font-size: 2em; font-weight: bold; color: #f78166; }}
  .stat-label {{ color: #8b949e; font-size: 0.85em; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; padding: 10px 12px; text-align: left; color: #8b949e; font-size: 0.85em; }}
  td {{ padding: 8px 12px; border-top: 1px solid #21262d; font-size: 0.88em; }}
  td a {{ color: #58a6ff; text-decoration: none; }}
  code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  .sev-critical {{ border-left: 3px solid #f85149; }}
  .sev-high {{ border-left: 3px solid #e3b341; }}
  .sev-medium {{ border-left: 3px solid #388bfd; }}
  .sev-low {{ border-left: 3px solid #56d364; }}
  .status-live {{ color: #f85149; font-weight: bold; }}
  .status-dead {{ color: #56d364; }}
  .status-unknown {{ color: #e3b341; }}
  ul.insights {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 16px 16px 32px; }}
  ul.insights li {{ margin: 4px 0; color: #8b949e; }}
</style>
</head>
<body>
<h1>🔍 Auto-Cronfig v3 Scan Report</h1>
<div class="summary">
  <div class="stat"><div class="stat-val">{self.scan_id}</div><div class="stat-label">Scan ID</div></div>
  <div class="stat"><div class="stat-val">{self.target}</div><div class="stat-label">Target</div></div>
  <div class="stat"><div class="stat-val">{self.repos_scanned}</div><div class="stat-label">Repos</div></div>
  <div class="stat"><div class="stat-val">{len(self.findings)}</div><div class="stat-label">Findings</div></div>
  <div class="stat" style="color:#f85149"><div class="stat-val">{len(self.live_keys)}</div><div class="stat-label">Live Keys</div></div>
  <div class="stat"><div class="stat-val">{round(self.duration_seconds, 1)}s</div><div class="stat-label">Duration</div></div>
</div>
<h2>Findings</h2>
<table>
<thead><tr><th>#</th><th>File</th><th>Pattern</th><th>Preview</th><th>Severity</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>
{"".join(rows) if rows else "<tr><td colspan='7' style='text-align:center;color:#8b949e'>No findings</td></tr>"}
</tbody>
</table>
<h2>Insights</h2>
<ul class="insights">
{insight_items if insight_items else "<li>Scan more repos to build intelligence.</li>"}
</ul>
<p style="color:#8b949e;font-size:0.8em;margin-top:32px">Generated by Auto-Cronfig v3 at {datetime.datetime.utcnow().isoformat()} UTC</p>
</body>
</html>"""


class AutoCronfig:
    def __init__(
        self,
        token: Optional[str] = None,
        workers: int = 8,
        verify_keys: bool = True,
        db_path: Optional[str] = None,
        notifier=None,
        use_node: bool = True,
    ):
        self.token = token
        self.workers = workers
        self.verify_keys = verify_keys
        self.notifier = notifier
        self.use_node = use_node
        self.memory = Memory(db_path)
        self.scanner = RepoScanner(token=token, workers=workers, memory=self.memory)
        self.deep_scanner = DeepScanner(token=token, workers=workers, memory=self.memory)
        self.global_scanner = GlobalScanner(token=token, memory=self.memory)
        self.scan_id = uuid4().hex[:8]

    def _auto_detect_type(self, target: str) -> str:
        if target.startswith("http") or "/" in target:
            return "repo"
        return "user"

    def _parse_repo_target(self, target: str) -> tuple:
        clean = target.replace("https://github.com/", "").strip("/")
        if "/" in clean:
            parts = clean.split("/")
            return parts[0], parts[1]
        raise ValueError(f"Cannot parse repo target: {target}")

    def _run_node_scraper(self, mode: str, query: Optional[str] = None) -> List[Dict]:
        """
        Run Node.js scraper as a subprocess and parse NDJSON output.
        Returns list of finding dicts. Silently returns [] if Node not available.
        """
        if not self.use_node:
            return []

        # Check if node is available
        if not shutil.which("node"):
            return []

        # Check if node_scraper/index.js exists
        import os
        from pathlib import Path
        scraper_path = Path(__file__).parent.parent / "node_scraper" / "index.js"
        if not scraper_path.exists():
            return []

        # Validate mode against allowlist to prevent command injection.
        _ALLOWED_MODES = {"paste", "github-web", "gist"}
        if mode not in _ALLOWED_MODES:
            logger.warning("[node-scraper] Rejected unknown mode: %r", mode)
            return []
        # Validate query: strip shell metacharacters, cap length.
        safe_query: Optional[str] = None
        if query:
            import re as _re
            safe_query = _re.sub(r"[^\w\s\-_./:@]", "", str(query))[:200]

        cmd = ["node", str(scraper_path), "--mode", mode]  # nosec B603
        if safe_query:
            cmd += ["--query", safe_query]

        try:
            result = subprocess.run(  # nosec B603 — cmd uses allowlist-validated mode + sanitized query
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=120,
                cwd=str(scraper_path.parent.parent),
            )
            findings = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    findings.append(obj)
                except json.JSONDecodeError:
                    pass
            return findings
        except Exception:
            return []

    def run(self, target: str, mode: ScanMode = ScanMode.STANDARD) -> ScanReport:
        """
        Unified run method. mode controls scan depth and verification.
        """
        start_time = time.monotonic()

        # Determine target type
        if mode == ScanMode.GLOBAL:
            target_type = "global"
        else:
            target_type = self._auto_detect_type(target)

        print(f"\n{'='*62}")
        print(f"  Auto-Cronfig v3 | Scan ID: {self.scan_id} | Mode: {mode.value.upper()}")
        print(f"  Target: {target}  ({target_type})")
        print(f"{'='*62}\n")

        raw_findings: List[RawFinding] = []
        repos_scanned = 0

        # ── Phase 1: File scan ─────────────────────────────────────────────────
        if target_type == "repo":
            owner, repo_name = self._parse_repo_target(target)
            raw_findings = self.scanner.scan_repo(owner, repo_name)
            repos_scanned = 1
        elif target_type == "user":
            raw_findings = self.scanner.scan_user(target)
            repos_scanned = len(set(f.repo for f in raw_findings))
        elif target_type == "global":
            # Use GlobalScanner.run_all_queries() — covers all 200+ patterns
            # If target is a specific search term (not __ALL__), run targeted search
            if target and target not in ("global", "__ALL__", ""):
                raw_findings = self.global_scanner.run_targeted(
                    target, max_results=100)
            else:
                raw_findings = self.global_scanner.run_all_queries(
                    max_per_query=20, fast=True)
            repos_scanned = len(set(f.repo for f in raw_findings))

        print(f"[*] Phase 1 (file scan): {len(raw_findings)} findings")

        # ── Phase 2: Deep scan (DEEP mode only) ────────────────────────────────
        if mode == ScanMode.DEEP and target_type == "repo":
            owner, repo_name = self._parse_repo_target(target)
            print(f"[*] Phase 2 (deep scan: commits, PRs, issues, releases)...")
            deep_findings = self.deep_scanner.full_deep_scan(owner, repo_name)
            print(f"[*] Deep scan: {len(deep_findings)} additional findings")
            raw_findings.extend(deep_findings)

        # ── Phase 3: Node.js scraper (STANDARD/DEEP) ──────────────────────────
        if mode in (ScanMode.STANDARD, ScanMode.DEEP) and self.use_node:
            node_mode = "paste"
            node_findings = self._run_node_scraper(node_mode)
            if node_findings:
                print(f"[*] Node.js scraper: {len(node_findings)} additional findings")
                # Convert node findings to RawFinding objects
                for nf in node_findings:
                    raw_findings.append(RawFinding(
                        repo=nf.get("source", "node-scraper"),
                        file_path=nf.get("url", ""),
                        pattern_name=nf.get("pattern", "Unknown"),
                        match=nf.get("raw", ""),
                        match_preview=nf.get("preview", "")[:80],
                        severity="MEDIUM",
                        url=nf.get("url", ""),
                    ))

        # ── Phase 4: Save to memory ────────────────────────────────────────────
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

        # ── Phase 5: Verify keys ───────────────────────────────────────────────
        do_verify = self.verify_keys and mode != ScanMode.FAST and enriched
        if do_verify:
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
                        self.memory.update_verification(ef.finding_id, result.status, result.detail)
                        self.memory.update_pattern_stats(ef.raw.pattern_name, result.status)

                        # Save live keys to vault
                        if result.status == "LIVE":
                            self.memory.save_leaked_key(
                                scan_id=self.scan_id,
                                repo=ef.raw.repo,
                                file_path=ef.raw.file_path,
                                pattern_name=ef.raw.pattern_name,
                                raw_value=ef.raw.match,
                                severity=ef.raw.severity,
                                url=ef.raw.url,
                                verified_status="LIVE",
                                verified_detail=result.detail,
                            )
                    except Exception as e:
                        ef.verification = VerificationResult(
                            status="ERROR",
                            detail=f"Verification crashed: {e}",
                        )

        for ef in enriched:
            if ef.verification is None:
                self.memory.update_pattern_stats(ef.raw.pattern_name, "UNKNOWN")

        live_keys = [ef for ef in enriched if ef.verified_status == "LIVE"]

        # ── Phase 6: Notifications ─────────────────────────────────────────────
        if self.notifier and enriched:
            for ef in enriched:
                finding_dict = {
                    "severity": ef.raw.severity,
                    "pattern_name": ef.raw.pattern_name,
                    "match_preview": ef.raw.match_preview,
                    "repo": ef.raw.repo,
                    "url": ef.raw.url,
                    "verified_status": ef.verified_status,
                }
                self.notifier.notify_finding(finding_dict, self.scan_id)

        # ── Phase 7: Save scan to history ─────────────────────────────────────
        duration = time.monotonic() - start_time
        self.memory.save_scan(
            scan_id=self.scan_id,
            target=target,
            target_type=target_type,
            stats={
                "repos_scanned": repos_scanned,
                "files_scanned": 0,
                "findings_count": len(enriched),
                "live_keys_count": len(live_keys),
                "duration_seconds": duration,
            },
        )

        insights = self.memory.get_insights()

        report = ScanReport(
            scan_id=self.scan_id,
            target=target,
            target_type=target_type,
            duration_seconds=duration,
            repos_scanned=repos_scanned,
            files_scanned=0,
            findings=enriched,
            live_keys=live_keys,
            insights=insights,
        )

        self._print_report(report)

        # Notify scan complete
        if self.notifier:
            self.notifier.notify_scan_complete(report)

        return report

    def run_watchlist(self) -> List[ScanReport]:
        """Scan all targets in the watchlist."""
        watchlist = self.memory.get_watchlist()
        reports = []

        for item in watchlist:
            target = item["target"]
            target_type = item.get("target_type", "auto")
            scan_mode_str = item.get("scan_mode", "fast")

            mode_map = {
                "fast": ScanMode.FAST,
                "standard": ScanMode.STANDARD,
                "deep": ScanMode.DEEP,
                "global": ScanMode.GLOBAL,
            }
            mode = mode_map.get(scan_mode_str, ScanMode.FAST)

            try:
                report = self.run(target, mode=mode)
                reports.append(report)
                self.memory.update_watchlist_scan(target, len(report.findings))
            except Exception as e:
                print(f"[!] Failed to scan watchlist item {target}: {e}")

        return reports

    def _print_report(self, report: ScanReport):
        print(f"\n{'─'*62}")
        print(f"  SCAN COMPLETE | ID: {report.scan_id}")
        print(f"  Duration: {report.duration_seconds:.1f}s")
        print(f"{'─'*62}")
        print(f"  Repos scanned : {report.repos_scanned}")
        print(f"  Findings      : {len(report.findings)}")

        live_count = len(report.live_keys)
        live_label = f"{live_count} 🚨 LIVE KEYS" if live_count > 0 else "0"
        if HAS_COLOR and live_count > 0:
            live_label = Fore.RED + live_label + Style.RESET_ALL
        print(f"  Live keys     : {live_label}")
        print(f"{'─'*62}\n")

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
