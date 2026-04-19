#!/usr/bin/env python3
"""
Auto-Cronfig v3 — Enterprise GitHub Secret Scanner
Full-featured CLI with scan, deep, global, watch, vault, stats, config commands.

Usage:
  python scanner.py scan --repo owner/repo
  python scanner.py scan --user username --mode deep
  python scanner.py deep --repo owner/repo
  python scanner.py global --auto
  python scanner.py watch --add owner/repo
  python scanner.py vault --live-only
  python scanner.py stats --full
  python scanner.py --help
"""

import sys
import os
import json
from typing import List
import argparse

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import requests  # noqa
except ImportError:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

from engine.orchestrator import AutoCronfig, ScanMode
from engine.memory import Memory
from engine.security import (
    validate_github_username, validate_github_repo,
    sanitise_query, validate_output_path,
    redact_token, print_startup_notice, check_config_permissions,
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, TOOL_REPO,
)
from engine.notifier import Notifier


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_token(args):
    return (
        getattr(args, "token", None)
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
    )


def _get_notifier(args):
    if getattr(args, "notify", False):
        return Notifier.from_env()
    return None


def _get_db_path(args):
    return getattr(args, "db_path", None)


def _save_output(report, output_path: str):
    """Save report to file based on extension."""
    from engine.exporter import Exporter
    exporter = Exporter(report)

    if output_path.endswith(".json"):
        exporter.to_json(output_path)
        print(f"[✓] JSON report saved: {output_path}")
    elif output_path.endswith(".html"):
        exporter.to_html(output_path)
        print(f"[✓] HTML report saved: {output_path}")
    elif output_path.endswith(".csv"):
        exporter.to_csv(output_path)
        print(f"[✓] CSV report saved: {output_path}")
    elif output_path.endswith(".md"):
        exporter.to_markdown(output_path)
        print(f"[✓] Markdown report saved: {output_path}")
    else:
        exporter.to_json(output_path)
        print(f"[✓] Report saved (JSON): {output_path}")


# ── Command handlers ──────────────────────────────────────────────────────────


def _wrap_findings(findings):
    """Wrap RawFinding objects so they look like EnrichedFinding to Exporter.
    EnrichedFinding already has .raw attr — RawFinding does not.
    """
    class _W:
        __slots__ = ("raw", "finding_id", "verification", "verified_status")
        def __init__(self, f):
            self.raw             = f
            self.finding_id      = 0
            self.verification    = None
            self.verified_status = "PENDING"
    result = []
    for f in findings:
        if hasattr(f, "raw"):
            result.append(f)   # already EnrichedFinding
        else:
            result.append(_W(f))
    return result


def _save_findings_to_file(findings, path: str, scan_id: str, mem=None):
    """Save findings list to file. Supports .json .csv .html .md.
    Also saves all findings to the memory vault (deduplicating by hash).
    Called on scan completion AND on Ctrl+C interrupt.
    """
    from engine.exporter import Exporter
    from engine.orchestrator import ScanReport
    import csv as _csv
    import time as _t

    # ── Always save to memory DB (vault) ──────────────────────────────────
    if mem:
        for f in findings:
            try:
                mem.save_leaked_key(
                    scan_id=scan_id,
                    repo=f.repo,
                    file_path=f.file_path,
                    pattern_name=f.pattern_name,
                    raw_value=f.match if hasattr(f, "match") and f.match else f.match_preview,
                    severity=f.severity,
                    url=f.url,
                    verified_status="PENDING",
                    verified_detail="",
                )
            except Exception as _vault_exc:  # nosec B110
                logger.debug("vault save error: %s", _vault_exc)

    if not path:
        return

    ext = path.rsplit(".", 1)[-1].lower() if "." in path else "json"

    if ext == "html":
        wrapped = _wrap_findings(findings)
        report = ScanReport(
            scan_id=scan_id, target=scan_id, target_type="scan",
            duration_seconds=0,
            repos_scanned=len(set(
                (f.raw.repo if hasattr(f, "raw") else f.repo) for f in findings)),
            files_scanned=len(findings),
            findings=wrapped, live_keys=[], insights=[],
        )
        Exporter(report).to_html(path)

    elif ext == "csv":
        with open(path, "w", newline="", encoding="utf-8") as fp:
            w = _csv.DictWriter(fp, fieldnames=[
                "repo", "file", "pattern", "severity", "preview", "url"])
            w.writeheader()
            for f in findings:
                w.writerow({
                    "repo": f.repo, "file": f.file_path,
                    "pattern": f.pattern_name, "severity": f.severity,
                    "preview": f.match_preview, "url": f.url,
                })

    elif ext == "md":
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(f"# Auto-Cronfig Scan Report\n\n")
            fp.write(f"**Scan ID:** {scan_id}  \n")
            fp.write(f"**Findings:** {len(findings)}  \n\n")
            fp.write("| Severity | Pattern | Repo | File | URL |\n")
            fp.write("|----------|---------|------|------|-----|\n")
            for f in findings:
                fp.write(f"| {f.severity} | {f.pattern_name} | "
                         f"{f.repo} | {f.file_path} | {f.url} |\n")

    else:  # json (default)
        with open(path, "w", encoding="utf-8") as fp:
            json.dump({
                "scan_id": scan_id,
                "total": len(findings),
                "generated_at": _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime()),
                "findings": [{
                    "repo": f.repo, "file": f.file_path,
                    "pattern": f.pattern_name, "severity": f.severity,
                    "preview": f.match_preview, "url": f.url,
                } for f in findings],
            }, fp, indent=2, ensure_ascii=False)


def cmd_scan(args):
    """Scan a repo or user."""
    token = _get_token(args)
    notifier = _get_notifier(args)
    db_path = _get_db_path(args)

    mode_map = {
        "fast": ScanMode.FAST,
        "standard": ScanMode.STANDARD,
        "deep": ScanMode.DEEP,
        "global": ScanMode.GLOBAL,
    }
    mode = mode_map.get(getattr(args, "mode", "standard"), ScanMode.STANDARD)

    engine = AutoCronfig(
        token=token,
        workers=getattr(args, "workers", 8),
        verify_keys=not getattr(args, "no_verify", False),
        db_path=db_path,
        notifier=notifier,
        use_node=not getattr(args, "no_node", False),
    )

    output = getattr(args, "output", None)
    if output:
        try:
            output = validate_output_path(output)
        except ValueError as e:
            print(f"  \033[91m✗ {e}\033[0m")
            return

    report = None
    try:
        if args.repo:
            try:
                validate_github_repo(args.repo)
            except ValueError as e:
                print(f"  \033[91m✗ Invalid repo: {e}\033[0m")
                return
            report = engine.run(args.repo, mode=mode)
        elif args.user:
            try:
                validate_github_username(args.user)
            except ValueError as e:
                print(f"  \033[91m✗ Invalid username: {e}\033[0m")
                return
            report = engine.run(args.user, mode=mode)
        else:
            print("[!] Specify --repo or --user")
            return
    except KeyboardInterrupt:
        print("\n  \033[93m⚠ Scan interrupted — saving partial results…\033[0m")

    if report:
        if output:
            _save_output(report, output)
        # Print rich table if available
        from engine.exporter import Exporter
        Exporter(report).print_rich_table()
    elif output:
        print(f"  \033[33m⚠ No report generated (interrupted before completion)\033[0m")


def cmd_deep(args):
    """Deep scan a repo (commits, PRs, issues, gists)."""
    token = _get_token(args)
    notifier = _get_notifier(args)
    db_path = _get_db_path(args)

    if not args.repo:
        print("[!] --repo OWNER/REPO required for deep scan")
        return

    engine = AutoCronfig(
        token=token,
        workers=getattr(args, "workers", 8),
        verify_keys=not getattr(args, "no_verify", False),
        db_path=db_path,
        notifier=notifier,
        use_node=not getattr(args, "no_node", False),
    )
    output = getattr(args, "output", None)
    report = None
    try:
        report = engine.run(args.repo, mode=ScanMode.DEEP)
    except KeyboardInterrupt:
        print("\n  \033[93m⚠ Deep scan interrupted — saving partial results…\033[0m")

    if report and output:
        _save_output(report, output)
    elif report:
        from engine.exporter import Exporter
        Exporter(report).print_rich_table()


def cmd_global(args):
    """Global scan — all of public GitHub for any leaked secret.
    Findings are saved to memory DB on each hit.
    File is written incrementally — Ctrl+C still saves partial results.
    """
    import time as _time
    import signal
    from engine.global_scanner import GlobalScanner, GLOBAL_SEARCH_QUERIES, CATEGORY_QUERY_MAP
    from engine.verifier import verify as _verify

    token       = _get_token(args)
    db_path     = _get_db_path(args)
    mem         = Memory(db_path)
    fast        = getattr(args, "mode", "fast") != "safe"
    max_results = int(getattr(args, "max_results", None) or 20)
    output      = getattr(args, "output", None)
    scan_id     = f"global-{int(_time.time())}"
    gs          = GlobalScanner(token=token, memory=mem)

    SEV = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
           "MEDIUM":   "\033[33m", "LOW":  "\033[36m"}
    RST = "\033[0m"

    # ── Incremental output buffer ─────────────────────────────────────────
    _all_findings = []
    _output_path  = output

    def _flush_output():
        """Write current findings to file — called on completion and Ctrl+C."""
        if not _output_path or not _all_findings:
            return
        try:
            _save_findings_to_file(_all_findings, _output_path, scan_id, mem)
            print(f"\n  \033[32m✓ Saved {len(_all_findings)} findings → {_output_path}\033[0m")
        except Exception as exc:
            print(f"\n  \033[31m✗ Save error: {exc}\033[0m")

    def _on_sigint(sig, frame):
        print(f"\n\n  \033[93m⚠ Scan interrupted — saving {len(_all_findings)} findings…\033[0m")
        _flush_output()
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_sigint)

    def _on_hit(h):
        """Called for each finding — save to memory + print immediately."""
        _all_findings.append(h)
        fid = mem.save_finding(
            scan_id=scan_id, repo=h.repo, file_path=h.file_path,
            pattern_name=h.pattern_name, match_preview=h.match_preview,
            severity=h.severity, url=h.url,
        )
        mem.update_file_stats(h.file_path.rsplit(".", 1)[-1] if "." in h.file_path else "unknown",
                              had_finding=True)
        mem.update_pattern_stats(h.pattern_name, "UNKNOWN")
        c = SEV.get(h.severity, "")
        print(f"  {c}[{h.severity}]{RST} {h.pattern_name}")
        print(f"    \033[2m{h.repo}/{h.file_path}\033[0m")
        print(f"    {h.url}")

    if getattr(args, "auto", False):
        gs.run_auto_scan(
            interval_seconds=getattr(args, "interval", 3600),
            output_path=output)
        return

    query = getattr(args, "query", None) or getattr(args, "global_query", None)
    if query and query not in ("__ALL__",) and not query.startswith("__CAT:"):
        query = sanitise_query(query)
        if not query:
            print("  \033[91m✗ Invalid search query\033[0m")
            return
    t0 = _time.monotonic()

    try:
        if query and query.startswith("__CAT:") and query.endswith("__"):
            cat_name   = query[6:-2]
            cat_queries = CATEGORY_QUERY_MAP.get(cat_name, [])
            if not cat_queries:
                print(f"  Unknown category: {cat_name!r}")
                return
            print(f"\n  Category: {cat_name}  {len(cat_queries)} queries  "
                  f"{'fast' if fast else 'safe'}\n")
            for i, q in enumerate(cat_queries, 1):
                pct = int(i / len(cat_queries) * 100)
                bar = "\u2588" * (pct // 5) + "\u2591" * (20 - pct // 5)
                sys.stdout.write(
                    f"\r  [{bar}] {pct:3d}%  {i}/{len(cat_queries)}  {len(_all_findings)} found  ")
                sys.stdout.flush()
                gs.run_targeted(q, max_results=max_results, callback=_on_hit)
            print()

        elif not query or query == "__ALL__":
            print(f"\n  Running {len(GLOBAL_SEARCH_QUERIES)} queries — "
                  f"{'fast' if fast else 'safe'} mode\n")
            gs._seen = set()
            # Attach callback at GlobalScanner level
            gs.run_all_queries(max_per_query=max_results, callback=_on_hit, fast=fast)

        else:
            print(f"\n  Searching GitHub: {query!r}\n")
            gs.run_targeted(query, max_results=max_results * 5, callback=_on_hit)

    except KeyboardInterrupt:
        pass  # SIGINT handler will flush

    dur = _time.monotonic() - t0
    crit = sum(1 for f in _all_findings if f.severity == "CRITICAL")
    high = sum(1 for f in _all_findings if f.severity == "HIGH")
    print(f"\n  \033[32m✓ {len(_all_findings)} findings  "
          f"dur={dur:.0f}s\033[0m  "
          f"\033[91mCRIT:{crit}\033[0m  \033[93mHIGH:{high}\033[0m")

    mem.save_scan(scan_id=scan_id, target=query or "global",
                  target_type="global",
                  stats={"repos_scanned": len(set(f.repo for f in _all_findings)),
                         "files_scanned": 0,
                         "findings_count": len(_all_findings),
                         "live_keys_count": 0,
                         "duration_seconds": dur})

    # Restore default SIGINT before flushing
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    _flush_output()


def cmd_vibe(args):
    """VibeScan — new AI-scaffolded repos (Lovable, Bolt, Replit, Base44, v0…).
    Findings saved to memory DB on each hit.
    Ctrl+C saves partial results automatically.
    """
    import time as _time
    import signal
    from engine.vibe_scanner import VibeScanner, VIBE_SCAN_QUERIES, VIBE_PLATFORM_SIGNALS

    token       = _get_token(args)
    db_path     = _get_db_path(args)
    mem         = Memory(db_path)
    fast        = getattr(args, "mode", "fast") != "safe"
    max_results = int(getattr(args, "max_results", None) or 20)
    output      = getattr(args, "output", None)
    platform    = getattr(args, "platform", None)
    days        = int(getattr(args, "days", None) or 7)
    continuous  = getattr(args, "continuous", False)
    repo_mode   = getattr(args, "repos", False)
    scan_id     = f"vibe-{int(_time.time())}"
    vs          = VibeScanner(token=token, workers=8, memory=mem)

    SEV = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
           "MEDIUM":   "\033[33m", "LOW":  "\033[36m"}
    RST = "\033[0m"

    _all_findings = []
    _output_path  = output

    def _flush_output():
        if not _output_path or not _all_findings:
            return
        try:
            _save_findings_to_file(_all_findings, _output_path, scan_id, mem)
            print(f"\n  \033[32m✓ Saved {len(_all_findings)} findings → {_output_path}\033[0m")
        except Exception as exc:
            print(f"\n  \033[31m✗ Save error: {exc}\033[0m")

    def _on_sigint(sig, frame):
        print(f"\n\n  \033[93m⚠ VibeScan interrupted — saving {len(_all_findings)} findings…\033[0m")
        _flush_output()
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_sigint)

    def _on_hit(h):
        _all_findings.append(h)
        fid = mem.save_finding(
            scan_id=scan_id, repo=h.repo, file_path=h.file_path,
            pattern_name=h.pattern_name, match_preview=h.match_preview,
            severity=h.severity, url=h.url,
        )
        mem.update_file_stats(h.file_path.rsplit(".", 1)[-1] if "." in h.file_path else "unknown",
                              had_finding=True)
        mem.update_pattern_stats(h.pattern_name, "UNKNOWN")
        c = SEV.get(h.severity, "")
        print(f"  {c}[{h.severity}]{RST} {h.pattern_name}")
        print(f"    \033[2m{h.repo}/{h.file_path}\033[0m")
        print(f"    {h.url}")

    # Sanitise platform name against known allowlist
    _ALLOWED_PLATFORMS = {
        None, "lovable","bolt","replit","base44","v0","cursor",
        "windsurf","claude","copilot","devin","gptengineer",
        "magic","env","repos",
    }
    if platform and platform not in _ALLOWED_PLATFORMS:
        print(f"  \033[91m✗ Unknown platform: {platform!r}\033[0m")
        print(f"  Allowed: {sorted(p for p in _ALLOWED_PLATFORMS if p)}")
        return

    if continuous:
        interval = int(getattr(args, "interval", None) or 1800)
        vs.run_continuous(interval_seconds=interval, output_path=output)
        return

    t0 = _time.monotonic()
    print(f"\n  \033[96mVibeScan\033[0m — new AI-scaffolded repos\n")

    try:
        if platform:
            findings = vs.scan_platform(platform, max_per_query=max_results, callback=_on_hit)
        elif repo_mode:
            findings = vs.search_new_vibe_repos(days=days, max_repos=50, callback=_on_hit)
        else:
            print(f"  {len(VIBE_SCAN_QUERIES)} queries — {'fast' if fast else 'safe'} mode\n")
            findings = vs.run_vibe_queries(max_per_query=max_results,
                                           callback=_on_hit, fast=fast)
    except KeyboardInterrupt:
        findings = _all_findings

    dur = _time.monotonic() - t0
    crit = sum(1 for f in _all_findings if f.severity == "CRITICAL")
    high = sum(1 for f in _all_findings if f.severity == "HIGH")
    print(f"\n  \033[32m✓ {len(_all_findings)} findings  dur={dur:.0f}s\033[0m  "
          f"\033[91mCRIT:{crit}\033[0m  \033[93mHIGH:{high}\033[0m")

    mem.save_scan(scan_id=scan_id, target=platform or "all-vibe",
                  target_type="vibe",
                  stats={"repos_scanned": len(set(f.repo for f in _all_findings)),
                         "files_scanned": 0,
                         "findings_count": len(_all_findings),
                         "live_keys_count": 0,
                         "duration_seconds": dur})

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    _flush_output()


def cmd_watch(args):
    """Manage watchlist."""
    db_path = _get_db_path(args)
    mem = Memory(db_path)

    if getattr(args, "add", None):
        target = args.add
        target_type = "repo" if "/" in target else "user"
        wid = mem.add_to_watchlist(
            target=target,
            target_type=target_type,
            scan_mode=getattr(args, "mode", "fast"),
            notes=getattr(args, "notes", ""),
        )
        print(f"[✓] Added to watchlist: {target} (id: {wid})")

    elif getattr(args, "run", False):
        token = _get_token(args)
        engine = AutoCronfig(
            token=token,
            workers=getattr(args, "workers", 8),
            verify_keys=not getattr(args, "no_verify", False),
            db_path=db_path,
        )
        reports = engine.run_watchlist()
        print(f"\n[✓] Watchlist scan complete: {len(reports)} repos scanned")

    elif getattr(args, "list", False) or not any([getattr(args, "add", None), getattr(args, "run", False)]):
        items = mem.get_watchlist()
        if not items:
            print("  Watchlist is empty. Add targets with: scanner.py watch --add owner/repo")
            return
        print(f"\n  Watchlist ({len(items)} items):\n")
        for item in items:
            status = f"Last scanned: {item.get('last_scanned', 'never')}"
            findings = item.get("findings_count", 0)
            print(f"  [{item['id']}] {item['target']} ({item['target_type']}) "
                  f"| mode: {item['scan_mode']} | findings: {findings} | {status}")

    mem.close()


def cmd_vault(args):
    """Show and export the leaked keys vault."""
    db_path = _get_db_path(args)
    mem = Memory(db_path)

    status_filter = "LIVE" if getattr(args, "live_only", False) else None
    pattern_filter = getattr(args, "pattern", None)
    keys = mem.get_leaked_keys(status=status_filter)

    if pattern_filter:
        keys = [k for k in keys if pattern_filter.lower() in k.get("pattern_name", "").lower()]

    print(f"\n  🔑 Leaked Keys Vault ({len(keys)} entries)\n")

    if not keys:
        print("  No leaked keys found.")
    else:
        for k in keys:
            sev = k.get("severity", "?")
            status = k.get("verified_status", "?")
            print(f"  [{sev}] [{status}] {k.get('pattern_name', '?')}")
            print(f"    Preview : {k.get('mask_preview', '****')}")
            print(f"    Repo    : {k.get('repo', '?')}")
            print(f"    File    : {k.get('file_path', '?')}")
            print(f"    URL     : {k.get('url', '?')}")
            print(f"    Seen    : {k.get('first_seen', '?')}")
            print()

    export_path = getattr(args, "export", None)
    if export_path:
        if export_path.endswith(".json"):
            mem.export_leaked_keys_json(export_path)
            print(f"[✓] Exported to {export_path}")
        elif export_path.endswith(".csv"):
            mem.export_findings_csv(export_path)
            print(f"[✓] Exported to {export_path}")

    mem.close()


def cmd_stats(args):
    """Show memory insights dashboard."""
    db_path = _get_db_path(args)
    mem = Memory(db_path)

    full = getattr(args, "full", False)
    export_path = getattr(args, "export", None)

    if full:
        insights_data = mem.get_advanced_insights()
        stats = insights_data["lifetime"]
    else:
        stats = mem.get_lifetime_stats()
        insights_data = None

    print("\n" + "=" * 58)
    print("  Auto-Cronfig v3 — Intelligence Dashboard")
    print("=" * 58)
    print(f"  Total scans          : {stats['total_scans']}")
    print(f"  Repos scanned        : {stats['total_repos_scanned']}")
    print(f"  Files scanned        : {stats['total_files_scanned']}")
    print(f"  Total findings       : {stats['total_findings']}")
    print(f"  Live keys confirmed  : {stats['total_live_keys']}")
    print(f"  Active patterns      : {stats['active_patterns']}")
    print(f"  Leaked keys vault    : {stats.get('total_leaked_keys_vault', 0)}")
    print("=" * 58)

    insights = mem.get_insights()
    if insights:
        print("\n  💡 Insights:")
        for i in insights:
            print(f"     • {i}")

    if full and insights_data:
        top_patterns = insights_data.get("top_patterns", [])
        if top_patterns:
            print("\n  Top Patterns:")
            print(f"  {'Pattern':<35} {'Found':>6} {'Live':>6}")
            print(f"  {'─'*35} {'─'*6} {'─'*6}")
            for p in top_patterns[:15]:
                print(f"  {p['pattern_name'][:35]:<35} {p['total_found']:>6} {p['verified_live']:>6}")

        top_repos = insights_data.get("top_repos", [])
        if top_repos:
            print("\n  Top Repos by Findings:")
            for r in top_repos[:10]:
                print(f"     {r['repo']}: {r['findings_count']} findings")

    pattern_perf = mem.get_pattern_performance()
    if pattern_perf and not full:
        print("\n  Pattern Performance (top 20):")
        print(f"  {'Pattern':<35} {'Found':>6} {'Live':>6} {'Dead':>6}")
        print(f"  {'─'*35} {'─'*6} {'─'*6} {'─'*6}")
        for pname, pdata in sorted(
            pattern_perf.items(), key=lambda x: x[1]["total_found"], reverse=True
        )[:20]:
            print(
                f"  {pname[:35]:<35} {pdata['total_found']:>6} "
                f"{pdata['verified_live']:>6} {pdata['verified_dead']:>6}"
            )

    if export_path and export_path.endswith(".html"):
        # Build a simple stats HTML
        from engine.exporter import Exporter
        # Create a minimal fake report for export
        print(f"[*] HTML stats export not yet implemented for standalone stats. Use scan --output report.html")

    print()
    mem.close()


def cmd_config(args):
    """Show or set configuration."""
    print("\n  Auto-Cronfig v3 — Configuration\n")
    print(f"  GITHUB_TOKEN   : {'set' if os.environ.get('GITHUB_TOKEN') else 'not set'}")
    print(f"  GH_TOKEN       : {'set' if os.environ.get('GH_TOKEN') else 'not set'}")
    print(f"  AC_TELEGRAM_TOKEN : {'set' if os.environ.get('AC_TELEGRAM_TOKEN') else 'not set'}")
    print(f"  AC_DISCORD_WEBHOOK: {'set' if os.environ.get('AC_DISCORD_WEBHOOK') else 'not set'}")
    print(f"  AC_SLACK_WEBHOOK  : {'set' if os.environ.get('AC_SLACK_WEBHOOK') else 'not set'}")
    print(f"  AC_NOTIFY_SEVERITY: {os.environ.get('AC_NOTIFY_SEVERITY', 'CRITICAL,HIGH')}")
    print("\n  Set via environment variables:")
    print("    export GITHUB_TOKEN=ghp_xxxx")
    print("    export AC_TELEGRAM_TOKEN=bot_token")
    print("    export AC_TELEGRAM_CHAT_ID=chat_id")
    print("    export AC_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...")
    print("    export AC_NOTIFY_SEVERITY=CRITICAL,HIGH")


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Auto-Cronfig v3 — Enterprise GitHub Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py scan --repo torvalds/linux
  python scanner.py scan --user octocat --mode fast
  python scanner.py deep --repo owner/repo --output report.html
  python scanner.py global --query "AKIA" --output findings.json
  python scanner.py global --auto --interval 3600
  python scanner.py watch --add owner/repo --mode standard
  python scanner.py watch --run
  python scanner.py vault --live-only --export vault.json
  python scanner.py stats --full
  python scanner.py config
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # ── Common options factory ───────────────────────────────────────────────
    def add_common(p):
        p.add_argument("--token", metavar="TOKEN", help="GitHub personal access token")
        p.add_argument("--db-path", dest="db_path", metavar="PATH", help="Custom memory DB path")
        p.add_argument("--workers", type=int, default=8, metavar="N", help="Concurrent workers (default: 8)")
        p.add_argument("--no-verify", dest="no_verify", action="store_true", help="Skip key verification")
        p.add_argument("--no-node", dest="no_node", action="store_true", help="Skip Node.js scraper")
        p.add_argument("--notify", action="store_true", help="Send notifications for critical findings")
        p.add_argument("--output", metavar="FILE", help="Save report (.json|.csv|.html|.md)")

    # ── scan ─────────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser("scan", help="Scan a repo or user")
    scan_target = scan_p.add_mutually_exclusive_group(required=True)
    scan_target.add_argument("--repo", metavar="OWNER/REPO", help="Scan a repository")
    scan_target.add_argument("--user", metavar="USERNAME", help="Scan all repos for a user")
    scan_p.add_argument("--mode", choices=["fast", "standard", "deep", "global", "vibe"], default="standard")
    add_common(scan_p)
    scan_p.set_defaults(func=cmd_scan)

    # ── deep ─────────────────────────────────────────────────────────────────
    deep_p = subparsers.add_parser("deep", help="Deep scan (commits, PRs, issues, gists)")
    deep_p.add_argument("--repo", metavar="OWNER/REPO", required=True)
    deep_p.add_argument("--max-commits", type=int, default=500, dest="max_commits")
    deep_p.add_argument("--max-prs", type=int, default=100, dest="max_prs")
    add_common(deep_p)
    deep_p.set_defaults(func=cmd_deep)

    # ── global ───────────────────────────────────────────────────────────────
    global_p = subparsers.add_parser("global", help="Auto global scan across GitHub")
    global_p.add_argument("--query", metavar="TERM", help="Custom search query (omit = run all 200+ built-in queries)")
    global_p.add_argument("--auto", action="store_true", help="Continuous auto-scan mode")
    global_p.add_argument("--interval", type=int, default=3600, metavar="SECONDS")
    global_p.add_argument("--output", metavar="FILE", help="Save results (.json|.csv|.html)")
    global_p.add_argument("--token", metavar="TOKEN")
    global_p.add_argument("--db-path", dest="db_path", metavar="PATH")
    global_p.add_argument("--max-results", type=int, default=20, metavar="N",
                          help="Max results per query (default 20)")
    global_p.add_argument("--mode", choices=["fast", "safe"], default="fast",
                          help="fast=parallel batches (default), safe=sequential")
    global_p.set_defaults(func=cmd_global)


    # ── vibe ─────────────────────────────────────────────────────────────────
    vibe_p = subparsers.add_parser("vibe",
        help="Scan new AI-scaffolded repos (Lovable, Bolt, Replit, Base44, v0…)")
    vibe_p.add_argument("--platform", metavar="NAME",
        help="Target one platform: lovable|bolt|replit|base44|v0|cursor|windsurf|claude")
    vibe_p.add_argument("--repos", action="store_true",
        help="Repo-search mode: find new vibe repos then scan files directly")
    vibe_p.add_argument("--days", type=int, default=7, metavar="N",
        help="Scan repos pushed in last N days (default 7)")
    vibe_p.add_argument("--continuous", action="store_true",
        help="Run continuously (repeat every --interval seconds)")
    vibe_p.add_argument("--interval", type=int, default=1800, metavar="SECONDS",
        help="Interval for continuous mode (default 1800)")
    vibe_p.add_argument("--output", metavar="FILE",
        help="Save results (.json|.csv|.html)")
    vibe_p.add_argument("--token", metavar="TOKEN")
    vibe_p.add_argument("--db-path", dest="db_path", metavar="PATH")
    vibe_p.add_argument("--max-results", type=int, default=20, metavar="N")
    vibe_p.add_argument("--mode", choices=["fast","safe"], default="fast")
    vibe_p.set_defaults(func=cmd_vibe)

    # ── watch ────────────────────────────────────────────────────────────────
    watch_p = subparsers.add_parser("watch", help="Manage watchlist")
    watch_grp = watch_p.add_mutually_exclusive_group()
    watch_grp.add_argument("--add", metavar="TARGET", help="Add target to watchlist")
    watch_grp.add_argument("--run", action="store_true", help="Scan all watchlist targets")
    watch_grp.add_argument("--list", action="store_true", help="List watchlist items")
    watch_p.add_argument("--mode", choices=["fast", "standard", "deep"], default="fast")
    watch_p.add_argument("--notes", metavar="TEXT", default="")
    watch_p.add_argument("--token", metavar="TOKEN")
    watch_p.add_argument("--db-path", dest="db_path", metavar="PATH")
    watch_p.add_argument("--workers", type=int, default=8)
    watch_p.add_argument("--no-verify", dest="no_verify", action="store_true")
    watch_p.set_defaults(func=cmd_watch)

    # ── vault ────────────────────────────────────────────────────────────────
    vault_p = subparsers.add_parser("vault", help="Show/export leaked keys vault")
    vault_p.add_argument("--export", metavar="FILE", help="Export to .json or .csv")
    vault_p.add_argument("--live-only", dest="live_only", action="store_true")
    vault_p.add_argument("--pattern", metavar="PATTERN_NAME", help="Filter by pattern name")
    vault_p.add_argument("--db-path", dest="db_path", metavar="PATH")
    vault_p.set_defaults(func=cmd_vault)

    # ── stats ────────────────────────────────────────────────────────────────
    stats_p = subparsers.add_parser("stats", help="Show memory insights dashboard")
    stats_p.add_argument("--full", action="store_true", help="Show all insights")
    stats_p.add_argument("--export", metavar="FILE", help="Export stats (.html)")
    stats_p.add_argument("--db-path", dest="db_path", metavar="PATH")
    stats_p.set_defaults(func=cmd_stats)

    # ── config ───────────────────────────────────────────────────────────────
    config_p = subparsers.add_parser("config", help="Show/set configuration")
    config_p.set_defaults(func=cmd_config)

    return parser


def main():
    # Legacy mode: support old-style flags for backward compatibility
    # (python scanner.py --repo owner/repo)
    if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
        # Backward-compatible legacy mode
        _legacy_main()
        return

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


def _legacy_main():
    """Backward-compatible CLI for v2-style invocations."""
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Auto-Cronfig v3 — GitHub Secret Scanner (legacy mode)",
        add_help=True,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--repo", metavar="OWNER/REPO")
    group.add_argument("--user", metavar="USERNAME")
    group.add_argument("--global", metavar="QUERY", dest="global_query",
                       help="Global scan (omit value or use __ALL__ for all 200+ queries)")
    group.add_argument("--stats", action="store_true")

    parser.add_argument("--token", metavar="TOKEN")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--output", metavar="FILE")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-results", type=int, default=100, dest="max_results")
    parser.add_argument("--db-path", metavar="PATH", default=None, dest="db_path")
    parser.add_argument("--mode", choices=["fast", "standard", "deep", "global", "vibe"], default="standard")

    args = parser.parse_args()

    if args.stats:
        args.full = False
        args.export = None
        cmd_stats(args)
        return

    if not any([args.repo, args.user, args.global_query]):
        parser.print_help()
        sys.exit(0)

    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    engine = AutoCronfig(
        token=token,
        workers=args.workers,
        verify_keys=not args.no_verify,
        db_path=args.db_path,
    )

    mode_map = {"fast": ScanMode.FAST, "standard": ScanMode.STANDARD,
                "deep": ScanMode.DEEP, "global": ScanMode.GLOBAL, "vibe": ScanMode.VIBE}
    mode = mode_map.get(args.mode, ScanMode.STANDARD)

    if args.repo:
        report = engine.run(args.repo, mode=mode)
    elif args.user:
        report = engine.run(args.user, mode=mode)
    elif args.global_query:
        # Route to cmd_global so ALL 200+ queries fire (not just one search term)
        class _FakeArgs:
            query       = args.global_query if args.global_query != "__ALL__" else None
            global_query= args.global_query
            auto        = False
            interval    = 3600
            output      = getattr(args, "output", None)
            token       = getattr(args, "token", None)
            db_path     = getattr(args, "db_path", None)
            max_results = getattr(args, "max_results", 20)
            mode        = getattr(args, "mode", "fast")
        cmd_global(_FakeArgs())
    else:
        return


if __name__ == "__main__":
    main()
