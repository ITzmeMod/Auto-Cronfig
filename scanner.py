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

    if args.repo:
        report = engine.run(args.repo, mode=mode)
    elif args.user:
        report = engine.run(args.user, mode=mode)
    else:
        print("[!] Specify --repo or --user")
        return

    if getattr(args, "output", None):
        _save_output(report, args.output)

    # Print rich table if available
    from engine.exporter import Exporter
    Exporter(report).print_rich_table()


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
    report = engine.run(args.repo, mode=ScanMode.DEEP)

    if getattr(args, "output", None):
        _save_output(report, args.output)


def cmd_global(args):
    """Global scan — all of public GitHub for any leaked secret."""
    from engine.global_scanner import GlobalScanner, GLOBAL_SEARCH_QUERIES

    token       = _get_token(args)
    db_path     = _get_db_path(args)
    mem         = Memory(db_path)
    fast        = getattr(args, "mode", "standard") == "fast"
    max_results = int(getattr(args, "max_results", None) or 20)
    output      = getattr(args, "output", None)
    gs          = GlobalScanner(token=token, memory=mem)

    SEV = {
        "CRITICAL": "[91m", "HIGH": "[93m",
        "MEDIUM":   "[33m", "LOW":  "[36m",
    }
    RST = "[0m"

    def _show(h):
        c = SEV.get(h.severity, "")
        print(f"  {c}[{h.severity}]{RST} {h.pattern_name}")
        print(f"    {h.repo}/{h.file_path}")
        print(f"    {h.url}")

    def _save(findings, path):
        ext = path.rsplit(".", 1)[-1].lower()
        if ext == "json":
            with open(path, "w") as fp:
                json.dump([{
                    "repo": f.repo, "file": f.file_path,
                    "pattern": f.pattern_name, "severity": f.severity,
                    "preview": f.match_preview, "url": f.url,
                } for f in findings], fp, indent=2)
        elif ext == "csv":
            import csv
            with open(path, "w", newline="") as fp:
                w = csv.DictWriter(fp, fieldnames=[
                    "repo", "file", "pattern", "severity", "preview", "url"])
                w.writeheader()
                for f in findings:
                    w.writerow({"repo": f.repo, "file": f.file_path,
                                "pattern": f.pattern_name, "severity": f.severity,
                                "preview": f.match_preview, "url": f.url})
        elif ext == "html":
            from engine.exporter import Exporter
            from engine.orchestrator import ScanReport
            report = ScanReport(
                scan_id="global", target="global", target_type="global",
                duration_seconds=0, repos_scanned=0, files_scanned=0,
                findings=findings, live_keys=[], insights=[],
            )
            Exporter(report).to_html(path)
        else:
            with open(path, "w") as fp:
                for f in findings:
                    fp.write(f"[{f.severity}] {f.pattern_name} | "
                             f"{f.repo}/{f.file_path} | {f.url}\n")
        print(f"  \u2713 Saved → {path}")

    if getattr(args, "auto", False):
        gs.run_auto_scan(
            interval_seconds=getattr(args, "interval", 3600),
            output_path=output)
        return

    query = getattr(args, "query", None) or getattr(args, "global_query", None)

    # ── Sentinel: __CAT:NAME__ — run focused category query list ─────────────
    if query and query.startswith("__CAT:") and query.endswith("__"):
        from engine.global_scanner import CATEGORY_QUERY_MAP
        cat_name = query[6:-2]  # strip __CAT: and __
        cat_queries = CATEGORY_QUERY_MAP.get(cat_name, [])
        if not cat_queries:
            print(f"  Unknown category: {cat_name!r}")
            return
        print(f"\n  Category: {cat_name} — {len(cat_queries)} queries — "
              f"{'fast' if fast else 'safe'} mode\n")
        all_findings: List[RawFinding] = []
        for i, q in enumerate(cat_queries, 1):
            pct = int(i / len(cat_queries) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            sys.stdout.write(f"\r  [{bar}] {pct:3d}%  {i}/{len(cat_queries)}  {len(all_findings)} found  ")
            sys.stdout.flush()
            hits = gs.run_targeted(q, max_results=max_results)
            for h in hits:
                _show(h)
            all_findings.extend(hits)
        print()
        findings = all_findings

    # ── No query or __ALL__: run every built-in query ─────────────────────────
    elif not query or query == "__ALL__":
        print(f"\n  Running {len(GLOBAL_SEARCH_QUERIES)} queries — "
              f"{'fast' if fast else 'safe'} mode\n")
        findings = gs.run_all_queries(
            max_per_query=max_results, callback=_show, fast=fast)

    # ── Custom search term ────────────────────────────────────────────────────
    else:
        print(f"\n  Searching GitHub: {query!r}\n")
        findings = gs.run_targeted(query, max_results=max_results * 5)
        for h in findings:
            _show(h)

    crit = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]
    print(f"\n  ✓ {len(findings)} total findings", end="")
    if crit: print(f"  [91mCRITICAL:{len(crit)}[0m", end="")
    if high: print(f"  [93mHIGH:{len(high)}[0m", end="")
    print()

    if output and findings:
        _save(findings, output)
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
    scan_p.add_argument("--mode", choices=["fast", "standard", "deep", "global"], default="standard")
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
    parser.add_argument("--mode", choices=["fast", "standard", "deep", "global"], default="standard")

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
                "deep": ScanMode.DEEP, "global": ScanMode.GLOBAL}
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
