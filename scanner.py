#!/usr/bin/env python3
"""
Auto-Cronfig v2 — GitHub Secret & Vulnerability Scanner
CLI entry point (backward compatible).

Usage:
  python scanner.py --repo owner/repo
  python scanner.py --user username
  python scanner.py --global AKIA
  python scanner.py --stats
  python scanner.py --output report.json
  python scanner.py --output report.html
"""

import sys
import json
import argparse
import os

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import requests  # noqa
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

from engine.orchestrator import AutoCronfig
from engine.memory import Memory


def cmd_stats(args):
    """Show lifetime memory stats and insights."""
    db_path = args.db_path if hasattr(args, "db_path") else None
    mem = Memory(db_path)
    stats = mem.get_lifetime_stats()
    insights = mem.get_insights()

    print("\n" + "="*55)
    print("  Auto-Cronfig v2 — Intelligence Dashboard")
    print("="*55)
    print(f"  Total scans          : {stats['total_scans']}")
    print(f"  Repos scanned        : {stats['total_repos_scanned']}")
    print(f"  Files scanned        : {stats['total_files_scanned']}")
    print(f"  Total findings       : {stats['total_findings']}")
    print(f"  Live keys confirmed  : {stats['total_live_keys']}")
    print(f"  Active patterns      : {stats['active_patterns']}")
    print("="*55)

    if insights:
        print("\n  💡 Insights:")
        for i in insights:
            print(f"     • {i}")
    else:
        print("\n  No insights yet — scan some repos first!")

    pattern_perf = mem.get_pattern_performance()
    if pattern_perf:
        print("\n  Pattern Performance:")
        print(f"  {'Pattern':<35} {'Found':>6} {'Live':>6} {'Dead':>6}")
        print(f"  {'─'*35} {'─'*6} {'─'*6} {'─'*6}")
        for pname, pdata in sorted(
            pattern_perf.items(), key=lambda x: x[1]["total_found"], reverse=True
        )[:20]:
            print(
                f"  {pname[:35]:<35} {pdata['total_found']:>6} "
                f"{pdata['verified_live']:>6} {pdata['verified_dead']:>6}"
            )
    print()
    mem.close()


def main():
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Auto-Cronfig v2 — GitHub Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --repo torvalds/linux
  python scanner.py --user octocat
  python scanner.py --global AKIA
  python scanner.py --stats
  python scanner.py --repo owner/repo --output report.json
  python scanner.py --repo owner/repo --output report.html --no-verify
        """,
    )

    # Scan target (mutually exclusive)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--repo", metavar="OWNER/REPO", help="Scan a specific repository")
    group.add_argument("--user", metavar="USERNAME", help="Scan all public repos for a user")
    group.add_argument(
        "--global",
        metavar="QUERY",
        dest="global_query",
        help="Global GitHub code search for a term",
    )
    group.add_argument("--stats", action="store_true", help="Show memory stats and insights")

    # Options
    parser.add_argument("--token", metavar="TOKEN", help="GitHub personal access token")
    parser.add_argument("--no-verify", action="store_true", help="Skip live key verification")
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save report to file (.json or .html)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Number of concurrent workers (default: 8)",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=100,
        metavar="N",
        help="Max results for global search (default: 100)",
    )
    parser.add_argument(
        "--db-path",
        metavar="PATH",
        default=None,
        help="Custom path for memory database",
    )

    args = parser.parse_args()

    # Resolve token: CLI arg > env var
    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    if args.stats:
        cmd_stats(args)
        return

    if not any([args.repo, args.user, args.global_query]):
        parser.print_help()
        sys.exit(0)

    engine = AutoCronfig(
        token=token,
        workers=args.workers,
        verify_keys=not args.no_verify,
        db_path=args.db_path,
    )

    if args.repo:
        report = engine.run(args.repo, target_type="repo")
    elif args.user:
        report = engine.run(args.user, target_type="user")
    elif args.global_query:
        report = engine.run(args.global_query, target_type="global")
    else:
        parser.print_help()
        sys.exit(0)

    # Output
    if args.output:
        out_path = args.output
        if out_path.endswith(".html"):
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(report.to_html())
            print(f"[✓] HTML report saved: {out_path}")
        elif out_path.endswith(".json"):
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report.to_json(), f, indent=2)
            print(f"[✓] JSON report saved: {out_path}")
        else:
            # Try to infer from content
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report.to_json(), f, indent=2)
            print(f"[✓] Report saved as JSON: {out_path}")


if __name__ == "__main__":
    main()
