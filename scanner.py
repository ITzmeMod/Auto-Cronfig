#!/usr/bin/env python3
"""
Auto-Cronfig — GitHub Secret & Vulnerability Scanner
Open Source | MIT License
https://github.com/ITzmeMod/Auto-Cronfig
"""

import re
import sys
import json
import base64
import argparse
import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

try:
    import requests
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

# ─────────────────────────────────────────────
# DETECTION PATTERNS
# ─────────────────────────────────────────────

PATTERNS = {
    "AWS Access Key": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}['\":]?\s*([0-9a-zA-Z/+]{40})",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth Token": r"ya29\.[0-9A-Za-z\\-_]+",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "Twilio Account SID": r"AC[a-zA-Z0-9]{32}",
    "Twilio Auth Token": r"(?i)twilio.{0,20}['\"]([a-f0-9]{32})['\"]",
    "Slack Bot Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
    "GitHub Actions": r"ghs_[0-9a-zA-Z]{36}",
    "Private Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----",
    "Private Key (Generic)": r"-----BEGIN (?:EC|PGP|OPENSSH) PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Generic Password": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    "Generic Secret": r"(?i)(?:secret|api_secret|client_secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    "Generic API Key": r"(?i)(?:api_key|apikey|access_key)\s*[=:]\s*['\"]([^'\"]{16,})['\"]",
    "DB Connection String": r"(?i)(?:mongodb|postgres|mysql|mssql):\/\/[^\s'\"]+:[^\s'\"]+@",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Heroku API Key": r"(?i)heroku.{0,20}['\"]([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})['\"]",
    "Shopify Token": r"shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}",
    "Telegram Bot Token": r"\d{9,10}:[A-Za-z0-9_-]{35}",
}

# Risky filenames to flag
RISKY_FILENAMES = [
    r"\.env$", r"\.env\.", r"config\.json$", r"secrets\.json$",
    r"credentials\.json$", r"\.pem$", r"\.key$", r"id_rsa$",
    r"\.p12$", r"\.pfx$", r"\.sqlite$", r"\.db$",
    r"wp-config\.php$", r"settings\.py$", r"database\.yml$",
]


# ─────────────────────────────────────────────
# GITHUB API HELPERS
# ─────────────────────────────────────────────

class GitHubScanner:
    BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.findings: List[Dict] = []
        self.stats = {"repos_scanned": 0, "files_scanned": 0, "findings": 0}

    def _get(self, url: str, params: dict = None) -> Optional[dict]:
        try:
            r = self.session.get(url, params=params, timeout=15)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(f"{Fore.YELLOW}⚠ Rate limited or forbidden: {url}")
            elif e.response.status_code == 404:
                pass  # silently skip 404s
            else:
                print(f"{Fore.RED}✗ HTTP error {e.response.status_code}: {url}")
            return None
        except Exception as e:
            print(f"{Fore.RED}✗ Request error: {e}")
            return None

    def get_repos(self, username: str) -> List[Dict]:
        repos = []
        page = 1
        while True:
            data = self._get(f"{self.BASE}/users/{username}/repos",
                             params={"per_page": 100, "page": page, "type": "public"})
            if not data:
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        return repos

    def get_tree(self, owner: str, repo: str, branch: str = "HEAD") -> List[Dict]:
        data = self._get(f"{self.BASE}/repos/{owner}/{repo}/git/trees/{branch}",
                         params={"recursive": "1"})
        if data and "tree" in data:
            return data["tree"]
        return []

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        data = self._get(f"{self.BASE}/repos/{owner}/{repo}/contents/{path}")
        if data and isinstance(data, dict) and data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def get_default_branch(self, owner: str, repo: str) -> str:
        data = self._get(f"{self.BASE}/repos/{owner}/{repo}")
        if data:
            return data.get("default_branch", "main")
        return "main"

    # ─── Core Scan Logic ───────────────────────

    def scan_content(self, content: str, context: str) -> List[Dict]:
        hits = []
        for pattern_name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                # Deduplicate
                unique = list(set(m if isinstance(m, str) else m[0] for m in matches))
                for match in unique:
                    # Redact middle of secret for safe display
                    display = match[:6] + "****" + match[-4:] if len(match) > 12 else "****"
                    hits.append({
                        "type": pattern_name,
                        "match_preview": display,
                        "context": context,
                    })
        return hits

    def scan_filename(self, path: str, context: str) -> List[Dict]:
        hits = []
        for pattern in RISKY_FILENAMES:
            if re.search(pattern, path, re.IGNORECASE):
                hits.append({
                    "type": "Risky Filename",
                    "match_preview": path,
                    "context": context,
                })
                break
        return hits

    def scan_repo(self, owner: str, repo_name: str) -> None:
        print(f"\n{Fore.CYAN}📦 Scanning repo: {owner}/{repo_name}")
        branch = self.get_default_branch(owner, repo_name)
        tree = self.get_tree(owner, repo_name, branch)
        if not tree:
            print(f"  {Fore.YELLOW}⚠ Could not fetch file tree")
            return

        self.stats["repos_scanned"] += 1
        skippable_exts = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                          ".woff", ".woff2", ".ttf", ".eot", ".zip", ".gz",
                          ".tar", ".mp4", ".mp3", ".pdf", ".lock", ".min.js"}

        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")

            # Flag risky filenames
            fn_hits = self.scan_filename(
                path, f"https://github.com/{owner}/{repo_name}/blob/{branch}/{path}")
            if fn_hits:
                for hit in fn_hits:
                    self._record_finding(owner, repo_name, path, hit)

            # Skip binary/large files
            ext = "." + path.split(".")[-1] if "." in path else ""
            if ext.lower() in skippable_exts:
                continue
            size = item.get("size", 0)
            if size > 500_000:  # skip files > 500KB
                continue

            content = self.get_file_content(owner, repo_name, path)
            if not content:
                continue

            self.stats["files_scanned"] += 1
            hits = self.scan_content(
                content, f"https://github.com/{owner}/{repo_name}/blob/{branch}/{path}")
            for hit in hits:
                self._record_finding(owner, repo_name, path, hit)

        print(f"  {Fore.GREEN}✓ Done — {self.stats['findings']} finding(s) so far")

    def _record_finding(self, owner: str, repo: str, path: str, hit: Dict) -> None:
        finding = {
            "repo": f"{owner}/{repo}",
            "file": path,
            "type": hit["type"],
            "preview": hit["match_preview"],
            "url": hit["context"],
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        self.findings.append(finding)
        self.stats["findings"] += 1
        severity = self._severity(hit["type"])
        color = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.LIGHTRED_EX,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.CYAN,
        }.get(severity, Fore.WHITE)
        print(f"  {color}[{severity}] {hit['type']}: {hit['match_preview']}")
        print(f"           └── {path}")

    @staticmethod
    def _severity(finding_type: str) -> str:
        critical = {"AWS Secret Key", "Private Key (RSA)", "Private Key (Generic)",
                    "Stripe Live Key", "GitHub Token", "GitHub OAuth", "GitHub Actions"}
        high = {"AWS Access Key", "Google API Key", "Stripe Test Key",
                "SendGrid API Key", "DB Connection String", "Telegram Bot Token",
                "Discord Bot Token", "Heroku API Key", "Shopify Token"}
        medium = {"Slack Bot Token", "Slack Webhook", "Discord Webhook",
                  "Twilio Account SID", "Twilio Auth Token", "JWT Token",
                  "Google OAuth Token", "Firebase URL"}
        if finding_type in critical:
            return "CRITICAL"
        if finding_type in high:
            return "HIGH"
        if finding_type in medium:
            return "MEDIUM"
        return "LOW"

    # ─── Report ────────────────────────────────

    def print_summary(self) -> None:
        print(f"\n{'─'*60}")
        print(f"{Fore.CYAN}📊 SCAN SUMMARY")
        print(f"{'─'*60}")
        print(f"  Repos scanned : {self.stats['repos_scanned']}")
        print(f"  Files scanned : {self.stats['files_scanned']}")
        print(f"  Total findings: {Fore.RED if self.stats['findings'] else Fore.GREEN}{self.stats['findings']}{Style.RESET_ALL}")
        if self.findings:
            from collections import Counter
            by_type = Counter(f["type"] for f in self.findings)
            print(f"\n{Fore.YELLOW}  Breakdown by type:")
            for t, c in by_type.most_common():
                print(f"    {c:3}x  {t}")
        print(f"{'─'*60}\n")

    def export_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump({
                "meta": {
                    "tool": "Auto-Cronfig",
                    "version": "1.0.0",
                    "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
                },
                "stats": self.stats,
                "findings": self.findings,
            }, f, indent=2)
        print(f"{Fore.GREEN}✅ Report saved to: {path}")


# ─────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────

def parse_repo_url(url: str):
    """Extract owner/repo from a GitHub URL or 'owner/repo' string."""
    url = url.rstrip("/")
    if url.startswith("https://github.com/"):
        parts = urlparse(url).path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    elif "/" in url:
        parts = url.split("/")
        return parts[0], parts[1]
    return None, None


def main():
    parser = argparse.ArgumentParser(
        description="🔍 Auto-Cronfig — GitHub Secret & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --repo https://github.com/owner/repo
  python scanner.py --user someusername
  python scanner.py --user someusername --token ghp_xxx --output report.json
        """,
    )
    parser.add_argument("--repo", help="GitHub repo URL or owner/repo")
    parser.add_argument("--user", help="GitHub username (scans all public repos)")
    parser.add_argument("--token", help="GitHub personal access token (optional, increases rate limits)")
    parser.add_argument("--output", help="Export findings to JSON file")
    parser.add_argument("--version", action="version", version="Auto-Cronfig v1.0.0")

    args = parser.parse_args()

    if not args.repo and not args.user:
        parser.print_help()
        sys.exit(1)

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║  🔍 Auto-Cronfig — GitHub Secret Scanner ║
║  v1.0.0 | MIT License | Open Source      ║
╚══════════════════════════════════════════╝{Style.RESET_ALL}
""")

    scanner = GitHubScanner(token=args.token)

    if args.repo:
        owner, repo = parse_repo_url(args.repo)
        if not owner:
            print(f"{Fore.RED}✗ Invalid repo format. Use: owner/repo or full GitHub URL")
            sys.exit(1)
        scanner.scan_repo(owner, repo)

    elif args.user:
        print(f"{Fore.CYAN}👤 Fetching repos for user: {args.user}")
        repos = scanner.get_repos(args.user)
        if not repos:
            print(f"{Fore.RED}✗ No public repos found or user does not exist.")
            sys.exit(1)
        print(f"  Found {len(repos)} public repo(s)\n")
        for repo in repos:
            scanner.scan_repo(args.user, repo["name"])

    scanner.print_summary()

    if args.output:
        scanner.export_json(args.output)


if __name__ == "__main__":
    main()
