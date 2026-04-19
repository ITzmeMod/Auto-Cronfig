"""
Auto global scan engine for Auto-Cronfig v3.
Searches GitHub code search for 50+ secret patterns across all public repos.
"""

import time
import sys
import logging
from typing import List, Optional, Callable, Dict, Any

logger = logging.getLogger(__name__)
from .scanner import RawFinding, _make_headers, _request_with_backoff, _scan_text_for_patterns

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# 50+ global search queries targeting known secret patterns
GLOBAL_SEARCH_QUERIES = [
    "AKIA language:python",
    "AKIA language:javascript",
    "AKIA language:yaml",
    "AKIA language:env",
    "sk_live_ language:python",
    "sk_live_ language:javascript",
    "sk_live_ language:ruby",
    "sk_test_ language:python",
    "ghp_ language:yaml",
    "ghp_ language:python",
    "glpat- language:yaml",
    "AIzaSy language:javascript",
    "AIzaSy language:python",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "mongodb+srv:// language:javascript",
    "mongodb+srv:// language:python",
    "postgres:// language:python",
    "postgres:// language:javascript",
    "sk-ant-api language:python",
    "sk-ant-api language:javascript",
    "hf_ language:python",
    "r8_ language:python",
    "SG. language:python",
    "SG. language:javascript",
    "xoxb- language:python",
    "xoxb- language:javascript",
    "xoxb- language:yaml",
    "xoxp- language:python",
    "EAAAl language:javascript",
    "EAAAl language:python",
    "shpat_ language:python",
    "shpat_ language:javascript",
    "sk_ language:python filename:.env",
    "API_KEY= filename:.env",
    "SECRET= filename:.env",
    "PASSWORD= filename:.env",
    "TOKEN= filename:.env",
    "dop_v1_ language:yaml",
    "dop_v1_ language:python",
    "vercel_token language:yaml",
    "GITHUB_TOKEN language:yaml",
    "whsec_ language:javascript",
    "hvs. language:python",
    "pul- language:python",
    "gsk_ language:python",
    "pplx- language:python",
    "r8_ language:javascript",
    "xkeysib- language:python",
    "SG. language:yaml filename:.env",
    "sk- language:python filename:openai",
    "sk_live_ filename:.env",
    "STRIPE_SECRET_KEY language:python",
    "STRIPE_SECRET_KEY language:javascript",
    "OPENAI_API_KEY language:python",
    "OPENAI_API_KEY filename:.env",
]


class GlobalScanner:
    def __init__(self, token: Optional[str] = None, workers: int = 4, memory=None):
        self.token = token
        self.workers = workers
        self.memory = memory
        self._headers = _make_headers(token)
        self._seen_keys: set = set()  # for deduplication across queries

    def search_github_code(
        self,
        query: str,
        max_results: int = 100,
        output_callback: Optional[Callable] = None,
    ) -> List[RawFinding]:
        """
        Use GitHub code search API to scan for a query.
        Respects 10 req/min rate limit with 6s sleep between calls.
        """
        findings: List[RawFinding] = []
        per_page = min(30, max_results)
        pages = (max_results + per_page - 1) // per_page
        fetched = 0

        for page in range(1, pages + 1):
            url = "https://api.github.com/search/code"
            resp = _request_with_backoff(
                "GET", url, self._headers,
                params={"q": query, "per_page": per_page, "page": page},
            )
            if resp is None:
                break
            if resp.status_code == 422:
                # Validation failed — query probably too short/broad
                break
            if resp.status_code == 403:
                # Rate limit hit — wait longer
                time.sleep(30)
                continue
            if resp.status_code != 200:
                break

            data = resp.json()
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                if fetched >= max_results:
                    break

                repo_full = item["repository"]["full_name"]
                file_path = item["path"]
                html_url = item.get("html_url", f"https://github.com/{repo_full}/blob/HEAD/{file_path}")
                owner, repo_name = repo_full.split("/", 1)

                # Fetch file content
                content_url = item.get("url", f"https://api.github.com/repos/{repo_full}/contents/{file_path}")
                content_resp = _request_with_backoff("GET", content_url, self._headers)
                if content_resp and content_resp.status_code == 200:
                    file_data = content_resp.json()
                    import base64 as b64
                    content_b64 = file_data.get("content", "")
                    if content_b64:
                        try:
                            content = b64.b64decode(content_b64).decode("utf-8", errors="replace")
                            hits = _scan_text_for_patterns(
                                content, repo_full, file_path, html_url,
                                memory=self.memory
                            )
                            for hit in hits:
                                # Global dedup
                                dedup_key = (hit.repo, hit.file_path, hit.pattern_name, hit.match_preview)
                                if dedup_key not in self._seen_keys:
                                    self._seen_keys.add(dedup_key)
                                    findings.append(hit)
                                    if output_callback:
                                        try:
                                            output_callback(hit)
                                        except Exception as exc:
                                            logger.debug("[global_scanner] callback error: %s", exc)
                        except Exception as exc:
                            logger.debug("[global_scanner] query item error: %s", exc)

                fetched += 1
                time.sleep(6)  # ~10 requests/min

            if fetched >= max_results:
                break

        return findings

    def run_all_queries(
        self,
        max_per_query: int = 30,
        output_callback: Optional[Callable] = None,
    ) -> List[RawFinding]:
        """
        Run all GLOBAL_SEARCH_QUERIES sequentially (rate limits require sequential).
        Deduplicates findings by (repo, file, pattern, preview).
        """
        all_findings: List[RawFinding] = []
        self._seen_keys = set()  # Reset dedup on each run

        queries = GLOBAL_SEARCH_QUERIES
        if HAS_TQDM:
            queries = tqdm(GLOBAL_SEARCH_QUERIES, desc="Global scan queries", unit="query")

        for query in queries:
            try:
                hits = self.search_github_code(
                    query,
                    max_results=max_per_query,
                    output_callback=output_callback,
                )
                all_findings.extend(hits)
            except KeyboardInterrupt:
                print("\n[!] Global scan interrupted by user")
                break
            except Exception as exc:
                logger.debug("[global_scanner] query failed: %s", exc)

        return all_findings

    def run_auto_scan(self, interval_seconds: int = 3600, output_path: Optional[str] = None):
        """
        Continuous scan mode — runs run_all_queries every interval_seconds.
        Loops forever until Ctrl+C.
        """
        import json
        import datetime

        scan_count = 0
        print(f"[*] Auto global scan started — interval: {interval_seconds}s")
        print("    Press Ctrl+C to stop\n")

        while True:
            scan_count += 1
            start = time.monotonic()
            print(f"[*] Starting global scan #{scan_count} at {datetime.datetime.utcnow().isoformat()}")

            findings = self.run_all_queries(max_per_query=30)

            duration = time.monotonic() - start
            print(f"[✓] Scan #{scan_count} complete: {len(findings)} findings in {duration:.1f}s")

            if output_path and findings:
                try:
                    existing = []
                    try:
                        with open(output_path, "r") as f:
                            existing = json.load(f)
                    except Exception as exc:
                        logger.debug("[global_scanner] load existing JSON error: %s", exc)
                    # Append new findings
                    for f in findings:
                        existing.append({
                            "repo": f.repo,
                            "file_path": f.file_path,
                            "pattern_name": f.pattern_name,
                            "match_preview": f.match_preview,
                            "severity": f.severity,
                            "url": f.url,
                            "scan_number": scan_count,
                        })
                    with open(output_path, "w") as fp:
                        json.dump(existing, fp, indent=2)
                    print(f"[✓] Results appended to {output_path}")
                except Exception as e:
                    print(f"[!] Could not save to {output_path}: {e}")

            # Countdown timer
            print(f"\n[*] Next scan in {interval_seconds}s... (Ctrl+C to stop)")
            try:
                for remaining in range(interval_seconds, 0, -1):
                    sys.stdout.write(f"\r    Waiting: {remaining:5d}s remaining   ")
                    sys.stdout.flush()
                    time.sleep(1)
                print("\r    Done waiting.                        ")
            except KeyboardInterrupt:
                print("\n[*] Auto scan stopped.")
                break

    def run_targeted_global(self, pattern_name: str, max_results: int = 100) -> List[RawFinding]:
        """
        Build a search query from the pattern name and search GitHub.
        """
        # Map pattern names to useful search terms
        query_map = {
            "aws access key": "AKIA",
            "aws secret": "aws_secret_access_key",
            "google api key": "AIzaSy",
            "stripe live key": "sk_live_",
            "stripe test key": "sk_test_",
            "github personal access token": "ghp_",
            "github oauth token": "gho_",
            "github fine-grained pat": "github_pat_",
            "gitlab personal access token": "glpat-",
            "openai api key": "sk-",
            "anthropic api key": "sk-ant-",
            "huggingface token": "hf_",
            "rsa private key": "-----BEGIN RSA PRIVATE KEY-----",
            "openssh private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "slack bot token": "xoxb-",
            "sendgrid api key": "SG.",
            "discord bot token": "discord_token",
        }

        # Try exact match first, then fuzzy
        name_lower = pattern_name.lower()
        query_term = query_map.get(name_lower)

        if not query_term:
            # Extract key terms from the pattern name
            words = name_lower.split()
            query_term = " ".join(w for w in words if len(w) > 3)

        if not query_term:
            query_term = pattern_name

        return self.search_github_code(query_term, max_results=max_results)
