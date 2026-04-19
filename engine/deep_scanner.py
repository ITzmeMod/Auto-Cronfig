"""
Deep scan engine for Auto-Cronfig v3.
Scans commit history, pull requests, issues, gists, wiki, and releases
to catch secrets that may have been added and removed.
"""

import time
import base64
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .scanner import RawFinding, _make_headers, _request_with_backoff, _scan_text_for_patterns

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


class DeepScanner:
    def __init__(self, token: Optional[str] = None, workers: int = 8, memory=None):
        self.token = token
        self.workers = workers
        self.memory = memory
        self._headers = _make_headers(token)

    def _paginate(self, url: str, params: Optional[Dict] = None, max_items: int = 500) -> List[Dict]:
        """Paginate a GitHub API endpoint, returning up to max_items items."""
        results = []
        page = 1
        per_page = min(100, max_items)
        base_params = dict(params or {})

        while len(results) < max_items:
            p = {**base_params, "per_page": per_page, "page": page}
            resp = _request_with_backoff("GET", url, self._headers, params=p)
            if resp is None or resp.status_code != 200:
                break
            batch = resp.json()
            if not batch:
                break
            results.extend(batch)
            if len(batch) < per_page:
                break
            page += 1

        return results[:max_items]

    def scan_commit_history(self, owner: str, repo: str, max_commits: int = 500) -> List[RawFinding]:
        """
        Scan commit diffs (patches) for secrets.
        This catches secrets that were added then removed.
        """
        findings: List[RawFinding] = []
        url = f"https://api.github.com/repos/{owner}/{repo}/commits"
        commits = self._paginate(url, max_items=max_commits)

        def process_commit(commit_summary: Dict) -> List[RawFinding]:
            sha = commit_summary["sha"]
            detail_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
            resp = _request_with_backoff("GET", detail_url, self._headers)
            if resp is None or resp.status_code != 200:
                return []
            data = resp.json()
            local: List[RawFinding] = []
            for file_info in data.get("files", []):
                patch = file_info.get("patch", "")
                if not patch:
                    continue
                filename = file_info.get("filename", "")
                file_url = f"https://github.com/{owner}/{repo}/commit/{sha}#{filename}"
                hits = _scan_text_for_patterns(
                    patch, f"{owner}/{repo}", f"{filename} (commit {sha[:7]})", file_url,
                    memory=self.memory
                )
                local.extend(hits)
            return local

        desc = f"Scanning commit history: {owner}/{repo}"
        it = tqdm(commits, desc=desc, unit="commit", leave=False) if HAS_TQDM else commits

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(process_commit, c): c for c in it}
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception:
                    pass

        return findings

    def scan_pull_requests(self, owner: str, repo: str, state: str = "all", max_prs: int = 100) -> List[RawFinding]:
        """
        Scan PR bodies, comments, and diffs for secrets.
        """
        findings: List[RawFinding] = []
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        prs = self._paginate(url, params={"state": state}, max_items=max_prs)

        for pr in prs:
            pr_number = pr["number"]
            pr_url = pr.get("html_url", f"https://github.com/{owner}/{repo}/pull/{pr_number}")

            # Scan PR body
            body = pr.get("body") or ""
            if body:
                hits = _scan_text_for_patterns(
                    body, f"{owner}/{repo}", f"PR #{pr_number} description", pr_url,
                    memory=self.memory
                )
                findings.extend(hits)

            # Scan PR comments
            comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
            comments = self._paginate(comments_url, max_items=50)
            for comment in comments:
                comment_body = comment.get("body") or ""
                if comment_body:
                    hits = _scan_text_for_patterns(
                        comment_body, f"{owner}/{repo}",
                        f"PR #{pr_number} comment", pr_url,
                        memory=self.memory
                    )
                    findings.extend(hits)

            # Fetch and scan PR diff
            diff_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
            pr_files = self._paginate(diff_url, max_items=50)
            for file_info in pr_files:
                patch = file_info.get("patch", "")
                if patch:
                    filename = file_info.get("filename", "")
                    hits = _scan_text_for_patterns(
                        patch, f"{owner}/{repo}",
                        f"{filename} (PR #{pr_number})", pr_url,
                        memory=self.memory
                    )
                    findings.extend(hits)

            time.sleep(0.1)  # Light rate limiting

        return findings

    def scan_issues(self, owner: str, repo: str, max_issues: int = 200) -> List[RawFinding]:
        """
        Scan issue bodies and comments for secrets.
        """
        findings: List[RawFinding] = []
        url = f"https://api.github.com/repos/{owner}/{repo}/issues"
        issues = self._paginate(url, params={"state": "all"}, max_items=max_issues)

        for issue in issues:
            # Skip PRs (they appear in issues endpoint too)
            if "pull_request" in issue:
                continue

            issue_number = issue["number"]
            issue_url = issue.get("html_url", f"https://github.com/{owner}/{repo}/issues/{issue_number}")

            # Scan issue body
            body = issue.get("body") or ""
            if body:
                hits = _scan_text_for_patterns(
                    body, f"{owner}/{repo}",
                    f"Issue #{issue_number} body", issue_url,
                    memory=self.memory
                )
                findings.extend(hits)

            # Scan issue comments
            comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
            comments = self._paginate(comments_url, max_items=30)
            for comment in comments:
                comment_body = comment.get("body") or ""
                if comment_body:
                    hits = _scan_text_for_patterns(
                        comment_body, f"{owner}/{repo}",
                        f"Issue #{issue_number} comment", issue_url,
                        memory=self.memory
                    )
                    findings.extend(hits)

            time.sleep(0.05)  # Light rate limiting

        return findings

    def scan_gists(self, username: str) -> List[RawFinding]:
        """
        Scan all public gists for a user.
        """
        findings: List[RawFinding] = []
        url = f"https://api.github.com/users/{username}/gists"
        gists = self._paginate(url, max_items=100)

        for gist in gists:
            gist_id = gist["id"]
            gist_url = gist.get("html_url", f"https://gist.github.com/{gist_id}")

            # Fetch full gist content
            detail_url = f"https://api.github.com/gists/{gist_id}"
            resp = _request_with_backoff("GET", detail_url, self._headers)
            if resp is None or resp.status_code != 200:
                continue

            data = resp.json()
            for filename, file_info in data.get("files", {}).items():
                content = file_info.get("content") or ""
                if not content:
                    raw_url = file_info.get("raw_url", "")
                    if raw_url:
                        try:
                            r = requests.get(raw_url, timeout=10)
                            if r.status_code == 200:
                                content = r.text
                        except Exception:
                            pass

                if content:
                    hits = _scan_text_for_patterns(
                        content, f"gist:{username}",
                        filename, gist_url,
                        memory=self.memory
                    )
                    findings.extend(hits)

        return findings

    def scan_wiki(self, owner: str, repo: str) -> List[RawFinding]:
        """
        Attempt to scan wiki pages via GitHub API.
        Falls back gracefully if wiki is disabled.
        """
        findings: List[RawFinding] = []

        # Try to fetch wiki content via search in the wiki
        # GitHub doesn't have a direct wiki API for content, so we search
        # the main repo for any wiki-like paths
        search_url = "https://api.github.com/search/code"
        resp = _request_with_backoff(
            "GET", search_url, self._headers,
            params={"q": f"repo:{owner}/{repo} extension:md", "per_page": 30}
        )
        if resp is None or resp.status_code != 200:
            return findings

        data = resp.json()
        for item in data.get("items", []):
            file_path = item.get("path", "")
            if not file_path.lower().endswith(".md"):
                continue
            html_url = item.get("html_url", "")
            # Fetch raw content
            raw_url = item.get("url", "")
            if not raw_url:
                continue
            resp2 = _request_with_backoff("GET", raw_url, self._headers)
            if resp2 is None or resp2.status_code != 200:
                continue
            file_data = resp2.json()
            content_b64 = file_data.get("content", "")
            if content_b64:
                try:
                    content = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                    hits = _scan_text_for_patterns(
                        content, f"{owner}/{repo}",
                        file_path, html_url,
                        memory=self.memory
                    )
                    findings.extend(hits)
                except Exception:
                    pass

        return findings

    def scan_releases(self, owner: str, repo: str) -> List[RawFinding]:
        """
        Scan release descriptions and tag names for secrets.
        """
        findings: List[RawFinding] = []
        url = f"https://api.github.com/repos/{owner}/{repo}/releases"
        releases = self._paginate(url, max_items=50)

        for release in releases:
            release_url = release.get("html_url", f"https://github.com/{owner}/{repo}/releases")
            release_id = release.get("tag_name", str(release.get("id", "")))

            body = release.get("body") or ""
            if body:
                hits = _scan_text_for_patterns(
                    body, f"{owner}/{repo}",
                    f"Release {release_id}", release_url,
                    memory=self.memory
                )
                findings.extend(hits)

        return findings

    def full_deep_scan(self, owner: str, repo: str) -> List[RawFinding]:
        """
        Run all deep scan methods concurrently.
        Returns combined deduplicated findings.
        """
        all_findings: List[RawFinding] = []
        tasks = [
            ("commit_history", lambda: self.scan_commit_history(owner, repo)),
            ("pull_requests", lambda: self.scan_pull_requests(owner, repo)),
            ("issues", lambda: self.scan_issues(owner, repo)),
            ("releases", lambda: self.scan_releases(owner, repo)),
        ]

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(fn): name for name, fn in tasks}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results = future.result()
                    all_findings.extend(results)
                except Exception as e:
                    pass  # Continue even if one scan method fails

        # Deduplicate by (file_path, pattern_name, match_preview)
        seen = set()
        unique: List[RawFinding] = []
        for f in all_findings:
            key = (f.file_path, f.pattern_name, f.match_preview)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
