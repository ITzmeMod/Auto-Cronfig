"""
Concurrent GitHub repo scanner for Auto-Cronfig v3.
Enhanced with false-positive checking, RISKY_CONTENT_SIGNALS pre-filter,
tqdm progress for scan_user, and proper global_search rate limiting.
"""

import re
import time
import base64
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from .patterns import PATTERNS, RISKY_FILENAMES, RISKY_CONTENT_SIGNALS

# File extensions to always skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".pyd", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".lock", ".sum",
}

SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "composer.lock",
    "Gemfile.lock",
    "poetry.lock",
    "Pipfile.lock",
    "cargo.lock",
    "go.sum",
}

MAX_FILE_BYTES = 500 * 1024  # 500 KB


@dataclass
class RawFinding:
    repo: str
    file_path: str
    pattern_name: str
    match: str
    match_preview: str
    severity: str
    url: str
    line_number: int = 0


def _make_headers(token: Optional[str]) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Auto-Cronfig/3.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _request_with_backoff(
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict] = None,
    max_retries: int = 3,
) -> Optional[requests.Response]:
    """Make an HTTP request with exponential backoff on 403/429."""
    for attempt in range(max_retries):
        try:
            resp = requests.request(
                method, url, headers=headers, params=params, timeout=15
            )
            if resp.status_code in (403, 429):
                wait = (2 ** attempt) * 2
                time.sleep(wait)
                continue
            return resp
        except requests.exceptions.RequestException:
            time.sleep(2 ** attempt)
    return None


def _has_content_signal(content: str) -> bool:
    """Fast pre-filter: check for any RISKY_CONTENT_SIGNALS before regex scanning."""
    lower = content.lower()
    return any(s.lower() in lower for s in RISKY_CONTENT_SIGNALS)


def _scan_text_for_patterns(
    text: str,
    repo: str,
    file_path: str,
    url: str,
    memory=None,
) -> List[RawFinding]:
    """Scan raw text content for all registered patterns."""
    # Fast pre-filter
    if not _has_content_signal(text):
        return []

    findings: List[RawFinding] = []
    lines = text.splitlines()

    for pattern_name, meta in PATTERNS.items():
        regex = meta["regex"]
        severity = meta["severity"]
        try:
            compiled = re.compile(regex)
        except re.error:
            continue

        for line_no, line in enumerate(lines, start=1):
            for m in compiled.finditer(line):
                raw_match = m.group(0)
                try:
                    raw_match = m.group(1)
                except IndexError:
                    pass

                # Check false positives
                if memory and memory.is_false_positive(raw_match, pattern_name):
                    continue

                preview = raw_match[:80] + ("..." if len(raw_match) > 80 else "")
                findings.append(
                    RawFinding(
                        repo=repo,
                        file_path=file_path,
                        pattern_name=pattern_name,
                        match=raw_match,
                        match_preview=preview,
                        severity=severity,
                        url=url,
                        line_number=line_no,
                    )
                )
    return findings


def _should_skip_file(filename: str, size: int) -> bool:
    if size > MAX_FILE_BYTES:
        return True
    lower = filename.lower()
    if any(lower.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True
    base = lower.split("/")[-1] if "/" in lower else lower
    if base in SKIP_FILENAMES:
        return True
    return False


def _get_file_extension(path: str) -> str:
    parts = path.rsplit(".", 1)
    if len(parts) == 2:
        return "." + parts[1].lower()
    return ""


class RepoScanner:
    def __init__(self, token: Optional[str] = None, workers: int = 8, memory=None):
        self.token = token
        self.workers = workers
        self.memory = memory
        self._lock = threading.Lock()
        self._headers = _make_headers(token)

    def _fetch_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        resp = _request_with_backoff("GET", url, self._headers)
        if resp is None or resp.status_code != 200:
            return None
        data = resp.json()
        content_b64 = data.get("content", "")
        if not content_b64:
            return None
        try:
            return base64.b64decode(content_b64).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _fetch_file_tree(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Get the full recursive file tree for a repo."""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD"
        resp = _request_with_backoff("GET", url, self._headers, params={"recursive": "1"})
        if resp is None or resp.status_code != 200:
            return []
        data = resp.json()
        return [item for item in data.get("tree", []) if item.get("type") == "blob"]

    def scan_repo(self, owner: str, repo_name: str) -> List[RawFinding]:
        """Scan a single repo concurrently. Returns all raw findings."""
        all_findings: List[RawFinding] = []
        tree = self._fetch_file_tree(owner, repo_name)

        if not tree:
            return all_findings

        # Separate risky files (prioritize them)
        risky_exts = set(self.memory.get_risky_extensions()) if self.memory else set()
        risky_basenames = {fn.lstrip(".").lower() for fn in RISKY_FILENAMES}

        def is_priority(item):
            path = item["path"]
            base = path.split("/")[-1].lower()
            ext = _get_file_extension(path)
            return (
                ext in risky_exts
                or base in risky_basenames
                or any(base.endswith(rf.lstrip(".").lower()) for rf in RISKY_FILENAMES)
            )

        priority = [f for f in tree if is_priority(f)]
        rest = [f for f in tree if not is_priority(f)]
        ordered = priority + rest

        def scan_file(item) -> List[RawFinding]:
            path = item["path"]
            size = item.get("size", 0)
            if _should_skip_file(path, size):
                return []
            content = self._fetch_file_content(owner, repo_name, path)
            if content is None:
                return []
            ext = _get_file_extension(path)
            url = f"https://github.com/{owner}/{repo_name}/blob/HEAD/{path}"
            local_findings = _scan_text_for_patterns(
                content, f"{owner}/{repo_name}", path, url, memory=self.memory
            )
            if self.memory:
                self.memory.update_file_stats(ext, had_finding=len(local_findings) > 0)
            return local_findings

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(scan_file, item): item for item in ordered}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    with self._lock:
                        all_findings.extend(result)
                except Exception:
                    pass

        return all_findings

    def scan_user(self, username: str) -> List[RawFinding]:
        """Scan all public repos for a user, with tqdm progress."""
        all_findings: List[RawFinding] = []
        page = 1
        repos = []
        while True:
            url = f"https://api.github.com/users/{username}/repos"
            resp = _request_with_backoff(
                "GET", url, self._headers, params={"per_page": 100, "page": page}
            )
            if resp is None or resp.status_code != 200:
                break
            batch = resp.json()
            if not batch:
                break
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1

        desc = f"Scanning repos for {username}"
        if HAS_TQDM:
            repo_iter = tqdm(repos, desc=desc, unit="repo")
        else:
            repo_iter = repos

        for repo in repo_iter:
            owner = repo["owner"]["login"]
            repo_name = repo["name"]
            findings = self.scan_repo(owner, repo_name)
            all_findings.extend(findings)

        return all_findings

    def global_search(self, query_term: str, max_results: int = 100) -> List[RawFinding]:
        """
        Use GitHub code search API to find files containing query_term,
        then scan those files for secrets.
        Handles the 10 req/min rate limit with sleep(6) between calls.
        """
        all_findings: List[RawFinding] = []
        per_page = 30
        pages = (max_results + per_page - 1) // per_page
        fetched = 0

        for page in range(1, pages + 1):
            url = "https://api.github.com/search/code"
            resp = _request_with_backoff(
                "GET",
                url,
                self._headers,
                params={"q": query_term, "per_page": per_page, "page": page},
            )
            if resp is None:
                break
            if resp.status_code == 422:
                break
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
                owner, repo_name = repo_full.split("/", 1)

                content = self._fetch_file_content(owner, repo_name, file_path)
                if content:
                    gh_url = item.get("html_url", f"https://github.com/{repo_full}/blob/HEAD/{file_path}")
                    findings = _scan_text_for_patterns(
                        content, repo_full, file_path, gh_url, memory=self.memory
                    )
                    all_findings.extend(findings)
                fetched += 1
                time.sleep(6)  # Respect 10 req/min rate limit

            if fetched >= max_results:
                break

        return all_findings
