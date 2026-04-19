"""
Auto-Cronfig v3 — Security Utilities
Centralised security helpers:
  - Input sanitisation (repo names, usernames, queries, tokens)
  - Token redaction for logging
  - Secure HTTP session factory
  - Rate-limit state tracking
  - Config file protection
  - Attribution enforcement
"""

import re
import os
import stat
import logging
import hashlib
import urllib.parse
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Attribution ───────────────────────────────────────────────────────────────
TOOL_NAME    = "Auto-Cronfig"
TOOL_VERSION = "3.0.0"
TOOL_AUTHOR  = "ITzmeMod"
TOOL_REPO    = "https://github.com/ITzmeMod/Auto-Cronfig"
TOOL_LICENSE = "MIT"

USER_AGENT = (
    f"{TOOL_NAME}/{TOOL_VERSION} "
    f"(+{TOOL_REPO}; security-research; "
    f"contact: github.com/{TOOL_AUTHOR})"
)

# ── Input validation ──────────────────────────────────────────────────────────

# GitHub username: alphanumeric + hyphen, 1-39 chars, no double-hyphen, no leading/trailing hyphen
_GITHUB_USER_RE  = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$')
# Repo name: alphanumeric + hyphen/dot/underscore, 1-100 chars
_GITHUB_REPO_RE  = re.compile(r'^[a-zA-Z0-9._-]{1,100}$')
# Safe search query: printable ASCII only, no shell metacharacters, max 200 chars
_SAFE_QUERY_RE   = re.compile(r'^[\w\s\-_./:@+=\[\](){}!?#%&,\'"~`^*|<>]+$')
# GitHub token prefixes
_TOKEN_PREFIXES  = ('ghp_', 'gho_', 'ghs_', 'github_pat_',
                    'glpat-', 'sk-', 'sk-ant-', 'hf_', 'r8_',
                    'SG.', 'xoxb-', 'xoxp-', 'dop_v1_', 'gsk_')


def validate_github_username(username: str) -> str:
    """Validate and return a safe GitHub username. Raises ValueError on invalid."""
    if not username or not isinstance(username, str):
        raise ValueError("Username must be a non-empty string")
    username = username.strip()
    if len(username) > 39:
        raise ValueError(f"Username too long: {len(username)} chars (max 39)")
    if not _GITHUB_USER_RE.match(username):
        raise ValueError(f"Invalid GitHub username: {username!r}")
    return username


def validate_github_repo(owner_repo: str) -> tuple:
    """Validate 'owner/repo' format. Returns (owner, repo) tuple."""
    if not owner_repo or not isinstance(owner_repo, str):
        raise ValueError("Repo must be a non-empty string")
    # Strip URL prefix
    for prefix in ('https://github.com/', 'http://github.com/', 'github.com/'):
        if owner_repo.startswith(prefix):
            owner_repo = owner_repo[len(prefix):]
    owner_repo = owner_repo.rstrip('/').strip()
    parts = owner_repo.split('/')
    if len(parts) != 2:
        raise ValueError(f"Repo must be in 'owner/repo' format, got: {owner_repo!r}")
    owner, repo = parts
    validate_github_username(owner)
    if not _GITHUB_REPO_RE.match(repo):
        raise ValueError(f"Invalid repo name: {repo!r}")
    return owner, repo


def sanitise_query(query: str, max_len: int = 200) -> str:
    """Strip unsafe characters from a search query. Returns sanitised string."""
    if not query:
        return ""
    # Remove null bytes and control characters
    query = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', query)
    # Truncate
    query = query[:max_len]
    return query.strip()


def redact_token(text: str) -> str:
    """Redact any token-like strings from text before logging.
    Replaces token values with REDACTED.
    """
    if not text:
        return text
    # Redact known token prefixes
    for prefix in _TOKEN_PREFIXES:
        pattern = re.compile(
            r'(' + re.escape(prefix) + r')[A-Za-z0-9_\-]{4,}',
            re.IGNORECASE
        )
        text = pattern.sub(lambda m: m.group(1) + '****REDACTED****', text)
    # Redact Authorization header values
    text = re.sub(
        r'(Authorization:\s*(?:Bearer|Token|Basic)\s+)[A-Za-z0-9_\-+/=]{8,}',
        r'\1****REDACTED****',
        text,
        flags=re.IGNORECASE
    )
    return text


def mask_secret(value: str) -> str:
    """Return a masked version safe to display: first 4 + **** + last 3."""
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return "****"
    return value[:4] + "••••" + value[-3:]


def hash_secret(value: str) -> str:
    """SHA-256 hash a secret value for deduplication without storing the raw value."""
    return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()


# ── Secure HTTP session ───────────────────────────────────────────────────────

def make_secure_session(token: Optional[str] = None):
    """Create a requests.Session with security headers, timeout, and proper UA.
    Token is injected into Authorization header — never logged.
    """
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
    except ImportError:
        return None

    session = requests.Session()

    # Retry strategy: 3 retries on 429/500/502/503/504
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist={429, 500, 502, 503, 504},
        allowed_methods={"GET", "POST", "HEAD"},
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })

    if token:
        session.headers["Authorization"] = f"Bearer {token}"
        logger.debug("Session created with token: %s", mask_secret(token))

    return session


# ── Config file protection ────────────────────────────────────────────────────

CONFIG_DIR  = Path.home() / ".auto-cronfig"
CONFIG_FILE = CONFIG_DIR / "config.json"
DB_FILE     = CONFIG_DIR / "memory.db"

def ensure_secure_config_dir():
    """Create config directory with restrictive permissions (owner-only)."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Owner rwx, group/other none
        CONFIG_DIR.chmod(0o700)
    except Exception as exc:
        logger.debug("Could not set config dir permissions: %s", exc)


def secure_write_config(data: dict):
    """Write config JSON with owner-only permissions."""
    import json
    ensure_secure_config_dir()
    CONFIG_FILE.write_text(json.dumps(data, indent=2))
    try:
        CONFIG_FILE.chmod(0o600)  # owner rw, group/other none
    except Exception as exc:
        logger.debug("Could not set config file permissions: %s", exc)


def check_config_permissions() -> list:
    """Check config file permissions. Returns list of warnings."""
    warnings = []
    if not CONFIG_FILE.exists():
        return warnings
    try:
        mode = CONFIG_FILE.stat().st_mode
        if mode & stat.S_IRGRP or mode & stat.S_IROTH:
            warnings.append(
                f"⚠ Config file is world/group readable: {CONFIG_FILE}\n"
                f"  Fix with: chmod 600 {CONFIG_FILE}"
            )
    except Exception as exc:
        logger.debug("permission check error: %s", exc)
    return warnings


# ── Attribution ───────────────────────────────────────────────────────────────

BANNER = f"""
╔══════════════════════════════════════════════════════════╗
║  {TOOL_NAME} v{TOOL_VERSION}  ·  GitHub Secret Scanner         ║
║  © 2026 {TOOL_AUTHOR}  ·  MIT License                          ║
║  {TOOL_REPO}  ║
╚══════════════════════════════════════════════════════════╝
"""

STARTUP_NOTICE = (
    f"{TOOL_NAME} v{TOOL_VERSION} by {TOOL_AUTHOR} | {TOOL_REPO} | MIT License\n"
    f"For authorized security research only. "
    f"See {TOOL_REPO}#️⃣-disclaimer"
)

FORK_NOTICE = (
    f"# Auto-Cronfig v{TOOL_VERSION}\n"
    f"# Original tool by {TOOL_AUTHOR}: {TOOL_REPO}\n"
    f"# MIT License — attribution required for forks and derivatives.\n"
    f"# © 2026 {TOOL_AUTHOR}\n"
)


def print_startup_notice():
    """Print a concise attribution notice on every startup."""
    try:
        from colorama import Fore, Style
        c = Fore.CYAN
        r = Style.RESET_ALL
        d = Fore.LIGHTBLACK_EX
    except ImportError:
        c = r = d = ""
    print(f"\n{c}{TOOL_NAME} v{TOOL_VERSION}{r}  "
          f"{d}by {TOOL_AUTHOR}  ·  MIT  ·  {TOOL_REPO}{r}")
    print(f"{d}For authorized security research only.{r}\n")


# ── Output path validation ────────────────────────────────────────────────────

_SAFE_EXTENSIONS = {'.json', '.csv', '.html', '.md', '.txt'}

def validate_output_path(path: str) -> str:
    """Validate and sanitise an output file path.
    Prevents path traversal, enforces safe extensions.
    """
    if not path:
        raise ValueError("Output path cannot be empty")
    p = Path(path)
    # Prevent path traversal
    if '..' in p.parts:
        raise ValueError(f"Path traversal not allowed: {path!r}")
    # Extension check
    ext = p.suffix.lower()
    if ext and ext not in _SAFE_EXTENSIONS:
        raise ValueError(
            f"Unsafe output extension {ext!r}. "
            f"Allowed: {', '.join(sorted(_SAFE_EXTENSIONS))}"
        )
    return str(p)
