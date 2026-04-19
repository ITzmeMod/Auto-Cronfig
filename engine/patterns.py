"""
Pattern registry for Auto-Cronfig v3.
Loads 200+ patterns from data/patterns_extended.json at runtime.
Hardcoded fallback ensures the module works without the JSON file.
"""

import re
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

# ── Locate data file ──────────────────────────────────────────────────────────
_HERE = Path(__file__).parent.parent  # repo root
_PATTERNS_JSON = _HERE / "data" / "patterns_extended.json"

# ── RISKY_FILENAMES ────────────────────────────────────────────────────────────
RISKY_FILENAMES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.test",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "config.json",
    "wp-config.php",
    "settings.py",
    "database.yml",
    "database.yaml",
    "application.yml",
    "application.properties",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    "terraform.tfvars",
    "terraform.tfstate",
]

# ── RISKY_CONTENT_SIGNALS ──────────────────────────────────────────────────────
RISKY_CONTENT_SIGNALS = [
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "password",
    "passwd",
    "token",
    "private_key",
    "privatekey",
    "credentials",
    "access_key",
    "accesskey",
    "auth",
    "authorization",
    "AKIA",
    "sk_live",
    "sk_test",
    "SG.",
    "xoxb-",
    "xoxp-",
    "ghp_",
    "gho_",
    "glpat-",
    "hf_",
    "sk-ant",
    "-----BEGIN",
    # Database connection signals
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "database_url",
    "db_url",
    "connection_string",
    # Generic env patterns
    "_url=",
    "_uri=",
]

# ── Hardcoded fallback patterns (subset for offline use) ─────────────────────
_FALLBACK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "AWS Access Key": {
        "regex": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "category": "cloud-aws",
        "verifier": "aws_access_key",
        "description": "AWS IAM Access Key ID",
    },
    "Google API Key": {
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "category": "cloud-google",
        "verifier": "google_api_key",
        "description": "Google API Key",
    },
    "Stripe Live Key": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "category": "payment",
        "verifier": "stripe_key",
        "description": "Stripe Live Secret Key",
    },
    "Stripe Test Key": {
        "regex": r"sk_test_[0-9a-zA-Z]{24,}",
        "severity": "MEDIUM",
        "category": "payment",
        "verifier": "stripe_key",
        "description": "Stripe Test Secret Key",
    },
    "GitHub Personal Access Token": {
        "regex": r"ghp_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "category": "vcs",
        "verifier": "github_token",
        "description": "GitHub Personal Access Token (Classic)",
    },
    "GitHub OAuth Token": {
        "regex": r"gho_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "category": "vcs",
        "verifier": "github_token",
        "description": "GitHub OAuth Token",
    },
    "RSA Private Key": {
        "regex": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "CRITICAL",
        "category": "crypto",
        "verifier": None,
        "description": "RSA Private Key",
    },
    "OpenSSH Private Key": {
        "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "CRITICAL",
        "category": "crypto",
        "verifier": None,
        "description": "OpenSSH Private Key",
    },
    "Slack Bot Token": {
        "regex": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "severity": "HIGH",
        "category": "messaging",
        "verifier": "slack_token",
        "description": "Slack Bot Token",
    },
    "OpenAI API Key": {
        "regex": r"sk-[A-Za-z0-9]{48}",
        "severity": "CRITICAL",
        "category": "ai-ml",
        "verifier": "openai_key",
        "description": "OpenAI API Key",
    },
    "SendGrid API Key": {
        "regex": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "severity": "HIGH",
        "category": "email",
        "verifier": "sendgrid_key",
        "description": "SendGrid API Key",
    },
    "Generic API Key": {
        "regex": r"(?i)api[_\-\s]*key[\s]*[=:\"']+\s*([A-Za-z0-9\-_]{20,80})",
        "severity": "MEDIUM",
        "category": "generic",
        "verifier": None,
        "description": "Generic API Key assignment",
    },
    "Generic Password": {
        "regex": r"(?i)password[\s]*[=:\"']+\s*([^\s\"']{8,80})",
        "severity": "MEDIUM",
        "category": "generic",
        "verifier": None,
        "description": "Generic password assignment",
    },
    "PostgreSQL Connection String": {
        "regex": r"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"']+",
        "severity": "CRITICAL",
        "category": "database",
        "verifier": None,
        "description": "PostgreSQL connection string with credentials",
    },
    "MongoDB Connection String": {
        "regex": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+",
        "severity": "CRITICAL",
        "category": "database",
        "verifier": None,
        "description": "MongoDB connection string with credentials",
    },
}

# ── Runtime pattern store ─────────────────────────────────────────────────────
# Loaded at module init; dict keyed by pattern name
PATTERNS: Dict[str, Dict[str, Any]] = {}


def _json_pattern_to_dict(p: Dict[str, Any]) -> Dict[str, Any]:
    """Convert JSON pattern entry to internal PATTERNS format."""
    return {
        "regex": p["regex"],
        "severity": p.get("severity", "MEDIUM"),
        "category": p.get("category", "generic"),
        "verifier": p.get("verifier"),
        "description": p.get("description", p.get("name", p.get("id", "Unknown"))),
        "tags": p.get("tags", []),
        "id": p.get("id", ""),
    }


def load_patterns() -> Dict[str, Dict[str, Any]]:
    """
    Load patterns from data/patterns_extended.json and merge with hardcoded fallback.
    Returns merged dict keyed by pattern name.
    """
    global PATTERNS
    merged: Dict[str, Dict[str, Any]] = {}

    # 1. Try loading from JSON file
    if _PATTERNS_JSON.exists():
        try:
            with open(_PATTERNS_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
            for p in data.get("patterns", []):
                name = p.get("name") or p.get("id", "unknown")
                merged[name] = _json_pattern_to_dict(p)
        except Exception as e:
            import warnings
            warnings.warn(f"Could not load patterns_extended.json: {e}", stacklevel=2)

    # 2. Merge fallback (don't overwrite JSON-loaded ones)
    for name, meta in _FALLBACK_PATTERNS.items():
        if name not in merged:
            merged[name] = {**meta, "tags": [], "id": ""}

    PATTERNS = merged
    return merged


def get_patterns_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Return all patterns belonging to a given category."""
    _ensure_loaded()
    return {
        name: meta
        for name, meta in PATTERNS.items()
        if meta.get("category", "") == category
        or meta.get("category", "").startswith(category)
    }


def get_patterns_by_severity(severity: str) -> Dict[str, Dict[str, Any]]:
    """Return all patterns with a given severity level."""
    _ensure_loaded()
    return {
        name: meta
        for name, meta in PATTERNS.items()
        if meta.get("severity", "").upper() == severity.upper()
    }


def match_all(content: str) -> List[Dict[str, Any]]:
    """
    Run all loaded patterns against content.
    Returns list of match dicts with full metadata.
    Pre-filters using RISKY_CONTENT_SIGNALS for performance.
    """
    _ensure_loaded()

    # Fast pre-filter: skip expensive regex if no signals present
    lower_content = content.lower()
    has_signal = any(s.lower() in lower_content for s in RISKY_CONTENT_SIGNALS)
    if not has_signal:
        return []

    results: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for pattern_name, meta in PATTERNS.items():
        regex = meta["regex"]
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

                preview = raw_match[:80] + ("..." if len(raw_match) > 80 else "")
                results.append({
                    "pattern_name": pattern_name,
                    "match": raw_match,
                    "match_preview": preview,
                    "severity": meta.get("severity", "MEDIUM"),
                    "category": meta.get("category", "generic"),
                    "verifier": meta.get("verifier"),
                    "description": meta.get("description", ""),
                    "line_number": line_no,
                    "line_content": line.strip()[:200],
                })

    return results


def _ensure_loaded():
    """Ensure patterns have been loaded at least once."""
    if not PATTERNS:
        load_patterns()


# Auto-load on import
load_patterns()
