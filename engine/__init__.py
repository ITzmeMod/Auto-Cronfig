"""
Auto-Cronfig v3 Engine
GitHub Secret Scanner — enterprise-grade, self-improving, Android-ready.
"""

from .patterns import (
    PATTERNS, RISKY_FILENAMES, RISKY_CONTENT_SIGNALS,
    load_patterns, match_all,
    get_patterns_by_category, get_patterns_by_severity,
)
from .verifier import verify, VerificationResult
from .memory import Memory
from .scanner import RepoScanner, RawFinding
from .deep_scanner import DeepScanner
from .global_scanner import GlobalScanner, GLOBAL_SEARCH_QUERIES, CATEGORY_QUERY_MAP
from .vibe_scanner import VibeScanner, VIBE_SCAN_QUERIES, VIBE_PLATFORM_SIGNALS
from .notifier import Notifier
from .exporter import Exporter
from .orchestrator import AutoCronfig, ScanMode, ScanReport

__version__ = "3.0.0"

__all__ = [
    # Patterns
    "PATTERNS",
    "RISKY_FILENAMES",
    "RISKY_CONTENT_SIGNALS",
    "load_patterns",
    "match_all",
    "get_patterns_by_category",
    "get_patterns_by_severity",
    # Verification
    "verify",
    "VerificationResult",
    # Memory
    "Memory",
    # Scanners
    "RepoScanner",
    "RawFinding",
    "DeepScanner",
    "GlobalScanner",
    "GLOBAL_SEARCH_QUERIES",
    "CATEGORY_QUERY_MAP",
    "VibeScanner",
    "VIBE_SCAN_QUERIES",
    "VIBE_PLATFORM_SIGNALS",
    # Utilities
    "Notifier",
    "Exporter",
    # Orchestration
    "AutoCronfig",
    "ScanMode",
    "ScanReport",
    # Meta
    "__version__",
]
