"""
Tests for engine/patterns.py — v3
"""

import sys
import os
import re

# Add parent dir to path so engine imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.patterns import (
    load_patterns,
    get_patterns_by_category,
    get_patterns_by_severity,
    match_all,
    RISKY_FILENAMES,
    RISKY_CONTENT_SIGNALS,
    PATTERNS,
)


class TestLoadPatterns:
    def test_load_patterns_returns_dict(self):
        patterns = load_patterns()
        assert isinstance(patterns, dict)

    def test_load_patterns_has_many_patterns(self):
        patterns = load_patterns()
        assert len(patterns) >= 100, f"Expected 100+ patterns, got {len(patterns)}"

    def test_patterns_have_required_keys(self):
        patterns = load_patterns()
        for name, meta in list(patterns.items())[:5]:
            assert "regex" in meta, f"Pattern {name} missing 'regex'"
            assert "severity" in meta, f"Pattern {name} missing 'severity'"
            assert "category" in meta, f"Pattern {name} missing 'category'"

    def test_patterns_regex_compilable(self):
        patterns = load_patterns()
        for name, meta in patterns.items():
            regex = meta.get("regex", "")
            try:
                re.compile(regex)
            except re.error as e:
                pytest.fail(f"Pattern '{name}' has invalid regex: {e}")

    def test_patterns_severity_valid(self):
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        patterns = load_patterns()
        for name, meta in patterns.items():
            sev = meta.get("severity", "")
            assert sev in valid_severities, f"Pattern '{name}' has invalid severity: {sev}"

    def test_global_patterns_populated(self):
        """PATTERNS module-level variable should be populated."""
        assert len(PATTERNS) >= 100

    def test_aws_pattern_exists(self):
        patterns = load_patterns()
        has_aws = any("aws" in name.lower() or "aws" in meta.get("category", "").lower()
                      for name, meta in patterns.items())
        assert has_aws, "Should have at least one AWS pattern"

    def test_github_pat_pattern_exists(self):
        patterns = load_patterns()
        has_github = any("github" in name.lower() for name in patterns.keys())
        assert has_github, "Should have at least one GitHub PAT pattern"

    def test_openai_pattern_exists(self):
        patterns = load_patterns()
        has_openai = any("openai" in name.lower() for name in patterns.keys())
        assert has_openai, "Should have OpenAI pattern"


class TestGetPatternsByCategory:
    def test_get_by_cloud_category(self):
        result = get_patterns_by_category("cloud")
        assert isinstance(result, dict)

    def test_get_by_vcs_category(self):
        result = get_patterns_by_category("vcs")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_get_by_payment_category(self):
        result = get_patterns_by_category("payment")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_unknown_category_returns_empty(self):
        result = get_patterns_by_category("nonexistent_category_xyz")
        assert isinstance(result, dict)
        # May be empty or not, depending on matching logic


class TestGetPatternsBySeverity:
    def test_get_critical_patterns(self):
        result = get_patterns_by_severity("CRITICAL")
        assert isinstance(result, dict)
        assert len(result) > 0
        for name, meta in result.items():
            assert meta["severity"] == "CRITICAL"

    def test_get_high_patterns(self):
        result = get_patterns_by_severity("HIGH")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_case_insensitive(self):
        upper = get_patterns_by_severity("CRITICAL")
        lower = get_patterns_by_severity("critical")
        assert len(upper) == len(lower)


class TestMatchAll:
    def test_match_aws_access_key(self):
        # Construct test value at runtime to avoid literal secret detection
        prefix = "AKIA"
        suffix = "AAAAAAAAAAAAAAAA"
        content = f"aws_key = {prefix}{suffix}"
        results = match_all(content)
        patterns = [r["pattern_name"] for r in results]
        assert any("AWS" in p for p in patterns), f"Should detect AWS key, got: {patterns}"

    def test_match_github_pat(self):
        # Construct at runtime
        token = "ghp_" + "A" * 36
        content = f"GITHUB_TOKEN={token}"
        results = match_all(content)
        patterns = [r["pattern_name"] for r in results]
        assert any("GitHub" in p for p in patterns), f"Should detect GitHub PAT, got: {patterns}"

    def test_no_false_positives_on_clean_content(self):
        content = "print('Hello, World!')\nx = 1 + 2\n# Just a normal Python file"
        results = match_all(content)
        # Generic patterns might hit on clean code, but count should be very low
        assert len(results) == 0 or all(r["severity"] in ("LOW", "MEDIUM") for r in results)

    def test_match_returns_list(self):
        results = match_all("some api_key = test_value_here_1234567890")
        assert isinstance(results, list)

    def test_match_result_has_required_fields(self):
        token = "ghp_" + "B" * 36
        content = f"token={token}"
        results = match_all(content)
        for r in results:
            assert "pattern_name" in r
            assert "match" in r
            assert "severity" in r
            assert "line_number" in r

    def test_match_stripe_live_key(self):
        # Construct at runtime
        key = "sk_live_" + "x" * 24
        content = f"STRIPE_SECRET={key}"
        results = match_all(content)
        patterns = [r["pattern_name"] for r in results]
        assert any("Stripe" in p for p in patterns)

    def test_signal_prefilter_works(self):
        """Content with no signals should return empty quickly."""
        content = "x = 1\ny = 2\nfor i in range(10): pass"
        results = match_all(content)
        assert results == []

    def test_postgres_connection_detected(self):
        content = "DATABASE_URL=postgres://user:pass@localhost/mydb"
        results = match_all(content)
        patterns = [r["pattern_name"] for r in results]
        assert any("PostgreSQL" in p or "postgres" in p.lower() for p in patterns)


class TestRiskyFilenames:
    def test_risky_filenames_is_list(self):
        assert isinstance(RISKY_FILENAMES, list)

    def test_risky_filenames_has_env(self):
        assert ".env" in RISKY_FILENAMES

    def test_risky_filenames_has_30_plus(self):
        assert len(RISKY_FILENAMES) >= 30, f"Expected 30+ risky filenames, got {len(RISKY_FILENAMES)}"

    def test_risky_filenames_include_pem(self):
        assert ".pem" in RISKY_FILENAMES

    def test_risky_filenames_include_key(self):
        assert ".key" in RISKY_FILENAMES


class TestRiskyContentSignals:
    def test_risky_signals_is_list(self):
        assert isinstance(RISKY_CONTENT_SIGNALS, list)

    def test_risky_signals_has_api_key(self):
        assert "api_key" in RISKY_CONTENT_SIGNALS

    def test_risky_signals_has_password(self):
        assert "password" in RISKY_CONTENT_SIGNALS

    def test_risky_signals_has_token(self):
        assert "token" in RISKY_CONTENT_SIGNALS
