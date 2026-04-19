"""
Tests for Auto-Cronfig v2 pattern registry and pattern matching.
Updated for v2 engine architecture.
"""
import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from engine.patterns import PATTERNS, RISKY_FILENAMES


# ─── Pattern Registry Structure Tests ────────────────────────────────────────

def test_patterns_dict_not_empty():
    assert len(PATTERNS) >= 20, f"Expected 20+ patterns, got {len(PATTERNS)}"


def test_all_patterns_have_required_fields():
    required = {"regex", "severity", "category", "verifier", "description"}
    for name, meta in PATTERNS.items():
        missing = required - set(meta.keys())
        assert not missing, f"Pattern '{name}' missing fields: {missing}"


def test_all_severities_are_valid():
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for name, meta in PATTERNS.items():
        assert meta["severity"] in valid, \
            f"Pattern '{name}' has invalid severity: {meta['severity']}"


def test_all_regexes_compile():
    for name, meta in PATTERNS.items():
        try:
            re.compile(meta["regex"])
        except re.error as e:
            assert False, f"Pattern '{name}' has invalid regex: {e}"


def test_risky_filenames_not_empty():
    assert len(RISKY_FILENAMES) >= 5


# ─── Pattern Detection Tests ──────────────────────────────────────────────────

def _match(pattern_name: str, content: str) -> bool:
    regex = PATTERNS[pattern_name]["regex"]
    return bool(re.search(regex, content))


def test_aws_access_key_detected():
    assert _match("AWS Access Key", "export AWS_KEY=AKIAIOSFODNN7EXAMPLE123")


def test_google_api_key_detected():
    assert _match("Google API Key", 'apiKey: "AIzaSyD-9tSrke72SouVgN5XkXZcmFNxjQmL5no"')


def test_github_token_detected():
    assert _match("GitHub Personal Access Token", "token: ghp_abcdefghijklmnopqrstuvwxyz123456789012")


def test_stripe_live_key_detected():
    fake = "sk_live_" + "x" * 24
    assert _match("Stripe Live Key", f"STRIPE={fake}")


def test_stripe_test_key_detected():
    fake = "sk_test_" + "x" * 24
    assert _match("Stripe Test Key", f"STRIPE={fake}")


def test_private_rsa_key_detected():
    assert _match("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----")


def test_discord_webhook_detected():
    url = "https://discord.com/api/webhooks/123456789012345678/" + "A" * 68
    assert _match("Discord Webhook URL", url)


def test_jwt_token_detected():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert _match("JWT Token", jwt)


def test_telegram_bot_token_detected():
    assert _match("Telegram Bot Token", "bot_token=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")


def test_db_connection_string_detected():
    assert _match("PostgreSQL Connection String", "postgres://admin:s3cr3t@db.example.com:5432/mydb")


# ─── Risky Filename Tests ─────────────────────────────────────────────────────

def test_env_file_in_risky_filenames():
    assert any(re.search(p, ".env", re.IGNORECASE) for p in RISKY_FILENAMES)


def test_pem_file_in_risky_filenames():
    assert any(re.search(p, "server.pem", re.IGNORECASE) for p in RISKY_FILENAMES)


def test_credentials_json_in_risky_filenames():
    assert any(re.search(p, "credentials.json", re.IGNORECASE) for p in RISKY_FILENAMES)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
