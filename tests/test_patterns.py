"""
Tests for Auto-Cronfig pattern detection.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner import GitHubScanner, PATTERNS
import re


def make_scanner():
    return GitHubScanner()


# ─── Pattern Unit Tests ───────────────────────

def test_aws_access_key_detected():
    scanner = make_scanner()
    content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "AWS Access Key" in types, f"Expected AWS Access Key, got: {types}"


def test_google_api_key_detected():
    scanner = make_scanner()
    content = 'const apiKey = "AIzaSyD-9tSrke72SouVgN5XkXZcmFNxjQmL5no";'
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "Google API Key" in types, f"Expected Google API Key, got: {types}"


def test_stripe_live_key_detected():
    scanner = make_scanner()
    # Fake key for test purposes only — not a real secret
    fake_key = "sk_live_" + "x" * 24
    content = f"STRIPE_KEY={fake_key}"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "Stripe Live Key" in types


def test_github_token_detected():
    scanner = make_scanner()
    content = "token: ghp_abcdefghijklmnopqrstuvwxyz123456789012"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "GitHub Token" in types


def test_slack_webhook_detected():
    scanner = make_scanner()
    # Fake webhook for test purposes only — not a real secret
    fake_hook = "https://hooks.slack.com/services/T" + "0" * 8 + "/B" + "0" * 8 + "/" + "X" * 24
    content = f"webhook_url: {fake_hook}"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "Slack Webhook" in types


def test_discord_webhook_detected():
    scanner = make_scanner()
    content = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNO"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "Discord Webhook" in types


def test_private_key_detected():
    scanner = make_scanner()
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "Private Key (RSA)" in types


def test_db_connection_string_detected():
    scanner = make_scanner()
    content = "DATABASE_URL=postgres://admin:s3cr3tp@ss@db.example.com:5432/mydb"
    hits = scanner.scan_content(content, "test-context")
    types = [h["type"] for h in hits]
    assert "DB Connection String" in types


def test_no_false_positives_on_clean_code():
    scanner = make_scanner()
    content = """
def hello_world():
    print("Hello, World!")
    return 42

class MyClass:
    def __init__(self):
        self.value = "nothing secret here"
"""
    hits = scanner.scan_content(content, "test-context")
    assert len(hits) == 0, f"False positives found: {hits}"


# ─── Risky Filename Tests ─────────────────────

def test_env_file_flagged():
    scanner = make_scanner()
    hits = scanner.scan_filename(".env", "https://github.com/owner/repo/blob/main/.env")
    assert len(hits) > 0


def test_pem_file_flagged():
    scanner = make_scanner()
    hits = scanner.scan_filename("certs/server.pem", "ctx")
    assert len(hits) > 0


def test_normal_file_not_flagged():
    scanner = make_scanner()
    hits = scanner.scan_filename("src/main.py", "ctx")
    assert len(hits) == 0


# ─── Severity Tests ───────────────────────────

def test_severity_critical():
    assert GitHubScanner._severity("AWS Secret Key") == "CRITICAL"
    assert GitHubScanner._severity("Private Key (RSA)") == "CRITICAL"
    assert GitHubScanner._severity("GitHub Token") == "CRITICAL"


def test_severity_high():
    assert GitHubScanner._severity("AWS Access Key") == "HIGH"
    assert GitHubScanner._severity("Stripe Test Key") == "HIGH"


def test_severity_medium():
    assert GitHubScanner._severity("Slack Webhook") == "MEDIUM"
    assert GitHubScanner._severity("JWT Token") == "MEDIUM"


def test_severity_low():
    assert GitHubScanner._severity("Risky Filename") == "LOW"
    assert GitHubScanner._severity("Generic Password") == "LOW"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
