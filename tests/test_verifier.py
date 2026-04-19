"""
Tests for engine/verifier.py — all requests are mocked, no real API calls.
"""

import unittest
from unittest.mock import patch, MagicMock
import requests

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.verifier import verify, VerificationResult


def _mock_response(status_code=200, json_data=None, headers=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data or {}
    mock.headers = headers or {}
    return mock


class TestGitHubVerifier(unittest.TestCase):

    @patch("engine.verifier.requests.get")
    def test_github_live_token(self, mock_get):
        """Live GitHub token returns LIVE with user info."""
        mock_get.return_value = _mock_response(
            status_code=200,
            json_data={"login": "testuser", "id": 12345},
            headers={"X-OAuth-Scopes": "repo"},
        )
        result = verify("GitHub Personal Access Token", "ghp_" + "A" * 36)
        self.assertEqual(result.status, "LIVE")
        self.assertIn("testuser", result.detail)
        self.assertIn("repo", result.detail)

    @patch("engine.verifier.requests.get")
    def test_github_dead_token(self, mock_get):
        """Invalid GitHub token returns DEAD."""
        mock_get.return_value = _mock_response(status_code=401, json_data={"message": "Bad credentials"})
        result = verify("GitHub Personal Access Token", "ghp_deadtoken123")
        self.assertEqual(result.status, "DEAD")

    @patch("engine.verifier.requests.get")
    def test_stripe_live_key(self, mock_get):
        """Live Stripe key returns LIVE."""
        mock_get.return_value = _mock_response(
            status_code=200,
            json_data={"object": "balance", "available": []},
        )
        result = verify("Stripe Live Key", "sk_live_testkey1234567890")
        self.assertEqual(result.status, "LIVE")

    @patch("engine.verifier.requests.get")
    def test_stripe_dead_key(self, mock_get):
        """Rejected Stripe key returns DEAD."""
        mock_get.return_value = _mock_response(
            status_code=401,
            json_data={"error": {"type": "authentication_error"}},
        )
        result = verify("Stripe Live Key", "sk_live_invalid")
        self.assertEqual(result.status, "DEAD")

    @patch("engine.verifier.requests.post")
    def test_slack_live_token(self, mock_post):
        """Live Slack bot token returns LIVE with team info."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"ok": True, "team": "T1", "user": "u1", "team_id": "T01"},
        )
        # Use a fake token that matches the pattern but won't be flagged as a real secret
        fake_slack = "xoxb-" + "1" * 13 + "-" + "2" * 13 + "-" + "A" * 24
        result = verify("Slack Bot Token", fake_slack)
        self.assertEqual(result.status, "LIVE")
        self.assertIn("T1", result.detail)

    @patch("engine.verifier.requests.post")
    def test_slack_dead_token(self, mock_post):
        """Invalid Slack token returns DEAD."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"ok": False, "error": "invalid_auth"},
        )
        result = verify("Slack Bot Token", "xoxb-deadtoken")
        self.assertEqual(result.status, "DEAD")
        self.assertIn("invalid_auth", result.detail)

    @patch("engine.verifier.requests.get")
    def test_telegram_live_token(self, mock_get):
        """Live Telegram bot token returns LIVE."""
        mock_get.return_value = _mock_response(
            status_code=200,
            json_data={"ok": True, "result": {"username": "mybot", "id": 999}},
        )
        result = verify("Telegram Bot Token", "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789")
        self.assertEqual(result.status, "LIVE")
        self.assertIn("mybot", result.detail)

    def test_unknown_pattern_returns_unknown(self):
        """Pattern with no verifier returns UNKNOWN without making HTTP calls."""
        result = verify("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----")
        self.assertEqual(result.status, "UNKNOWN")

    def test_nonexistent_pattern_returns_unknown(self):
        """Completely unknown pattern name returns UNKNOWN."""
        result = verify("Totally Fake Pattern XYZ", "somevalue")
        self.assertEqual(result.status, "UNKNOWN")

    @patch("engine.verifier.requests.get")
    def test_network_error_returns_error(self, mock_get):
        """Network error (ConnectionError) returns ERROR gracefully."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        result = verify("GitHub Personal Access Token", "ghp_" + "A" * 36)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("ConnectionError", result.detail)

    @patch("engine.verifier.requests.get")
    def test_timeout_returns_error(self, mock_get):
        """Timeout returns ERROR gracefully."""
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")
        result = verify("GitHub Personal Access Token", "ghp_" + "A" * 36)
        self.assertEqual(result.status, "ERROR")

    def test_result_has_checked_at(self):
        """VerificationResult always has a checked_at timestamp."""
        result = verify("Generic API Key", "somefakeapikey12345678901234567890")
        self.assertIsNotNone(result.checked_at)
        self.assertIsInstance(result.checked_at, str)


if __name__ == "__main__":
    unittest.main()
