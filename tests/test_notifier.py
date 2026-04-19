"""
Tests for engine/notifier.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock, call
from engine.notifier import Notifier


def _make_finding(severity="CRITICAL", verified_status="LIVE"):
    return {
        "severity": severity,
        "pattern_name": "Test Pattern",
        "match_preview": "FAKE****789",
        "repo": "owner/repo",
        "url": "https://github.com/owner/repo/blob/HEAD/test.py",
        "verified_status": verified_status,
    }


class TestNotifierInit:
    def test_default_init(self):
        n = Notifier()
        assert n.telegram_token is None
        assert n.discord_webhook is None
        assert n.slack_webhook is None
        assert "CRITICAL" in n.notify_on

    def test_init_with_config(self):
        config = {
            "telegram_token": "bot123",
            "telegram_chat_id": "456",
            "discord_webhook": "https://discord.com/api/webhooks/test",
            "notify_on": ["CRITICAL"],
        }
        n = Notifier(config)
        assert n.telegram_token == "bot123"
        assert n.telegram_chat_id == "456"
        assert n.discord_webhook == "https://discord.com/api/webhooks/test"
        assert n.notify_on == ["CRITICAL"]


class TestNotifierFromEnv:
    def test_from_env_loads_telegram(self, monkeypatch):
        monkeypatch.setenv("AC_TELEGRAM_TOKEN", "test_bot_token")
        monkeypatch.setenv("AC_TELEGRAM_CHAT_ID", "12345")
        monkeypatch.delenv("AC_DISCORD_WEBHOOK", raising=False)
        monkeypatch.delenv("AC_SLACK_WEBHOOK", raising=False)
        n = Notifier.from_env()
        assert n.telegram_token == "test_bot_token"
        assert n.telegram_chat_id == "12345"

    def test_from_env_loads_discord(self, monkeypatch):
        monkeypatch.setenv("AC_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/test")
        monkeypatch.delenv("AC_TELEGRAM_TOKEN", raising=False)
        n = Notifier.from_env()
        assert n.discord_webhook == "https://discord.com/api/webhooks/test"

    def test_from_env_loads_slack(self, monkeypatch):
        monkeypatch.setenv("AC_SLACK_WEBHOOK", "https://hooks.slack.com/services/T123/B123/abc")
        monkeypatch.delenv("AC_TELEGRAM_TOKEN", raising=False)
        monkeypatch.delenv("AC_DISCORD_WEBHOOK", raising=False)
        n = Notifier.from_env()
        assert n.slack_webhook == "https://hooks.slack.com/services/T123/B123/abc"

    def test_from_env_notify_severity(self, monkeypatch):
        monkeypatch.setenv("AC_NOTIFY_SEVERITY", "CRITICAL")
        n = Notifier.from_env()
        assert n.notify_on == ["CRITICAL"]

    def test_from_env_default_severity(self, monkeypatch):
        monkeypatch.delenv("AC_NOTIFY_SEVERITY", raising=False)
        n = Notifier.from_env()
        assert "CRITICAL" in n.notify_on
        assert "HIGH" in n.notify_on


class TestTelegramNotification:
    def test_telegram_notification_sent(self):
        config = {
            "telegram_token": "bot123:test",
            "telegram_chat_id": "456789",
        }
        n = Notifier(config)
        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            n._send_telegram("Test message")
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "api.telegram.org" in call_args[0][0]

    def test_telegram_not_sent_without_token(self):
        n = Notifier({})
        with patch("requests.post") as mock_post:
            n._send_telegram("Test message")
            mock_post.assert_not_called()

    def test_telegram_handles_exception_gracefully(self):
        config = {"telegram_token": "bot123", "telegram_chat_id": "456"}
        n = Notifier(config)
        with patch("requests.post", side_effect=Exception("Network error")):
            # Should not raise
            n._send_telegram("Test message")


class TestDiscordNotification:
    def test_discord_notification_sent(self):
        config = {"discord_webhook": "https://discord.com/api/webhooks/test/token"}
        n = Notifier(config)
        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=204)
            n._send_discord("Test message")
            mock_post.assert_called_once_with(
                "https://discord.com/api/webhooks/test/token",
                json={"content": "Test message"},
                timeout=10,
            )

    def test_discord_not_sent_without_webhook(self):
        n = Notifier({})
        with patch("requests.post") as mock_post:
            n._send_discord("Test message")
            mock_post.assert_not_called()

    def test_discord_handles_exception_gracefully(self):
        config = {"discord_webhook": "https://discord.com/api/webhooks/test"}
        n = Notifier(config)
        with patch("requests.post", side_effect=Exception("Webhook error")):
            # Should not raise
            n._send_discord("Test message")


class TestSlackNotification:
    def test_slack_notification_sent(self):
        config = {"slack_webhook": "https://hooks.slack.com/services/T123/B123/abc"}
        n = Notifier(config)
        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            n._send_slack("Test message")
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "hooks.slack.com" in call_args[0][0]

    def test_slack_not_sent_without_webhook(self):
        n = Notifier({})
        with patch("requests.post") as mock_post:
            n._send_slack("Test message")
            mock_post.assert_not_called()


class TestSeverityThreshold:
    def test_low_finding_not_sent_when_threshold_is_critical(self):
        """LOW severity finding should NOT trigger notification when threshold is CRITICAL."""
        config = {
            "discord_webhook": "https://discord.com/api/webhooks/test",
            "notify_on": ["CRITICAL"],
        }
        n = Notifier(config)
        finding = _make_finding(severity="LOW", verified_status="UNKNOWN")
        with patch("requests.post") as mock_post:
            n.notify_finding(finding, "scan123")
            import time
            time.sleep(0.1)  # Wait for background thread
            mock_post.assert_not_called()

    def test_critical_finding_sent_when_threshold_is_critical(self):
        """CRITICAL severity finding SHOULD trigger notification."""
        config = {
            "discord_webhook": "https://discord.com/api/webhooks/test/token",
            "notify_on": ["CRITICAL"],
        }
        n = Notifier(config)
        finding = _make_finding(severity="CRITICAL", verified_status="LIVE")
        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=204)
            n._dispatch_finding(finding, "scan123")  # Call sync version directly
            mock_post.assert_called()

    def test_medium_not_sent_when_threshold_is_high(self):
        """MEDIUM finding should NOT be sent when threshold is HIGH."""
        config = {
            "slack_webhook": "https://hooks.slack.com/services/test",
            "notify_on": ["CRITICAL", "HIGH"],
        }
        n = Notifier(config)
        finding = _make_finding(severity="MEDIUM")
        with patch("requests.post") as mock_post:
            n.notify_finding(finding, "scan123")
            import time
            time.sleep(0.1)
            mock_post.assert_not_called()

    def test_should_notify_returns_true_for_matching_severity(self):
        n = Notifier({"notify_on": ["CRITICAL", "HIGH"]})
        assert n._should_notify("CRITICAL") is True
        assert n._should_notify("HIGH") is True

    def test_should_notify_returns_false_for_non_matching_severity(self):
        n = Notifier({"notify_on": ["CRITICAL"]})
        assert n._should_notify("LOW") is False
        assert n._should_notify("MEDIUM") is False

    def test_case_insensitive_severity_matching(self):
        n = Notifier({"notify_on": ["critical", "HIGH"]})
        assert n._should_notify("CRITICAL") is True
        assert n._should_notify("critical") is True


class TestNotifyScanComplete:
    def test_notify_scan_complete_sends_message(self):
        config = {
            "discord_webhook": "https://discord.com/api/webhooks/test/token",
            "notify_on": ["CRITICAL"],
        }
        n = Notifier(config)
        mock_report = MagicMock()
        mock_report.scan_id = "test123"
        mock_report.target = "owner/repo"
        mock_report.duration_seconds = 5.0
        mock_report.findings = [MagicMock()]
        mock_report.live_keys = []
        with patch("requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=204)
            n.notify_scan_complete(mock_report)
            mock_post.assert_called()
