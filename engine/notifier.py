"""
Multi-channel notification system for Auto-Cronfig v3.
Supports Telegram, Discord, Slack, and custom webhooks.
"""

import os
import logging
import json
import threading
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)
import requests


class Notifier:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.telegram_token: Optional[str] = cfg.get("telegram_token")
        self.telegram_chat_id: Optional[str] = cfg.get("telegram_chat_id")
        self.discord_webhook: Optional[str] = cfg.get("discord_webhook")
        self.slack_webhook: Optional[str] = cfg.get("slack_webhook")
        self.custom_webhook: Optional[str] = cfg.get("custom_webhook")
        self.notify_on: List[str] = cfg.get("notify_on", ["CRITICAL", "HIGH"])
        self._timeout = 10

    @classmethod
    def from_env(cls) -> "Notifier":
        """Load configuration from environment variables."""
        config = {
            "telegram_token": os.environ.get("AC_TELEGRAM_TOKEN"),
            "telegram_chat_id": os.environ.get("AC_TELEGRAM_CHAT_ID"),
            "discord_webhook": os.environ.get("AC_DISCORD_WEBHOOK"),
            "slack_webhook": os.environ.get("AC_SLACK_WEBHOOK"),
            "custom_webhook": os.environ.get("AC_WEBHOOK_URL"),
            "notify_on": [
                s.strip().upper()
                for s in os.environ.get("AC_NOTIFY_SEVERITY", "CRITICAL,HIGH").split(",")
                if s.strip()
            ],
        }
        return cls(config)

    def _should_notify(self, severity: str) -> bool:
        """Check if severity meets the notification threshold."""
        return severity.upper() in [s.upper() for s in self.notify_on]

    def notify_finding(self, finding: Dict[str, Any], scan_id: str):
        """
        Send notification for a finding based on severity threshold.
        Non-blocking: runs in a background thread.
        """
        severity = finding.get("severity", "UNKNOWN")
        if not self._should_notify(severity):
            return

        def _send():
            self._dispatch_finding(finding, scan_id)

        thread = threading.Thread(target=_send, daemon=True)
        thread.start()

    def _dispatch_finding(self, finding: Dict[str, Any], scan_id: str):
        """Send finding notification to all configured channels."""
        severity = finding.get("severity", "UNKNOWN")
        pattern = finding.get("pattern_name", "Unknown Pattern")
        preview = finding.get("match_preview", "")
        repo = finding.get("repo", "")
        url = finding.get("url", "")
        verified = finding.get("verified_status", "PENDING")

        # Severity emoji
        emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📋", "LOW": "ℹ️"}.get(severity, "🔍")
        live_badge = " 🔴 LIVE!" if verified == "LIVE" else ""

        message = (
            f"{emoji} **Auto-Cronfig Alert**{live_badge}\n"
            f"**Scan ID:** `{scan_id}`\n"
            f"**Pattern:** {pattern}\n"
            f"**Severity:** {severity}\n"
            f"**Repo:** {repo}\n"
            f"**Preview:** `{preview[:60]}`\n"
            f"**URL:** {url}"
        )

        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(message)
        if self.discord_webhook:
            self._send_discord(message)
        if self.slack_webhook:
            self._send_slack(message)
        if self.custom_webhook:
            self._send_webhook({
                "scan_id": scan_id,
                "finding": finding,
                "message": message,
            })

    def _send_telegram(self, message: str):
        """Send message via Telegram Bot API."""
        if not self.telegram_token or not self.telegram_chat_id:
            return
        try:
            # Convert markdown to Telegram-compatible format (HTML)
            html_message = (
                message
                .replace("**", "<b>", 1).replace("**", "</b>", 1)
                .replace("`", "<code>", 1).replace("`", "</code>", 1)
            )
            # Simpler: just send plain text
            plain = (
                message
                .replace("**", "")
                .replace("`", "")
                .replace("🚨", "🚨")
            )
            requests.post(
                f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                json={
                    "chat_id": self.telegram_chat_id,
                    "text": plain,
                    "parse_mode": "HTML",
                },
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.warning("[notifier] send failed: %s", exc)

    def _send_discord(self, message: str):
        """Send message via Discord Webhook."""
        if not self.discord_webhook:
            return
        try:
            requests.post(
                self.discord_webhook,
                json={"content": message[:2000]},
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.warning("[notifier] send failed: %s", exc)

    def _send_slack(self, message: str):
        """Send message via Slack Webhook."""
        if not self.slack_webhook:
            return
        try:
            # Convert ** to Slack bold syntax *
            slack_msg = message.replace("**", "*")
            requests.post(
                self.slack_webhook,
                json={"text": slack_msg[:3000]},
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.warning("[notifier] send failed: %s", exc)

    def _send_webhook(self, payload: Dict[str, Any]):
        """Send payload to custom webhook URL."""
        if not self.custom_webhook:
            return
        try:
            requests.post(
                self.custom_webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.warning("[notifier] send failed: %s", exc)

    def notify_scan_complete(self, report):
        """Send a scan completion summary notification."""
        findings_count = len(report.findings) if hasattr(report, "findings") else 0
        live_count = len(report.live_keys) if hasattr(report, "live_keys") else 0
        scan_id = getattr(report, "scan_id", "unknown")
        target = getattr(report, "target", "unknown")
        duration = round(getattr(report, "duration_seconds", 0), 1)

        message = (
            f"✅ **Scan Complete** — ID: `{scan_id}`\n"
            f"**Target:** {target}\n"
            f"**Findings:** {findings_count}\n"
            f"**Live Keys:** {'🔴 ' + str(live_count) if live_count > 0 else str(live_count)}\n"
            f"**Duration:** {duration}s"
        )

        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(message)
        if self.discord_webhook:
            self._send_discord(message)
        if self.slack_webhook:
            self._send_slack(message)
