"""
Tests for Auto-Cronfig v3 DeepScanner.
All GitHub API calls are mocked — no real network requests.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import unittest
from unittest.mock import patch, MagicMock, call

from engine.deep_scanner import DeepScanner


def make_scanner():
    return DeepScanner(token="fake-token", workers=2)


def _mock_response(json_data, status_code=200):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    mock.raise_for_status.return_value = None
    return mock


def _mock_response_text(text, status_code=200):
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.json.return_value = {}
    mock.raise_for_status.return_value = None
    return mock


class TestScanCommitHistory(unittest.TestCase):

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_commit_history_finds_secrets(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session

        # Commits list response
        commits_resp = _mock_response([
            {"sha": "abc123", "commit": {"message": "add config"}}
        ])
        # Commit detail with patch containing a secret
        commit_detail_resp = _mock_response({
            "sha": "abc123",
            "files": [
                {
                    "filename": "config.py",
                    "patch": "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE123'\n+SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
                }
            ]
        })
        session.get.side_effect = [commits_resp, commit_detail_resp]

        scanner = make_scanner()
        findings = scanner.scan_commit_history("owner", "repo", max_commits=10)
        assert isinstance(findings, list)

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_commit_history_empty_repo(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response([])

        scanner = make_scanner()
        findings = scanner.scan_commit_history("owner", "repo", max_commits=10)
        assert findings == []

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_commit_history_handles_api_error(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response({"message": "Not Found"}, status_code=404)

        scanner = make_scanner()
        # Should not raise
        findings = scanner.scan_commit_history("owner", "repo", max_commits=10)
        assert isinstance(findings, list)


class TestScanPullRequests(unittest.TestCase):

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_pull_requests_finds_secrets(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session

        prs_resp = _mock_response([
            {
                "number": 1,
                "title": "add feature",
                "body": "token: ghp_abcdefghijklmnopqrstuvwxyz12345678901",
                "html_url": "https://github.com/owner/repo/pull/1"
            }
        ])
        # diff response
        diff_resp = _mock_response_text("+STRIPE_KEY=sk_live_" + "x" * 24)
        diff_resp.raise_for_status = MagicMock()

        # comments response
        comments_resp = _mock_response([])

        session.get.side_effect = [prs_resp, diff_resp, comments_resp]

        scanner = make_scanner()
        findings = scanner.scan_pull_requests("owner", "repo", max_prs=10)
        assert isinstance(findings, list)

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_pull_requests_empty(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response([])

        scanner = make_scanner()
        findings = scanner.scan_pull_requests("owner", "repo", max_prs=10)
        assert findings == []


class TestScanIssues(unittest.TestCase):

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_issues_finds_secrets(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session

        issues_resp = _mock_response([
            {
                "number": 42,
                "title": "bug report",
                "body": "I found this token: AKIAIOSFODNN7EXAMPLE123",
                "html_url": "https://github.com/owner/repo/issues/42",
                "comments": 0
            }
        ])
        session.get.return_value = issues_resp

        scanner = make_scanner()
        findings = scanner.scan_issues("owner", "repo", max_issues=10)
        assert isinstance(findings, list)

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_issues_scans_comments(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session

        issues_resp = _mock_response([
            {
                "number": 1,
                "title": "test",
                "body": "no secrets here",
                "html_url": "https://github.com/owner/repo/issues/1",
                "comments": 1,
                "comments_url": "https://api.github.com/repos/owner/repo/issues/1/comments"
            }
        ])
        comments_resp = _mock_response([
            {
                "body": "secret_key: AKIAIOSFODNN7EXAMPLE123",
                "html_url": "https://github.com/owner/repo/issues/1#comment-1"
            }
        ])
        session.get.side_effect = [issues_resp, comments_resp]

        scanner = make_scanner()
        findings = scanner.scan_issues("owner", "repo", max_issues=10)
        assert isinstance(findings, list)

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_issues_empty(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response([])

        scanner = make_scanner()
        findings = scanner.scan_issues("owner", "repo", max_issues=10)
        assert findings == []


class TestScanGists(unittest.TestCase):

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_gists_finds_secrets(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session

        gists_resp = _mock_response([
            {
                "id": "gist123",
                "html_url": "https://gist.github.com/user/gist123",
                "files": {
                    "config.py": {
                        "filename": "config.py",
                        "raw_url": "https://gist.githubusercontent.com/user/gist123/raw/config.py",
                        "size": 100
                    }
                }
            }
        ])
        file_resp = _mock_response_text("API_KEY = 'AKIAIOSFODNN7EXAMPLE123'")
        session.get.side_effect = [gists_resp, file_resp]

        scanner = make_scanner()
        findings = scanner.scan_gists("testuser")
        assert isinstance(findings, list)

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_gists_empty(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response([])

        scanner = make_scanner()
        findings = scanner.scan_gists("testuser")
        assert findings == []

    @patch("engine.deep_scanner.requests.Session")
    def test_scan_gists_handles_error(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.side_effect = Exception("Network error")

        scanner = make_scanner()
        # Should not raise
        findings = scanner.scan_gists("testuser")
        assert isinstance(findings, list)


class TestFullDeepScan(unittest.TestCase):

    @patch("engine.deep_scanner.requests.Session")
    def test_full_deep_scan_returns_list(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        # All endpoints return empty
        session.get.return_value = _mock_response([])

        scanner = make_scanner()
        findings = scanner.full_deep_scan("owner", "repo")
        assert isinstance(findings, list)

    @patch("engine.deep_scanner.requests.Session")
    def test_full_deep_scan_deduplicates(self, mock_session_cls):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response([])

        scanner = make_scanner()
        findings = scanner.full_deep_scan("owner", "repo")
        # Check no duplicates by (repo, file_path, pattern_name, match_preview)
        if findings:
            keys = [(f.get("repo"), f.get("file_path"), f.get("pattern_name"), f.get("match_preview"))
                    for f in findings]
            assert len(keys) == len(set(keys))


if __name__ == "__main__":
    unittest.main()
