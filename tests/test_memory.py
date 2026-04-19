"""
Tests for engine/memory.py — all tests use in-memory SQLite (db_path=":memory:").
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.memory import Memory


class TestMemory(unittest.TestCase):

    def setUp(self):
        """Create a fresh in-memory DB for each test."""
        self.mem = Memory(db_path=":memory:")

    def tearDown(self):
        self.mem.close()

    def test_save_and_retrieve_finding(self):
        """save_finding returns an integer ID and the finding is stored."""
        fid = self.mem.save_finding(
            scan_id="abc123",
            repo="owner/repo",
            file_path=".env",
            pattern_name="AWS Access Key",
            match_preview="AKIAIOSFODNN7EXAMPLE",
            severity="CRITICAL",
            url="https://github.com/owner/repo/blob/HEAD/.env",
        )
        self.assertIsInstance(fid, int)
        self.assertGreater(fid, 0)

        rows = self.mem._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (fid,)
        ).fetchall()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["pattern_name"], "AWS Access Key")
        self.assertEqual(row["repo"], "owner/repo")
        self.assertEqual(row["verified_status"], "PENDING")

    def test_update_verification(self):
        """update_verification sets verified_status and verified_detail."""
        fid = self.mem.save_finding(
            scan_id="abc123",
            repo="owner/repo",
            file_path="config.py",
            pattern_name="GitHub Personal Access Token",
            match_preview="ghp_xxx",
            severity="CRITICAL",
            url="https://github.com/owner/repo/blob/HEAD/config.py",
        )
        self.mem.update_verification(fid, "LIVE", "GitHub user: testuser, scopes: repo")
        row = self.mem._conn.execute(
            "SELECT verified_status, verified_detail FROM findings WHERE id = ?", (fid,)
        ).fetchone()
        self.assertEqual(row["verified_status"], "LIVE")
        self.assertIn("testuser", row["verified_detail"])

    def test_pattern_stats_update_live(self):
        """update_pattern_stats increments verified_live counter."""
        self.mem.save_finding(
            scan_id="s1", repo="r/r", file_path="f.py",
            pattern_name="Stripe Live Key", match_preview="sk_live_xxx",
            severity="CRITICAL", url="http://example.com"
        )
        self.mem.update_pattern_stats("Stripe Live Key", "LIVE")
        row = self.mem._conn.execute(
            "SELECT verified_live FROM pattern_stats WHERE pattern_name = ?",
            ("Stripe Live Key",),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertGreaterEqual(row["verified_live"], 1)

    def test_pattern_stats_update_dead(self):
        """update_pattern_stats increments verified_dead counter."""
        self.mem.save_finding(
            scan_id="s2", repo="r/r", file_path="f.py",
            pattern_name="Stripe Live Key", match_preview="sk_live_dead",
            severity="CRITICAL", url="http://example.com"
        )
        self.mem.update_pattern_stats("Stripe Live Key", "DEAD")
        row = self.mem._conn.execute(
            "SELECT verified_dead FROM pattern_stats WHERE pattern_name = ?",
            ("Stripe Live Key",),
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertGreaterEqual(row["verified_dead"], 1)

    def test_file_stats_update(self):
        """update_file_stats tracks total_scanned and findings_count."""
        self.mem.update_file_stats(".env", had_finding=True)
        self.mem.update_file_stats(".env", had_finding=False)
        self.mem.update_file_stats(".env", had_finding=True)

        row = self.mem._conn.execute(
            "SELECT total_scanned, findings_count FROM file_stats WHERE extension = ?",
            (".env",),
        ).fetchone()
        self.assertEqual(row["total_scanned"], 3)
        self.assertEqual(row["findings_count"], 2)

    def test_get_insights_empty_db(self):
        """get_insights on empty DB returns empty list without raising."""
        insights = self.mem.get_insights()
        self.assertIsInstance(insights, list)
        # May be empty or have just lifetime summary
        # Should NOT raise

    def test_get_insights_with_data(self):
        """get_insights returns strings after some data has been added."""
        # Add some findings
        for i in range(5):
            fid = self.mem.save_finding(
                scan_id=f"scan{i}", repo="owner/repo", file_path=f"file{i}.env",
                pattern_name="AWS Access Key", match_preview="AKIAIOSFODNN7EXAMPLE",
                severity="CRITICAL", url="http://github.com/test"
            )
            self.mem.update_verification(fid, "LIVE", "AWS key is live")
            self.mem.update_pattern_stats("AWS Access Key", "LIVE")
            self.mem.update_file_stats(".env", had_finding=True)

        # Add scan history
        self.mem.save_scan(
            scan_id="scan0", target="owner/repo", target_type="repo",
            stats={"repos_scanned": 1, "files_scanned": 10, "findings_count": 5,
                   "live_keys_count": 5, "duration_seconds": 3.14}
        )

        insights = self.mem.get_insights()
        self.assertIsInstance(insights, list)
        self.assertGreater(len(insights), 0)
        for insight in insights:
            self.assertIsInstance(insight, str)
            self.assertGreater(len(insight), 0)

    def test_scan_history_saved(self):
        """save_scan persists to scan_history table."""
        self.mem.save_scan(
            scan_id="abc456",
            target="owner/repo",
            target_type="repo",
            stats={
                "repos_scanned": 1,
                "files_scanned": 42,
                "findings_count": 3,
                "live_keys_count": 1,
                "duration_seconds": 5.5,
            },
        )
        row = self.mem._conn.execute(
            "SELECT * FROM scan_history WHERE scan_id = ?", ("abc456",)
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["target"], "owner/repo")
        self.assertEqual(row["files_scanned"], 42)
        self.assertEqual(row["findings_count"], 3)
        self.assertEqual(row["live_keys_count"], 1)

    def test_lifetime_stats(self):
        """get_lifetime_stats aggregates scan_history correctly."""
        self.mem.save_scan(
            "s1", "owner/repo", "repo",
            {"repos_scanned": 1, "files_scanned": 10, "findings_count": 2,
             "live_keys_count": 1, "duration_seconds": 1.0}
        )
        self.mem.save_scan(
            "s2", "owner2/repo2", "repo",
            {"repos_scanned": 1, "files_scanned": 20, "findings_count": 5,
             "live_keys_count": 2, "duration_seconds": 2.0}
        )
        stats = self.mem.get_lifetime_stats()
        self.assertEqual(stats["total_scans"], 2)
        self.assertEqual(stats["total_files_scanned"], 30)
        self.assertEqual(stats["total_findings"], 7)
        self.assertEqual(stats["total_live_keys"], 3)

    def test_get_risky_extensions(self):
        """get_risky_extensions returns list ordered by finding rate."""
        self.mem.update_file_stats(".env", had_finding=True)
        self.mem.update_file_stats(".env", had_finding=True)
        self.mem.update_file_stats(".env", had_finding=False)  # rate = 2/3
        self.mem.update_file_stats(".py", had_finding=True)
        self.mem.update_file_stats(".py", had_finding=False)
        self.mem.update_file_stats(".py", had_finding=False)
        self.mem.update_file_stats(".py", had_finding=False)
        self.mem.update_file_stats(".py", had_finding=False)  # rate = 1/5
        # .env should rank higher
        risky = self.mem.get_risky_extensions()
        self.assertIn(".env", risky)
        self.assertIn(".py", risky)
        self.assertLess(risky.index(".env"), risky.index(".py"))

    def test_multiple_findings_pattern_stats(self):
        """Pattern stats total_found increments for each save_finding call."""
        for _ in range(3):
            self.mem.save_finding(
                scan_id="s1", repo="r/r", file_path="f.txt",
                pattern_name="Generic API Key", match_preview="apikey=XXXXXX",
                severity="MEDIUM", url="http://example.com"
            )
        row = self.mem._conn.execute(
            "SELECT total_found FROM pattern_stats WHERE pattern_name = ?",
            ("Generic API Key",)
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["total_found"], 3)


if __name__ == "__main__":
    unittest.main()
