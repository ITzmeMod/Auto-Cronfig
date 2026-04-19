"""
SQLite-based knowledge base for Auto-Cronfig v3.
Tracks findings, verifications, scan history, leaked keys vault,
watchlist, false positives, and notifications.
"""

import os
import csv
import json
import hashlib
import sqlite3
import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


def _default_db_path() -> str:
    db_dir = Path.home() / ".auto-cronfig"
    db_dir.mkdir(parents=True, exist_ok=True)
    return str(db_dir / "memory.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT,
    repo              TEXT,
    file_path         TEXT,
    pattern_name      TEXT,
    match_preview     TEXT,
    severity          TEXT,
    url               TEXT,
    verified_status   TEXT DEFAULT 'PENDING',
    verified_detail   TEXT,
    created_at        TEXT
);

CREATE TABLE IF NOT EXISTS pattern_stats (
    pattern_name      TEXT PRIMARY KEY,
    total_found       INTEGER DEFAULT 0,
    verified_live     INTEGER DEFAULT 0,
    verified_dead     INTEGER DEFAULT 0,
    verified_unknown  INTEGER DEFAULT 0,
    last_updated      TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT,
    target            TEXT,
    target_type       TEXT,
    repos_scanned     INTEGER,
    files_scanned     INTEGER,
    findings_count    INTEGER,
    live_keys_count   INTEGER DEFAULT 0,
    duration_seconds  REAL,
    created_at        TEXT
);

CREATE TABLE IF NOT EXISTS file_stats (
    extension         TEXT PRIMARY KEY,
    total_scanned     INTEGER DEFAULT 0,
    findings_count    INTEGER DEFAULT 0,
    last_updated      TEXT
);

CREATE TABLE IF NOT EXISTS repo_stats (
    repo              TEXT PRIMARY KEY,
    times_scanned     INTEGER DEFAULT 0,
    findings_count    INTEGER DEFAULT 0,
    last_scanned      TEXT
);

CREATE TABLE IF NOT EXISTS knowledge (
    key               TEXT PRIMARY KEY,
    value             TEXT,
    updated_at        TEXT
);

CREATE TABLE IF NOT EXISTS leaked_keys (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT,
    repo              TEXT,
    file_path         TEXT,
    pattern_name      TEXT,
    raw_value_hash    TEXT UNIQUE,
    mask_preview      TEXT,
    severity          TEXT,
    url               TEXT,
    verified_status   TEXT DEFAULT 'PENDING',
    verified_detail   TEXT,
    first_seen        TEXT,
    last_verified     TEXT,
    is_active         INTEGER DEFAULT 1,
    notification_sent INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS watchlist (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    target            TEXT UNIQUE,
    target_type       TEXT,
    scan_mode         TEXT DEFAULT 'fast',
    schedule_cron     TEXT,
    last_scanned      TEXT,
    findings_count    INTEGER DEFAULT 0,
    created_at        TEXT,
    notes             TEXT
);

CREATE TABLE IF NOT EXISTS false_positives (
    hash              TEXT PRIMARY KEY,
    pattern_name      TEXT,
    reason            TEXT,
    added_at          TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        INTEGER,
    channel           TEXT,
    status            TEXT,
    sent_at           TEXT,
    error             TEXT
);
"""


class Memory:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path if db_path is not None else _default_db_path()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self):
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def _now(self) -> str:
        return datetime.datetime.utcnow().isoformat()

    # ── Findings ──────────────────────────────────────────────────────────────

    def save_finding(
        self,
        scan_id: str,
        repo: str,
        file_path: str,
        pattern_name: str,
        match_preview: str,
        severity: str,
        url: str,
    ) -> int:
        """Save a finding and return its auto-incremented id."""
        cur = self._conn.execute(
            """
            INSERT INTO findings
                (scan_id, repo, file_path, pattern_name, match_preview, severity, url, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, repo, file_path, pattern_name, match_preview, severity, url, self._now()),
        )
        self._conn.commit()

        self._conn.execute(
            """
            INSERT INTO pattern_stats (pattern_name, total_found, last_updated)
            VALUES (?, 1, ?)
            ON CONFLICT(pattern_name) DO UPDATE SET
                total_found = total_found + 1,
                last_updated = excluded.last_updated
            """,
            (pattern_name, self._now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_verification(self, finding_id: int, status: str, detail: str):
        """Update the verification result for a finding."""
        self._conn.execute(
            """
            UPDATE findings
            SET verified_status = ?, verified_detail = ?
            WHERE id = ?
            """,
            (status, detail, finding_id),
        )
        self._conn.commit()

    # ── Leaked Keys Vault ─────────────────────────────────────────────────────

    def save_leaked_key(
        self,
        scan_id: str,
        repo: str,
        file_path: str,
        pattern_name: str,
        raw_value: str,
        severity: str,
        url: str,
        verified_status: str = "PENDING",
        verified_detail: str = "",
    ) -> int:
        """
        Save a leaked key to the vault, deduplicating by SHA256 hash.
        Returns the id of the leaked_keys row.
        """
        raw_hash = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        mask_preview = (raw_value[:4] + "*" * max(0, len(raw_value) - 8) + raw_value[-4:]) if len(raw_value) > 8 else "****"
        now = self._now()

        # Check if already exists
        existing = self._conn.execute(
            "SELECT id FROM leaked_keys WHERE raw_value_hash = ?",
            (raw_hash,)
        ).fetchone()

        if existing:
            self._conn.execute(
                """
                UPDATE leaked_keys
                SET last_verified = ?, verified_status = ?, verified_detail = ?, is_active = 1
                WHERE raw_value_hash = ?
                """,
                (now, verified_status, verified_detail, raw_hash),
            )
            self._conn.commit()
            return existing["id"]

        cur = self._conn.execute(
            """
            INSERT INTO leaked_keys
                (scan_id, repo, file_path, pattern_name, raw_value_hash, mask_preview,
                 severity, url, verified_status, verified_detail, first_seen, last_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, repo, file_path, pattern_name, raw_hash, mask_preview,
             severity, url, verified_status, verified_detail, now, now),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_leaked_keys(self, status: Optional[str] = None, verified_only: bool = False) -> List[Dict]:
        """
        Get all leaked keys from the vault.
        Returns masked previews — never raw values.
        """
        query = "SELECT * FROM leaked_keys WHERE 1=1"
        params = []
        if status:
            query += " AND verified_status = ?"
            params.append(status)
        if verified_only:
            query += " AND verified_status = 'LIVE'"
        query += " ORDER BY severity DESC, first_seen DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Watchlist ─────────────────────────────────────────────────────────────

    def add_to_watchlist(
        self,
        target: str,
        target_type: str,
        scan_mode: str = "fast",
        notes: str = "",
    ) -> int:
        """Add a repo/user to watchlist. Returns id."""
        cur = self._conn.execute(
            """
            INSERT INTO watchlist (target, target_type, scan_mode, created_at, notes)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target) DO UPDATE SET
                scan_mode = excluded.scan_mode,
                notes = excluded.notes
            """,
            (target, target_type, scan_mode, self._now(), notes),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_watchlist(self) -> List[Dict]:
        """Get all watchlist items."""
        rows = self._conn.execute(
            "SELECT * FROM watchlist ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_watchlist_scan(self, target: str, findings_count: int):
        """Update last_scanned and findings_count for a watchlist item."""
        self._conn.execute(
            """
            UPDATE watchlist SET last_scanned = ?, findings_count = ?
            WHERE target = ?
            """,
            (self._now(), findings_count, target),
        )
        self._conn.commit()

    # ── False Positives ───────────────────────────────────────────────────────

    def add_false_positive(self, raw_value: str, pattern_name: str, reason: str = ""):
        """Hash and store a false positive so future scans skip it."""
        raw_hash = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        self._conn.execute(
            """
            INSERT OR REPLACE INTO false_positives (hash, pattern_name, reason, added_at)
            VALUES (?, ?, ?, ?)
            """,
            (raw_hash, pattern_name, reason, self._now()),
        )
        self._conn.commit()

    def is_false_positive(self, raw_value: str, pattern_name: str) -> bool:
        """Check if a value is a known false positive."""
        raw_hash = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        row = self._conn.execute(
            "SELECT 1 FROM false_positives WHERE hash = ? AND pattern_name = ?",
            (raw_hash, pattern_name),
        ).fetchone()
        return row is not None

    # ── Notifications ─────────────────────────────────────────────────────────

    def record_notification(self, finding_id: int, channel: str, status: str, error: str = ""):
        self._conn.execute(
            """
            INSERT INTO notifications (finding_id, channel, status, sent_at, error)
            VALUES (?, ?, ?, ?, ?)
            """,
            (finding_id, channel, status, self._now(), error),
        )
        self._conn.commit()

    # ── Scan history ──────────────────────────────────────────────────────────

    def save_scan(self, scan_id: str, target: str, target_type: str, stats: Dict[str, Any]):
        self._conn.execute(
            """
            INSERT INTO scan_history
                (scan_id, target, target_type, repos_scanned, files_scanned,
                 findings_count, live_keys_count, duration_seconds, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target,
                target_type,
                stats.get("repos_scanned", 0),
                stats.get("files_scanned", 0),
                stats.get("findings_count", 0),
                stats.get("live_keys_count", 0),
                stats.get("duration_seconds", 0.0),
                self._now(),
            ),
        )
        if target_type in ("repo", "user"):
            self._conn.execute(
                """
                INSERT INTO repo_stats (repo, times_scanned, findings_count, last_scanned)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(repo) DO UPDATE SET
                    times_scanned = times_scanned + 1,
                    findings_count = findings_count + excluded.findings_count,
                    last_scanned = excluded.last_scanned
                """,
                (target, stats.get("findings_count", 0), self._now()),
            )
        self._conn.commit()

    # ── Pattern stats ─────────────────────────────────────────────────────────

    def update_pattern_stats(self, pattern_name: str, verified_status: str):
        # Allowlist-based column mapping — prevents SQL injection.
        # col is never derived from user input; it comes from a fixed dict.
        _ALLOWED_STAT_COLS = {
            "verified_live",
            "verified_dead",
            "verified_unknown",
        }
        col_map = {
            "LIVE": "verified_live",
            "DEAD": "verified_dead",
            "UNKNOWN": "verified_unknown",
            "ERROR": "verified_unknown",
            "PENDING": None,
        }
        col = col_map.get(verified_status.upper())
        if col is None:
            return
        # Safety assertion: col must be in the explicit allowlist before
        # being interpolated into the SQL query string.
        assert col in _ALLOWED_STAT_COLS, f"Unexpected column name: {col!r}"
        # Column names come from a controlled allowlist, not user input — safe.
        # col is allowlist-validated above — safe to interpolate  # nosec B608
        sql = (  # nosec B608
            f"INSERT INTO pattern_stats (pattern_name, {col}, last_updated) "  # nosec B608
            f"VALUES (?, 1, ?) "
            f"ON CONFLICT(pattern_name) DO UPDATE SET "
            f"{col} = {col} + 1, "
            f"last_updated = excluded.last_updated"
        )
        self._conn.execute(sql, (pattern_name, self._now()))
        self._conn.commit()

    # ── File stats ────────────────────────────────────────────────────────────

    def update_file_stats(self, extension: str, had_finding: bool):
        finding_delta = 1 if had_finding else 0
        self._conn.execute(
            """
            INSERT INTO file_stats (extension, total_scanned, findings_count, last_updated)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(extension) DO UPDATE SET
                total_scanned = total_scanned + 1,
                findings_count = findings_count + excluded.findings_count,
                last_updated = excluded.last_updated
            """,
            (extension, finding_delta, self._now()),
        )
        self._conn.commit()

    # ── Insights / Analytics ──────────────────────────────────────────────────

    def get_risky_extensions(self) -> List[str]:
        rows = self._conn.execute(
            """
            SELECT extension,
                   CAST(findings_count AS REAL) / NULLIF(total_scanned, 0) AS finding_rate
            FROM file_stats
            WHERE total_scanned > 0
            ORDER BY finding_rate DESC
            """
        ).fetchall()
        return [row["extension"] for row in rows]

    def get_pattern_performance(self) -> Dict[str, Any]:
        rows = self._conn.execute("SELECT * FROM pattern_stats").fetchall()
        return {
            row["pattern_name"]: {
                "total_found": row["total_found"],
                "verified_live": row["verified_live"],
                "verified_dead": row["verified_dead"],
                "verified_unknown": row["verified_unknown"],
            }
            for row in rows
        }

    def get_lifetime_stats(self) -> Dict[str, Any]:
        scans = self._conn.execute(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(repos_scanned),0) as repos, "
            "COALESCE(SUM(files_scanned),0) as files, "
            "COALESCE(SUM(findings_count),0) as findings, "
            "COALESCE(SUM(live_keys_count),0) as live_keys FROM scan_history"
        ).fetchone()
        patterns = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM pattern_stats WHERE total_found > 0"
        ).fetchone()
        leaked = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM leaked_keys"
        ).fetchone()
        return {
            "total_scans": scans["cnt"],
            "total_repos_scanned": scans["repos"],
            "total_files_scanned": scans["files"],
            "total_findings": scans["findings"],
            "total_live_keys": scans["live_keys"],
            "active_patterns": patterns["cnt"],
            "total_leaked_keys_vault": leaked["cnt"],
        }

    def get_insights(self) -> List[str]:
        """Generate natural-language insight strings from accumulated data."""
        insights: List[str] = []
        now = self._now()

        ext_rows = self._conn.execute(
            """
            SELECT extension, findings_count, total_scanned,
                   CAST(findings_count AS REAL) / NULLIF(total_scanned, 0) AS finding_rate
            FROM file_stats WHERE total_scanned >= 5
            ORDER BY finding_rate DESC LIMIT 1
            """
        ).fetchone()
        if ext_rows and ext_rows["finding_rate"]:
            pct = round(ext_rows["finding_rate"] * 100, 1)
            insight = f"{ext_rows['extension']} files have the highest finding rate at {pct}%"
            insights.append(insight)
            self._upsert_knowledge("top_risky_extension", insight, now)

        most_found = self._conn.execute(
            "SELECT pattern_name, total_found FROM pattern_stats ORDER BY total_found DESC LIMIT 1"
        ).fetchone()
        if most_found and most_found["total_found"] > 0:
            insight = f"Most common secret type: {most_found['pattern_name']} ({most_found['total_found']} found)"
            insights.append(insight)
            self._upsert_knowledge("most_common_pattern", insight, now)

        live_row = self._conn.execute(
            """
            SELECT pattern_name, verified_live,
                   (verified_live + verified_dead + verified_unknown) as total_verified,
                   CAST(verified_live AS REAL) / NULLIF(verified_live + verified_dead + verified_unknown, 0) as live_rate
            FROM pattern_stats
            WHERE (verified_live + verified_dead + verified_unknown) >= 3
            ORDER BY live_rate DESC LIMIT 1
            """
        ).fetchone()
        if live_row and live_row["live_rate"]:
            pct = round(live_row["live_rate"] * 100, 1)
            insight = f"{live_row['pattern_name']} has {pct}% live verification rate"
            insights.append(insight)
            self._upsert_knowledge("top_live_pattern", insight, now)

        stats = self.get_lifetime_stats()
        if stats["total_scans"] > 0:
            insight = (
                f"Lifetime: {stats['total_scans']} scans, "
                f"{stats['total_files_scanned']} files scanned, "
                f"{stats['total_findings']} total findings, "
                f"{stats['total_live_keys']} live keys confirmed"
            )
            insights.append(insight)
            self._upsert_knowledge("lifetime_summary", insight, now)

        return insights

    def get_advanced_insights(self) -> Dict[str, Any]:
        """Return rich insight dict for stats dashboard."""
        lifetime = self.get_lifetime_stats()

        top_patterns = self._conn.execute(
            "SELECT pattern_name, total_found, verified_live FROM pattern_stats ORDER BY total_found DESC LIMIT 10"
        ).fetchall()

        top_repos = self._conn.execute(
            "SELECT repo, findings_count, last_scanned FROM repo_stats ORDER BY findings_count DESC LIMIT 10"
        ).fetchall()

        risky_extensions = self._conn.execute(
            """
            SELECT extension, findings_count, total_scanned,
                   CAST(findings_count AS REAL)/NULLIF(total_scanned,0) as rate
            FROM file_stats WHERE total_scanned > 0
            ORDER BY rate DESC LIMIT 10
            """
        ).fetchall()

        scan_freq = self._conn.execute(
            """
            SELECT DATE(created_at) as day, COUNT(*) as scans, SUM(findings_count) as findings
            FROM scan_history
            WHERE created_at >= datetime('now', '-7 days')
            GROUP BY day ORDER BY day
            """
        ).fetchall()

        live_rates = self._conn.execute(
            """
            SELECT pattern_name,
                   CAST(verified_live AS REAL)/NULLIF(verified_live+verified_dead+verified_unknown,0) as rate,
                   verified_live
            FROM pattern_stats
            WHERE (verified_live+verified_dead+verified_unknown) >= 3
            ORDER BY rate DESC LIMIT 10
            """
        ).fetchall()

        return {
            "lifetime": lifetime,
            "top_patterns": [dict(r) for r in top_patterns],
            "top_repos": [dict(r) for r in top_repos],
            "risky_extensions": [dict(r) for r in risky_extensions],
            "live_key_rate_by_service": {r["pattern_name"]: round((r["rate"] or 0) * 100, 1) for r in live_rates},
            "scan_frequency": [dict(r) for r in scan_freq],
            "insights_text": self.get_insights(),
        }

    def export_findings_csv(self, output_path: str, days: int = 30):
        """Export recent findings to CSV."""
        rows = self._conn.execute(
            """
            SELECT repo, file_path, pattern_name, severity, match_preview, url,
                   verified_status, verified_detail, created_at
            FROM findings
            WHERE created_at >= datetime('now', ?)
            ORDER BY severity DESC, created_at DESC
            """,
            (f"-{days} days",),
        ).fetchall()

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["repo", "file_path", "pattern", "severity", "preview",
                             "url", "verified_status", "verified_detail", "timestamp"])
            for r in rows:
                writer.writerow(list(r))

    def export_leaked_keys_json(self, output_path: str):
        """Export leaked keys vault to JSON (masked previews only)."""
        keys = self.get_leaked_keys()
        # Ensure no raw values leak — only include mask_preview
        safe_keys = []
        for k in keys:
            k.pop("raw_value_hash", None)
            safe_keys.append(k)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"exported_at": self._now(), "leaked_keys": safe_keys}, f, indent=2)

    def _upsert_knowledge(self, key: str, value: str, updated_at: str):
        self._conn.execute(
            """
            INSERT INTO knowledge (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, updated_at),
        )
        self._conn.commit()

    def close(self):
        self._conn.close()
