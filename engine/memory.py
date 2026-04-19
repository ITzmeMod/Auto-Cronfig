"""
SQLite-based knowledge base for Auto-Cronfig v2.
Tracks findings, verifications, scan history, and learns patterns over time.
"""

import os
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

    # ── Findings ──────────────────────────────────────────────────────────

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

        # Upsert pattern_stats.total_found
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

    # ── Scan history ──────────────────────────────────────────────────────

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
        # Upsert repo_stats
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

    # ── Pattern stats ─────────────────────────────────────────────────────

    def update_pattern_stats(self, pattern_name: str, verified_status: str):
        """Increment the appropriate verified_* counter for a pattern."""
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
        self._conn.execute(
            f"""
            INSERT INTO pattern_stats (pattern_name, {col}, last_updated)
            VALUES (?, 1, ?)
            ON CONFLICT(pattern_name) DO UPDATE SET
                {col} = {col} + 1,
                last_updated = excluded.last_updated
            """,
            (pattern_name, self._now()),
        )
        self._conn.commit()

    # ── File stats ────────────────────────────────────────────────────────

    def update_file_stats(self, extension: str, had_finding: bool):
        """Track which file extensions are most dangerous."""
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

    # ── Insights / Analytics ──────────────────────────────────────────────

    def get_risky_extensions(self) -> List[str]:
        """Return extensions ordered by finding_rate (findings/total_scanned) descending."""
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
        return {
            "total_scans": scans["cnt"],
            "total_repos_scanned": scans["repos"],
            "total_files_scanned": scans["files"],
            "total_findings": scans["findings"],
            "total_live_keys": scans["live_keys"],
            "active_patterns": patterns["cnt"],
        }

    def get_insights(self) -> List[str]:
        """
        Generate natural-language insight strings from accumulated data.
        Also refreshes the knowledge table.
        """
        insights: List[str] = []
        now = self._now()

        # 1. Top extension by finding rate
        ext_rows = self._conn.execute(
            """
            SELECT extension,
                   findings_count,
                   total_scanned,
                   CAST(findings_count AS REAL) / NULLIF(total_scanned, 0) AS finding_rate
            FROM file_stats
            WHERE total_scanned >= 5
            ORDER BY finding_rate DESC
            LIMIT 1
            """
        ).fetchone()
        if ext_rows and ext_rows["finding_rate"]:
            pct = round(ext_rows["finding_rate"] * 100, 1)
            insight = f"{ext_rows['extension']} files have the highest finding rate at {pct}%"
            insights.append(insight)
            self._upsert_knowledge("top_risky_extension", insight, now)

        # 2. Extension with most raw findings
        top_ext = self._conn.execute(
            "SELECT extension, findings_count, "
            "(SELECT SUM(findings_count) FROM file_stats) as total "
            "FROM file_stats ORDER BY findings_count DESC LIMIT 1"
        ).fetchone()
        if top_ext and top_ext["total"] and top_ext["total"] > 0:
            share = round((top_ext["findings_count"] / top_ext["total"]) * 100, 1)
            insight = f"{top_ext['extension']} files account for {share}% of all findings"
            insights.append(insight)
            self._upsert_knowledge("top_finding_extension", insight, now)

        # 3. Pattern with highest live rate
        live_row = self._conn.execute(
            """
            SELECT pattern_name,
                   verified_live,
                   (verified_live + verified_dead + verified_unknown) as total_verified,
                   CAST(verified_live AS REAL) / NULLIF(verified_live + verified_dead + verified_unknown, 0) as live_rate
            FROM pattern_stats
            WHERE (verified_live + verified_dead + verified_unknown) >= 3
            ORDER BY live_rate DESC
            LIMIT 1
            """
        ).fetchone()
        if live_row and live_row["live_rate"]:
            pct = round(live_row["live_rate"] * 100, 1)
            insight = f"{live_row['pattern_name']} has {pct}% live verification rate"
            insights.append(insight)
            self._upsert_knowledge("top_live_pattern", insight, now)

        # 4. Most found pattern
        most_found = self._conn.execute(
            "SELECT pattern_name, total_found FROM pattern_stats ORDER BY total_found DESC LIMIT 1"
        ).fetchone()
        if most_found and most_found["total_found"] > 0:
            insight = f"Most common secret type: {most_found['pattern_name']} ({most_found['total_found']} found)"
            insights.append(insight)
            self._upsert_knowledge("most_common_pattern", insight, now)

        # 5. Lifetime summary
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
