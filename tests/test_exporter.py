"""
Tests for engine/exporter.py
"""

import sys
import os
import json
import csv
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock
from engine.exporter import Exporter
from engine.orchestrator import ScanReport, EnrichedFinding
from engine.scanner import RawFinding
from engine.verifier import VerificationResult


def _make_finding(finding_id=1, severity="HIGH", pattern="Test Pattern",
                  verified_status="LIVE", file_path="test.py", repo="owner/repo"):
    """Create a mock EnrichedFinding for testing."""
    raw = RawFinding(
        repo=repo,
        file_path=file_path,
        pattern_name=pattern,
        match="FAKE_SECRET_VALUE_123456789",
        match_preview="FAKE****789",
        severity=severity,
        url=f"https://github.com/{repo}/blob/HEAD/{file_path}",
        line_number=42,
    )
    vr = VerificationResult(
        status=verified_status,
        detail=f"Verified as {verified_status}",
        checked_at="2024-01-01T00:00:00",
        latency_ms=100,
    )
    ef = EnrichedFinding(raw=raw, finding_id=finding_id, verification=vr)
    return ef


def _make_report(findings=None):
    """Create a minimal ScanReport for testing."""
    if findings is None:
        findings = [
            _make_finding(1, "CRITICAL", "AWS Access Key", "LIVE"),
            _make_finding(2, "HIGH", "GitHub PAT", "DEAD"),
            _make_finding(3, "MEDIUM", "Generic API Key", "UNKNOWN"),
        ]
    live = [f for f in findings if f.verified_status == "LIVE"]
    report = ScanReport(
        scan_id="test1234",
        target="owner/test-repo",
        target_type="repo",
        duration_seconds=12.5,
        repos_scanned=1,
        files_scanned=50,
        findings=findings,
        live_keys=live,
        insights=["Test insight one", "Test insight two"],
    )
    return report


class TestToJson:
    def test_creates_valid_json_file(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.json")
        exporter.to_json(out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert "scan_id" in data
        assert "findings" in data

    def test_json_has_correct_scan_id(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.json")
        exporter.to_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["scan_id"] == "test1234"

    def test_json_has_all_findings(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.json")
        exporter.to_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["findings_count"] == 3
        assert len(data["findings"]) == 3

    def test_json_has_target_field(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.json")
        exporter.to_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["target"] == "owner/test-repo"

    def test_json_empty_findings(self, tmp_path):
        report = _make_report(findings=[])
        exporter = Exporter(report)
        out = str(tmp_path / "report.json")
        exporter.to_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["findings_count"] == 0


class TestToCsv:
    def test_creates_valid_csv_file(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.csv")
        exporter.to_csv(out)
        assert os.path.exists(out)

    def test_csv_has_header_row(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.csv")
        exporter.to_csv(out)
        with open(out, newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
        assert "repo" in header
        assert "pattern" in header
        assert "severity" in header

    def test_csv_has_correct_row_count(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.csv")
        exporter.to_csv(out)
        with open(out, newline="") as f:
            rows = list(csv.reader(f))
        # Header + 3 findings
        assert len(rows) == 4

    def test_csv_row_has_severity(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.csv")
        exporter.to_csv(out)
        with open(out, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert any(r["severity"] == "CRITICAL" for r in rows)


class TestToHtml:
    def test_creates_html_file(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.html")
        exporter.to_html(out)
        assert os.path.exists(out)

    def test_html_contains_scan_id(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.html")
        exporter.to_html(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "test1234" in content

    def test_html_is_valid_html(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.html")
        exporter.to_html(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content or "<html" in content

    def test_html_contains_findings(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.html")
        exporter.to_html(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "AWS Access Key" in content or "test.py" in content

    def test_html_with_no_findings(self, tmp_path):
        report = _make_report(findings=[])
        exporter = Exporter(report)
        out = str(tmp_path / "report.html")
        exporter.to_html(out)
        assert os.path.exists(out)


class TestToMarkdown:
    def test_creates_markdown_file(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.md")
        exporter.to_markdown(out)
        assert os.path.exists(out)

    def test_markdown_has_header(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.md")
        exporter.to_markdown(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "# " in content

    def test_markdown_has_scan_id(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.md")
        exporter.to_markdown(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "test1234" in content

    def test_markdown_has_table(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.md")
        exporter.to_markdown(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "|" in content  # Table separator

    def test_markdown_live_keys_section(self, tmp_path):
        report = _make_report()
        exporter = Exporter(report)
        out = str(tmp_path / "report.md")
        exporter.to_markdown(out)
        with open(out, encoding="utf-8") as f:
            content = f.read()
        # Report has 1 LIVE finding
        assert "Live" in content or "LIVE" in content


class TestPrintRichTable:
    def test_print_rich_table_runs_without_error(self, capsys):
        report = _make_report()
        exporter = Exporter(report)
        # Should not raise
        exporter.print_rich_table()
