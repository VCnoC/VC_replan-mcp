"""E3: Unit tests for engine/kb_writer.py"""

import shutil
from pathlib import Path

import pytest
import yaml

from models.schemas import Vulnerability, Severity, Category, Evidence, EvidenceType
from engine.kb_writer import write_vulnerabilities, compute_snapshot_hash


@pytest.fixture
def tmp_kb(tmp_path):
    """Create a temporary KB directory."""
    kb = tmp_path / "test_kb"
    kb.mkdir()
    return kb


def _make_vuln(
    vid: str = "V001",
    severity: Severity = Severity.S0,
    category: Category = Category.Security,
    title: str = "Test Vulnerability",
) -> Vulnerability:
    return Vulnerability(
        id=vid,
        severity=severity,
        category=category,
        title=title,
        trigger_scenario="When user does X",
        impact="Data loss",
        required_actions=["Fix it"],
        evidence=[Evidence(
            source="https://example.com",
            type=EvidenceType.web_search,
            summary="Found issue",
        )],
    )


class TestWriteVulnerabilities:
    def test_s0_writes_to_global(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S0)
        result = write_vulnerabilities(
            [vuln], "audit-001", tmp_kb, ["python"],
        )
        assert len(result["written_global"]) == 1
        assert len(result["skipped"]) == 0

    def test_s3_skipped(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S3)
        result = write_vulnerabilities(
            [vuln], "audit-001", tmp_kb, ["python"],
        )
        assert len(result["written_global"]) == 0
        assert len(result["skipped"]) == 1

    def test_s2_skipped_when_disabled(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S2)
        result = write_vulnerabilities(
            [vuln], "audit-001", tmp_kb, ["python"], write_s2=False,
        )
        assert len(result["skipped"]) == 1

    def test_s2_written_when_enabled(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S2)
        result = write_vulnerabilities(
            [vuln], "audit-001", tmp_kb, ["python"], write_s2=True,
        )
        assert len(result["written_global"]) == 1

    def test_project_write_with_reverse_link(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S0)
        result = write_vulnerabilities(
            [vuln], "audit-001", tmp_kb, ["python"], project_id="my-project",
        )
        assert len(result["written_global"]) == 1
        assert len(result["written_project"]) == 1

        # Verify reverse link in global index
        idx_path = tmp_kb / "global" / "Security" / "_index.yaml"
        idx_data = yaml.safe_load(idx_path.read_text())
        entry = idx_data["entries"][0]
        assert len(entry.get("related_projects", [])) == 1
        assert entry["related_projects"][0]["project_id"] == "my-project"

    def test_dedup_appends_audit_id(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S0)
        write_vulnerabilities([vuln], "audit-001", tmp_kb, ["python"])
        write_vulnerabilities([vuln], "audit-002", tmp_kb, ["python"])

        idx_path = tmp_kb / "global" / "Security" / "_index.yaml"
        idx_data = yaml.safe_load(idx_path.read_text())
        assert len(idx_data["entries"]) == 1
        assert "audit-002" in idx_data["entries"][0]["audit_ids"]

    def test_creates_directory_structure(self, tmp_kb):
        vuln = _make_vuln(category=Category.Performance)
        write_vulnerabilities([vuln], "audit-001", tmp_kb, ["redis"])
        assert (tmp_kb / "global" / "Performance").is_dir()
        assert (tmp_kb / "global" / "Performance" / "_index.yaml").exists()

    def test_md_file_content(self, tmp_kb):
        vuln = _make_vuln(severity=Severity.S1, title="JWT Leak")
        write_vulnerabilities([vuln], "audit-001", tmp_kb, ["jwt"])
        md_files = list((tmp_kb / "global" / "Security").glob("*.md"))
        assert len(md_files) == 1
        content = md_files[0].read_text()
        assert "JWT Leak" in content
        assert "V001" in content


class TestSnapshotHash:
    def test_empty_kb(self, tmp_kb):
        h = compute_snapshot_hash(tmp_kb)
        assert h.startswith("sha256:")

    def test_changes_after_write(self, tmp_kb):
        h1 = compute_snapshot_hash(tmp_kb)
        vuln = _make_vuln()
        write_vulnerabilities([vuln], "audit-001", tmp_kb, ["python"])
        h2 = compute_snapshot_hash(tmp_kb)
        assert h1 != h2
