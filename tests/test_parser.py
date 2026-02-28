"""E6: Unit tests for engine/parser.py"""

import json

import pytest
from engine.parser import parse, _regex_fallback, _compute_summary
from models.schemas import Severity, Category, CoverageStatus, Vulnerability


def _valid_json_response():
    return json.dumps({
        "vulnerabilities": [
            {
                "id": "V001",
                "severity": "S0",
                "category": "Security",
                "title": "SQL Injection",
                "trigger_scenario": "User input in query",
                "impact": "Data breach",
                "required_actions": ["Use parameterized queries"],
                "evidence": [
                    {
                        "source": "https://owasp.org",
                        "type": "web_search",
                        "summary": "OWASP Top 10",
                    }
                ],
                "waivable": False,
            },
            {
                "id": "V002",
                "severity": "S2",
                "category": "Performance",
                "title": "N+1 Query",
                "trigger_scenario": "List endpoint",
                "impact": "Slow response",
                "required_actions": ["Add eager loading"],
                "evidence": [],
            },
        ],
        "matrix_coverage": {
            "Security": "checked",
            "Performance": "checked",
            "Architecture": "checked",
            "Compatibility": "not_applicable",
        },
    })


_COMMON_KWARGS = dict(
    reviewer_model="test-model",
    reviewer_api_base="https://test.api",
    prompt_template_version="v0.1.0",
    kb_snapshot_hash="sha256:abc",
    web_source_hashes=[],
    search_keywords=["python"],
    kb_records_found=0,
    web_sources_consulted=2,
)


class TestParseValidJSON:
    def test_parses_vulnerabilities(self):
        resp = parse(_valid_json_response(), True, **_COMMON_KWARGS)
        assert len(resp.vulnerabilities) == 2
        assert resp.vulnerabilities[0].id == "V001"
        assert resp.vulnerabilities[0].severity == Severity.S0

    def test_summary_counts(self):
        resp = parse(_valid_json_response(), True, **_COMMON_KWARGS)
        assert resp.summary.total_issues == 2
        assert resp.summary.s0_fatal == 1
        assert resp.summary.s2_warning == 1
        assert resp.summary.passed is False  # has S0

    def test_matrix_coverage(self):
        resp = parse(_valid_json_response(), True, **_COMMON_KWARGS)
        assert resp.matrix_coverage.Security == CoverageStatus.checked
        assert resp.matrix_coverage.Compatibility == CoverageStatus.not_applicable

    def test_audit_metadata(self):
        resp = parse(_valid_json_response(), True, **_COMMON_KWARGS)
        assert resp.audit_metadata.reviewer_model == "test-model"
        assert resp.audit_metadata.audit_id  # non-empty

    def test_intelligence_sources(self):
        resp = parse(_valid_json_response(), True, **_COMMON_KWARGS)
        assert resp.intelligence_sources.web_sources_consulted == 2


class TestParseInvalidJSON:
    def test_regex_fallback(self):
        raw = '''Some text "id": "V001", "severity": "S0", "category": "Security", "title": "SQL Injection" more text'''
        resp = parse(raw, False, **_COMMON_KWARGS)
        assert len(resp.vulnerabilities) >= 1
        assert resp.vulnerabilities[0].id == "V001"

    def test_empty_response(self):
        resp = parse("", False, **_COMMON_KWARGS)
        assert len(resp.vulnerabilities) == 0
        # Empty unparseable response should be marked as failed (not false-pass)
        assert resp.status == "failed"
        assert resp.summary.passed is False


class TestRegexFallback:
    def test_extracts_multiple(self):
        raw = '"id": "V001", "severity": "S0", "category": "Security", "title": "Injection" ... "id": "V002", "severity": "S1", "category": "Performance", "title": "Slow"'
        vulns = _regex_fallback(raw)
        assert len(vulns) == 2


class TestComputeSummary:
    def test_all_pass(self):
        vulns = [
            Vulnerability(id="V1", severity=Severity.S3, category=Category.Security,
                          title="t", trigger_scenario="t", impact="t"),
        ]
        s = _compute_summary(vulns)
        assert s.passed is True
        assert s.s3_suggestion == 1

    def test_s0_fails(self):
        vulns = [
            Vulnerability(id="V1", severity=Severity.S0, category=Category.Security,
                          title="t", trigger_scenario="t", impact="t"),
        ]
        s = _compute_summary(vulns)
        assert s.passed is False
