"""Vulnerability parser — JSON validation → Pydantic → regex fallback.

Parses the Reviewer model's raw output into structured Vulnerability
objects, computes summary statistics, and fills matrix coverage.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone

from models.schemas import (
    AuditMetadata,
    AuditResponse,
    AuditSummary,
    CoverageStatus,
    Evidence,
    EvidenceType,
    IntelligenceSources,
    MatrixCoverage,
    Severity,
    Category,
    Vulnerability,
    WebSourceHash,
)

logger = logging.getLogger("engine.parser")


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

def _parse_json(raw: str) -> dict | None:
    """Try to parse raw string as JSON."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _safe_severity(val: str) -> Severity:
    try:
        return Severity(val)
    except ValueError:
        return Severity.S3


def _safe_category(val: str) -> Category:
    try:
        return Category(val)
    except ValueError:
        return Category.Architecture


def _safe_evidence_type(val: str) -> EvidenceType:
    try:
        return EvidenceType(val)
    except ValueError:
        return EvidenceType.web_search


# ---------------------------------------------------------------------------
# Structured parsing from JSON dict
# ---------------------------------------------------------------------------

def _parse_vulnerability(data: dict) -> Vulnerability:
    """Parse a single vulnerability dict into a Pydantic model."""
    evidence = []
    for ev in data.get("evidence", []):
        evidence.append(Evidence(
            source=ev.get("source", ""),
            type=_safe_evidence_type(ev.get("type", "web_search")),
            summary=ev.get("summary", "")[:500],
        ))

    return Vulnerability(
        id=data.get("id", f"V{uuid.uuid4().hex[:3].upper()}"),
        severity=_safe_severity(data.get("severity", "S3")),
        category=_safe_category(data.get("category", "Architecture")),
        title=data.get("title", "Untitled"),
        trigger_scenario=data.get("trigger_scenario", ""),
        impact=data.get("impact", ""),
        required_actions=data.get("required_actions", []),
        evidence=evidence,
        waivable=data.get("waivable", True),
        waiver_required_adr=data.get("waiver_required_adr", False),
        suggested_tradeoff=data.get("suggested_tradeoff"),
    )


def _parse_matrix(data: dict) -> MatrixCoverage:
    """Parse matrix_coverage dict."""
    def _status(val: str) -> CoverageStatus:
        try:
            return CoverageStatus(val)
        except ValueError:
            return CoverageStatus.skipped

    mc = data.get("matrix_coverage", {})
    return MatrixCoverage(
        Security=_status(mc.get("Security", "skipped")),
        Performance=_status(mc.get("Performance", "skipped")),
        Architecture=_status(mc.get("Architecture", "skipped")),
        Compatibility=_status(mc.get("Compatibility", "skipped")),
        DataIntegrity=_status(mc.get("DataIntegrity", "skipped")),
        Reliability=_status(mc.get("Reliability", "skipped")),
        Observability=_status(mc.get("Observability", "skipped")),
    )


# ---------------------------------------------------------------------------
# Regex fallback
# ---------------------------------------------------------------------------

_VULN_PATTERN = re.compile(
    r'"id"\s*:\s*"(V\d+)".*?'
    r'"severity"\s*:\s*"(S[0-3])".*?'
    r'"category"\s*:\s*"(\w+)".*?'
    r'"title"\s*:\s*"([^"]+)"',
    re.DOTALL,
)


def _regex_fallback(raw: str) -> list[Vulnerability]:
    """Extract vulnerabilities via regex when JSON parsing fails."""
    vulns: list[Vulnerability] = []
    for match in _VULN_PATTERN.finditer(raw):
        vid, sev, cat, title = match.groups()
        vulns.append(Vulnerability(
            id=vid,
            severity=_safe_severity(sev),
            category=_safe_category(cat),
            title=title,
            trigger_scenario="(extracted via regex fallback)",
            impact="(see raw output for details)",
        ))
    return vulns


# ---------------------------------------------------------------------------
# Summary computation
# ---------------------------------------------------------------------------

def _compute_summary(vulns: list[Vulnerability]) -> AuditSummary:
    counts = {s: 0 for s in Severity}
    for v in vulns:
        counts[v.severity] += 1
    return AuditSummary(
        total_issues=len(vulns),
        s0_fatal=counts[Severity.S0],
        s1_critical=counts[Severity.S1],
        s2_warning=counts[Severity.S2],
        s3_suggestion=counts[Severity.S3],
        passed=counts[Severity.S0] == 0,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse(
    raw_response: str,
    is_valid_json: bool,
    reviewer_model: str,
    reviewer_api_base: str,
    prompt_template_version: str,
    kb_snapshot_hash: str,
    web_source_hashes: list[WebSourceHash],
    search_keywords: list[str],
    kb_records_found: int,
    web_sources_consulted: int,
    kb_retrieval_method: str = "",
    kb_cli_name: str = "",
) -> AuditResponse:
    """Parse Reviewer output into a structured AuditResponse."""

    vulns: list[Vulnerability] = []
    matrix = MatrixCoverage()

    if is_valid_json:
        data = _parse_json(raw_response)
        if data:
            for v_data in data.get("vulnerabilities", []):
                try:
                    vulns.append(_parse_vulnerability(v_data))
                except Exception as exc:
                    logger.warning(
                        "Skipping malformed vulnerability entry %s: %s",
                        v_data.get("id", "?"), exc,
                    )
            matrix = _parse_matrix(data)
    else:
        # Regex fallback
        logger.warning("Using regex fallback for parsing")
        vulns = _regex_fallback(raw_response)

    summary = _compute_summary(vulns)

    # If JSON was invalid and no vulns extracted, mark as failed
    # to prevent false "passed" on reviewer errors
    status = "reviewed"
    if not is_valid_json and not vulns:
        status = "failed"
        summary.passed = False
        logger.warning("Reviewer output unparseable — marking as failed")

    metadata = AuditMetadata(
        reviewer_model=reviewer_model,
        reviewer_api_base=reviewer_api_base,
        prompt_template_version=prompt_template_version,
        kb_snapshot_hash=kb_snapshot_hash,
        web_sources_hashes=web_source_hashes,
    )

    intel = IntelligenceSources(
        unifuncs_search=search_keywords,
        kb_records_found=kb_records_found,
        kb_retrieval_method=kb_retrieval_method,
        kb_cli_name=kb_cli_name,
        web_sources_consulted=web_sources_consulted,
    )

    return AuditResponse(
        status=status,
        summary=summary,
        matrix_coverage=matrix,
        vulnerabilities=vulns,
        intelligence_sources=intel,
        audit_metadata=metadata,
    )
