"""Pydantic v2 models for MCP tool input/output schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    S0 = "S0"  # Fatal
    S1 = "S1"  # Critical
    S2 = "S2"  # Warning
    S3 = "S3"  # Suggestion


class Category(str, Enum):
    Security = "Security"
    Performance = "Performance"
    Architecture = "Architecture"
    Compatibility = "Compatibility"
    DataIntegrity = "DataIntegrity"
    Reliability = "Reliability"
    Observability = "Observability"


class CoverageStatus(str, Enum):
    checked = "checked"
    not_applicable = "not_applicable"
    skipped = "skipped"


class EvidenceType(str, Enum):
    web_search = "web_search"
    kb_record = "kb_record"
    official_doc = "official_doc"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class Evidence(BaseModel):
    """A single piece of supporting evidence."""
    source: str = Field(description="URL or KB path")
    type: EvidenceType
    summary: str = Field(max_length=500, description="Factual summary only")


class Vulnerability(BaseModel):
    """One discovered vulnerability."""
    id: str = Field(description="e.g. V001")
    severity: Severity
    category: Category
    title: str
    trigger_scenario: str
    impact: str
    required_actions: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    waivable: bool = True
    waiver_required_adr: bool = False
    suggested_tradeoff: str | None = None


class MatrixCoverage(BaseModel):
    """7-dimension review matrix coverage."""
    Security: CoverageStatus = CoverageStatus.skipped
    Performance: CoverageStatus = CoverageStatus.skipped
    Architecture: CoverageStatus = CoverageStatus.skipped
    Compatibility: CoverageStatus = CoverageStatus.skipped
    DataIntegrity: CoverageStatus = CoverageStatus.skipped
    Reliability: CoverageStatus = CoverageStatus.skipped
    Observability: CoverageStatus = CoverageStatus.skipped


class WebSourceHash(BaseModel):
    url: str
    content_hash: str


class AuditMetadata(BaseModel):
    """Reproducibility fingerprint for every audit run."""
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reviewer_model: str = ""
    reviewer_api_base: str = ""
    prompt_template_version: str = "v0.1.0"
    kb_snapshot_hash: str = ""
    web_sources_hashes: list[WebSourceHash] = Field(default_factory=list)
    sanitizer_version: str = "v0.1.0"
    tool_version: str = "VC_replan-mcp@0.1.0"


# ---------------------------------------------------------------------------
# Tool I/O: mcp_audit_architecture
# ---------------------------------------------------------------------------

class AuditRequest(BaseModel):
    """Input for mcp_audit_architecture."""
    proposed_solution: str = Field(description="Technical solution text")
    tech_stack_keywords: list[str] = Field(
        description="Core tech/framework keywords for intelligence retrieval"
    )
    relevant_local_context: str = Field(
        description="Caller must supply relevant local code snippets"
    )
    project_id: str | None = Field(
        default=None,
        description="Optional project identifier for project-level KB"
    )


class AuditSummary(BaseModel):
    total_issues: int = 0
    s0_fatal: int = 0
    s1_critical: int = 0
    s2_warning: int = 0
    s3_suggestion: int = 0
    passed: bool = True


class IntelligenceSources(BaseModel):
    unifuncs_search: list[str] = Field(default_factory=list)
    kb_records_found: int = 0
    web_sources_consulted: int = 0


class AuditResponse(BaseModel):
    """Output of mcp_audit_architecture."""
    status: str = "reviewed"
    summary: AuditSummary = Field(default_factory=AuditSummary)
    matrix_coverage: MatrixCoverage = Field(default_factory=MatrixCoverage)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    intelligence_sources: IntelligenceSources = Field(
        default_factory=IntelligenceSources
    )
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


# ---------------------------------------------------------------------------
# Tool I/O: mcp_kb_update
# ---------------------------------------------------------------------------

class KBUpdateAction(str, Enum):
    link = "link"
    unlink = "unlink"
    refresh_links = "refresh_links"
    update_content = "update_content"
    cleanup_stale = "cleanup_stale"


class ContentPatch(BaseModel):
    append_section: str | None = None
    update_keywords: list[str] = Field(default_factory=list)
    update_tech_stack: list[str] = Field(default_factory=list)


class KBUpdateRequest(BaseModel):
    action: KBUpdateAction
    global_vuln_id: str | None = None
    global_category: str | None = None
    project_id: str | None = None
    project_kb_file: str | None = None
    content_patch: ContentPatch | None = None


class AffectedEntry(BaseModel):
    global_file: str
    change: str


class KBUpdateResponse(BaseModel):
    status: str = "success"
    action: KBUpdateAction
    affected_entries: list[AffectedEntry] = Field(default_factory=list)
    stale_links_found: int = 0
    stale_links_cleaned: int = 0
    summary: str = ""
