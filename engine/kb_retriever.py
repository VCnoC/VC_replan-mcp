"""Knowledge-base retriever — index-first search with clink CLI fallback.

Retrieval strategy:
1. Scan _index.yaml files for keyword matches (fast)
2. Read matched .md files for full context (on demand)
3. Merge global + project results, deduplicate by vuln_id
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from engine.sanitizer import sanitize
from engine.kb_writer import _keyword_overlap

logger = logging.getLogger("engine.kb_retriever")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class KBRecord:
    """A single knowledge-base record."""
    vuln_id: str
    severity: str
    category: str
    title: str
    keywords: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    file_path: str = ""
    content: str = ""
    hit_count: int = 0
    layer: str = "global"  # "global" or "project"


@dataclass
class KBRetrievalResult:
    records: list[KBRecord] = field(default_factory=list)
    snapshot_hash: str = ""
    injection_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Categories (7-dimension matrix)
# ---------------------------------------------------------------------------
CATEGORIES = [
    "Security", "Performance", "Architecture",
    "Compatibility", "DataIntegrity", "Reliability", "Observability",
]


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _safe_path(kb_root: Path, candidate: Path) -> bool:
    """Ensure *candidate* is inside *kb_root* (whitelist enforcement)."""
    try:
        candidate.resolve().relative_to(kb_root.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Index-based retrieval (Python native fallback)
# ---------------------------------------------------------------------------

def _scan_index(
    index_path: Path,
    query_keywords: list[str],
    kb_root: Path,
    layer: str,
) -> list[KBRecord]:
    """Parse a single _index.yaml and return matching KBRecords."""
    if not index_path.exists():
        return []
    if not _safe_path(kb_root, index_path):
        logger.warning("Path outside KB root: %s", index_path)
        return []

    try:
        data = yaml.safe_load(index_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", index_path, exc)
        return []

    if not data or "entries" not in data:
        return []

    matches: list[KBRecord] = []
    for entry in data["entries"]:
        kw = entry.get("keywords", []) + entry.get("tech_stack", [])
        overlap = _keyword_overlap(kw, query_keywords)
        if overlap > 0:
            matches.append(KBRecord(
                vuln_id=entry.get("vuln_id", ""),
                severity=entry.get("severity", ""),
                category=entry.get("category", index_path.parent.name),
                title=entry.get("title", ""),
                keywords=entry.get("keywords", []),
                tech_stack=entry.get("tech_stack", []),
                file_path=str(index_path.parent / entry.get("file", "")),
                hit_count=entry.get("hit_count", 0),
                layer=layer,
            ))
    return matches


def _read_full_record(record: KBRecord, kb_root: Path) -> KBRecord:
    """Read the .md file for a matched record and sanitize content."""
    md_path = Path(record.file_path)
    if not md_path.exists() or not _safe_path(kb_root, md_path):
        return record
    try:
        raw = md_path.read_text(encoding="utf-8")
        result = sanitize(raw)
        record.content = result.cleaned
    except Exception as exc:
        logger.warning("Failed to read %s: %s", md_path, exc)
    return record


def _update_hit_count(index_path: Path, vuln_id: str) -> None:
    """Increment hit_count for a matched entry in _index.yaml."""
    if not index_path.exists():
        return
    try:
        data = yaml.safe_load(index_path.read_text(encoding="utf-8"))
        if not data or "entries" not in data:
            return
        for entry in data["entries"]:
            if entry.get("vuln_id") == vuln_id:
                entry["hit_count"] = entry.get("hit_count", 0) + 1
                break
        index_path.write_text(
            yaml.dump(data, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("Failed to update hit_count in %s: %s", index_path, exc)


# ---------------------------------------------------------------------------
# Snapshot hash
# ---------------------------------------------------------------------------

def _compute_snapshot_hash(kb_root: Path) -> str:
    """SHA-256 over all _index.yaml contents for reproducibility."""
    import hashlib
    h = hashlib.sha256()
    for idx in sorted(kb_root.rglob("_index.yaml")):
        if _safe_path(kb_root, idx):
            try:
                h.update(idx.read_bytes())
            except Exception:
                pass
    return f"sha256:{h.hexdigest()}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def retrieve(
    kb_path: Path,
    tech_stack_keywords: list[str],
    project_id: str | None = None,
) -> KBRetrievalResult:
    """Retrieve relevant KB records using index-first strategy.

    This is the Python-native fallback.  When clink CLI is available,
    the caller (kb_retriever via clink) can use AI-powered retrieval
    instead.
    """
    kb_root = Path(kb_path).resolve()
    if not kb_root.exists():
        logger.info("KB path does not exist: %s", kb_root)
        return KBRetrievalResult(snapshot_hash=f"sha256:{'0'*64}")

    all_records: list[KBRecord] = []
    injection_warnings: list[str] = []

    # Scan global indexes
    for cat in CATEGORIES:
        idx = kb_root / "global" / cat / "_index.yaml"
        all_records.extend(_scan_index(idx, tech_stack_keywords, kb_root, "global"))

    # Scan project indexes (if project_id provided)
    if project_id:
        for cat in CATEGORIES:
            idx = kb_root / "projects" / project_id / cat / "_index.yaml"
            all_records.extend(_scan_index(idx, tech_stack_keywords, kb_root, "project"))

    # Deduplicate by vuln_id (prefer project-level detail)
    seen: dict[str, KBRecord] = {}
    for rec in all_records:
        key = rec.vuln_id
        if key in seen:
            if rec.layer == "project":
                seen[key] = rec  # project overrides global
        else:
            seen[key] = rec

    # Read full content for matched records
    final: list[KBRecord] = []
    for rec in seen.values():
        rec = _read_full_record(rec, kb_root)
        # Update hit_count in index
        idx_path = Path(rec.file_path).parent / "_index.yaml"
        _update_hit_count(idx_path, rec.vuln_id)
        final.append(rec)

    snapshot = _compute_snapshot_hash(kb_root)

    return KBRetrievalResult(
        records=final,
        snapshot_hash=snapshot,
        injection_warnings=injection_warnings,
    )
