"""Knowledge-base auto-writer — dual-layer write with dedup + reverse links.

After each audit, this module:
1. Filters vulnerabilities by severity (S0/S1 always, S2 optional, S3 never)
2. Splits content: generic knowledge → global/, project context → projects/
3. Deduplicates via _index.yaml keyword overlap (>70%)
4. Maintains reverse links (global → project)
5. Ensures transactional consistency (.md first, then _index.yaml)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from models.schemas import Vulnerability, Severity

logger = logging.getLogger("engine.kb_writer")

# Categories matching the 7-dimension matrix
CATEGORIES = [
    "Security", "Performance", "Architecture",
    "Compatibility", "DataIntegrity", "Reliability", "Observability",
]

_DEDUP_THRESHOLD = 0.70  # keyword overlap ratio for dedup

# Safe identifier pattern for project_id (prevents path traversal)
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _validate_project_id(project_id: str) -> None:
    """Raise ValueError if project_id contains path traversal characters."""
    if not _SAFE_ID_RE.match(project_id) or ".." in project_id:
        raise ValueError(
            f"Invalid project_id '{project_id}': must match [a-zA-Z0-9._-]+ "
            f"and must not contain '..'"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(text: str, max_len: int = 40) -> str:
    """Create a filesystem-safe slug from text."""
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return slug[:max_len]


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _empty_index(category: str) -> dict:
    """Return a blank _index.yaml structure."""
    return {
        "entries": [],
        "metadata": {
            "category": category,
            "total_entries": 0,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        },
    }


def _load_index(path: Path, category: str) -> dict:
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and "entries" in data:
                return data
        except Exception as exc:
            logger.warning("Corrupt index %s: %s", path, exc)
    return _empty_index(category)


def _save_index(path: Path, data: dict) -> None:
    data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    data["metadata"]["total_entries"] = len(data.get("entries", []))
    path.write_text(
        yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


def _keyword_overlap(a: list[str], b: list[str]) -> float:
    if not a or not b:
        return 0.0
    sa = {k.lower() for k in a}
    sb = {k.lower() for k in b}
    return len(sa & sb) / max(len(sb), 1)


# ---------------------------------------------------------------------------
# Content generation helpers
# ---------------------------------------------------------------------------

def _build_global_md(vuln: Vulnerability, audit_id: str) -> str:
    """Build generic knowledge .md (no project-specific info)."""
    evidence_lines = ""
    for ev in vuln.evidence:
        evidence_lines += f"- [{ev.summary}]({ev.source}) ({ev.type.value})\n"

    actions = "\n".join(f"{i+1}. {a}" for i, a in enumerate(vuln.required_actions))

    return f"""---
vuln_id: {vuln.id}
severity: {vuln.severity.value}
category: {vuln.category.value}
title: {vuln.title}
date: {_today()}
audit_ids:
  - {audit_id}
---

# {vuln.title}

## Trigger Scenario
{vuln.trigger_scenario}

## Impact
{vuln.impact}

## Required Actions
{actions}

## Evidence
{evidence_lines}
"""


def _build_project_md(
    vuln: Vulnerability, audit_id: str, project_id: str, global_ref: str,
) -> str:
    """Build project-specific .md with link to global record."""
    actions = "\n".join(f"{i+1}. {a}" for i, a in enumerate(vuln.required_actions))

    return f"""---
vuln_id: {vuln.id}
severity: {vuln.severity.value}
category: {vuln.category.value}
title: {vuln.title}
project_id: {project_id}
date: {_today()}
audit_ids:
  - {audit_id}
global_ref: {global_ref}
---

# {vuln.title}

## Trigger Scenario
{vuln.trigger_scenario}

## Impact
{vuln.impact}

## Project Fix Actions
{actions}

## Related Global Knowledge
→ [{vuln.title} (global)]({global_ref})
"""


def _build_index_entry(vuln: Vulnerability, filename: str, audit_id: str) -> dict:
    return {
        "file": filename,
        "vuln_id": vuln.id,
        "severity": vuln.severity.value,
        "title": vuln.title,
        "tech_stack": [],  # populated by caller
        "keywords": [],    # populated by caller
        "date": _today(),
        "audit_ids": [audit_id],
        "hit_count": 0,
        "lifecycle": "Active",
    }


# ---------------------------------------------------------------------------
# Core write logic
# ---------------------------------------------------------------------------

def _find_duplicate(index_data: dict, vuln: Vulnerability) -> dict | None:
    """Find an existing entry by vuln_id (exact) or keyword overlap >70%."""
    vuln_kw = [vuln.category.value.lower(), _slugify(vuln.title)]
    for entry in index_data.get("entries", []):
        # Exact match on vuln_id takes priority
        if entry.get("vuln_id") == vuln.id:
            return entry
        entry_kw = entry.get("keywords", []) + entry.get("tech_stack", [])
        if _keyword_overlap(entry_kw, vuln_kw) > _DEDUP_THRESHOLD:
            return entry
    return None


def _write_global(
    vuln: Vulnerability,
    audit_id: str,
    kb_root: Path,
    tech_keywords: list[str],
) -> str:
    """Write/update global KB record. Returns relative path to .md file."""
    cat_dir = kb_root / "global" / vuln.category.value
    _ensure_dir(cat_dir)
    idx_path = cat_dir / "_index.yaml"
    idx_data = _load_index(idx_path, vuln.category.value)

    dup = _find_duplicate(idx_data, vuln)
    if dup:
        # Append audit_id to existing record
        if audit_id not in dup.get("audit_ids", []):
            dup.setdefault("audit_ids", []).append(audit_id)
        _save_index(idx_path, idx_data)
        return f"global/{vuln.category.value}/{dup['file']}"

    # New record
    filename = f"{_today()}_{vuln.id}_{_slugify(vuln.title)}.md"
    md_path = cat_dir / filename
    md_content = _build_global_md(vuln, audit_id)

    # Transaction: write .md first
    md_path.write_text(md_content, encoding="utf-8")

    # Then update index
    entry = _build_index_entry(vuln, filename, audit_id)
    entry["tech_stack"] = tech_keywords
    entry["keywords"] = list({vuln.category.value.lower(), _slugify(vuln.title)} | {k.lower() for k in tech_keywords})
    idx_data["entries"].append(entry)

    try:
        _save_index(idx_path, idx_data)
    except Exception as exc:
        # Rollback .md on index failure
        logger.error("Index update failed, rolling back %s: %s", md_path, exc)
        md_path.unlink(missing_ok=True)
        raise

    return f"global/{vuln.category.value}/{filename}"


def _write_project(
    vuln: Vulnerability,
    audit_id: str,
    kb_root: Path,
    project_id: str,
    global_ref: str,
    tech_keywords: list[str],
) -> str:
    """Write/update project KB record. Returns relative path."""
    _validate_project_id(project_id)
    cat_dir = kb_root / "projects" / project_id / vuln.category.value
    _ensure_dir(cat_dir)
    idx_path = cat_dir / "_index.yaml"
    idx_data = _load_index(idx_path, vuln.category.value)

    dup = _find_duplicate(idx_data, vuln)
    if dup:
        if audit_id not in dup.get("audit_ids", []):
            dup.setdefault("audit_ids", []).append(audit_id)
        _save_index(idx_path, idx_data)
        return f"projects/{project_id}/{vuln.category.value}/{dup['file']}"

    filename = f"{_today()}_{vuln.id}_{_slugify(vuln.title)}.md"
    md_path = cat_dir / filename
    md_content = _build_project_md(vuln, audit_id, project_id, global_ref)

    md_path.write_text(md_content, encoding="utf-8")

    entry = _build_index_entry(vuln, filename, audit_id)
    entry["tech_stack"] = tech_keywords
    entry["keywords"] = list({vuln.category.value.lower(), _slugify(vuln.title)} | {k.lower() for k in tech_keywords})
    entry["project_id"] = project_id
    idx_data["entries"].append(entry)

    try:
        _save_index(idx_path, idx_data)
    except Exception as exc:
        logger.error("Index update failed, rolling back %s: %s", md_path, exc)
        md_path.unlink(missing_ok=True)
        raise

    return f"projects/{project_id}/{vuln.category.value}/{filename}"


def _add_reverse_link(
    kb_root: Path,
    global_ref: str,
    project_id: str,
    project_ref: str,
    vuln: Vulnerability,
) -> None:
    """Add reverse link from global _index.yaml to project record."""
    parts = global_ref.split("/")
    if len(parts) < 3:
        return
    cat = parts[1]
    idx_path = kb_root / "global" / cat / "_index.yaml"
    if not idx_path.exists():
        return
    try:
        idx_data = yaml.safe_load(idx_path.read_text(encoding="utf-8"))
        for entry in idx_data.get("entries", []):
            if entry.get("vuln_id") == vuln.id:
                rp = entry.setdefault("related_projects", [])
                link = {"project_id": project_id, "file": project_ref}
                if link not in rp:
                    rp.append(link)
                break
        _save_index(idx_path, idx_data)
    except Exception as exc:
        logger.warning("Failed to add reverse link: %s", exc)


# ---------------------------------------------------------------------------
# Snapshot hash
# ---------------------------------------------------------------------------

def compute_snapshot_hash(kb_root: Path) -> str:
    """SHA-256 over all _index.yaml for audit reproducibility."""
    import hashlib
    h = hashlib.sha256()
    for idx in sorted(kb_root.rglob("_index.yaml")):
        try:
            h.update(idx.read_bytes())
        except Exception:
            pass
    return f"sha256:{h.hexdigest()}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    audit_id: str,
    kb_path: Path,
    tech_keywords: list[str],
    project_id: str | None = None,
    write_s2: bool = True,
) -> dict[str, Any]:
    """Write audit results to KB. Returns summary of operations."""
    kb_root = Path(kb_path).resolve()
    written_global: list[str] = []
    written_project: list[str] = []
    skipped: list[str] = []

    # Validate project_id before any writes
    if project_id:
        _validate_project_id(project_id)

    for vuln in vulnerabilities:
        # Filter by severity
        if vuln.severity == Severity.S3:
            skipped.append(vuln.id)
            continue
        if vuln.severity == Severity.S2 and not write_s2:
            skipped.append(vuln.id)
            continue

        # Write global
        global_ref = _write_global(vuln, audit_id, kb_root, tech_keywords)
        written_global.append(global_ref)

        # Write project (if project_id provided)
        if project_id:
            project_ref = _write_project(
                vuln, audit_id, kb_root, project_id, global_ref, tech_keywords,
            )
            written_project.append(project_ref)
            _add_reverse_link(kb_root, global_ref, project_id, project_ref, vuln)

    return {
        "written_global": written_global,
        "written_project": written_project,
        "skipped": skipped,
        "snapshot_hash": compute_snapshot_hash(kb_root),
    }
