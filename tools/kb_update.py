"""MCP Tool: mcp_kb_update — Knowledge base maintenance.

Manages global ↔ project reverse links, content updates, and cleanup.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from config import load_settings
from models.schemas import (
    Category,
    KBUpdateRequest,
    KBUpdateResponse,
    KBUpdateAction,
    AffectedEntry,
)
from engine.sanitizer import sanitize

logger = logging.getLogger("tools.kb_update")

# Valid category names (whitelist)
_VALID_CATEGORIES = {c.value for c in Category}


def _load_index(path: Path) -> dict:
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and "entries" in data:
                return data
        except Exception:
            pass
    return {"entries": [], "metadata": {}}


def _save_index(path: Path, data: dict) -> None:
    from datetime import datetime, timezone
    data.setdefault("metadata", {})
    data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    data["metadata"]["total_entries"] = len(data.get("entries", []))
    path.write_text(
        yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


def _find_entry(idx_data: dict, vuln_id: str) -> dict | None:
    for entry in idx_data.get("entries", []):
        if entry.get("vuln_id") == vuln_id:
            return entry
    return None


def _validate_category(category: str | None) -> str:
    """Validate global_category against the Category enum whitelist."""
    if not category or category not in _VALID_CATEGORIES:
        raise ValueError(
            f"Invalid category '{category}': must be one of {_VALID_CATEGORIES}"
        )
    return category


def _safe_path(kb_root: Path, candidate: Path) -> bool:
    """Ensure candidate is inside kb_root (whitelist enforcement)."""
    try:
        candidate.resolve().relative_to(kb_root.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------

def _action_link(req: KBUpdateRequest, kb_root: Path) -> KBUpdateResponse:
    """Add global → project reverse link."""
    _validate_category(req.global_category)
    idx_path = kb_root / "global" / req.global_category / "_index.yaml"
    if not _safe_path(kb_root, idx_path):
        return KBUpdateResponse(
            status="failed", action=req.action,
            summary=f"Path safety check failed for {req.global_category}",
        )
    idx_data = _load_index(idx_path)
    entry = _find_entry(idx_data, req.global_vuln_id)
    if not entry:
        return KBUpdateResponse(
            status="failed", action=req.action,
            summary=f"Entry {req.global_vuln_id} not found in global/{req.global_category}",
        )
    rp = entry.setdefault("related_projects", [])
    link = {"project_id": req.project_id, "file": req.project_kb_file}
    if link not in rp:
        rp.append(link)
    _save_index(idx_path, idx_data)
    return KBUpdateResponse(
        status="success", action=req.action,
        affected_entries=[AffectedEntry(
            global_file=str(idx_path),
            change=f"added link to {req.project_id}",
        )],
        summary=f"Linked {req.global_vuln_id} → {req.project_id}",
    )


def _action_unlink(req: KBUpdateRequest, kb_root: Path) -> KBUpdateResponse:
    """Remove global → project reverse link."""
    _validate_category(req.global_category)
    idx_path = kb_root / "global" / req.global_category / "_index.yaml"
    if not _safe_path(kb_root, idx_path):
        return KBUpdateResponse(
            status="failed", action=req.action,
            summary=f"Path safety check failed for {req.global_category}",
        )
    idx_data = _load_index(idx_path)
    entry = _find_entry(idx_data, req.global_vuln_id)
    if not entry:
        return KBUpdateResponse(
            status="failed", action=req.action,
            summary=f"Entry {req.global_vuln_id} not found",
        )
    rp = entry.get("related_projects", [])
    entry["related_projects"] = [
        lnk for lnk in rp if lnk.get("project_id") != req.project_id
    ]
    _save_index(idx_path, idx_data)
    return KBUpdateResponse(
        status="success", action=req.action,
        affected_entries=[AffectedEntry(
            global_file=str(idx_path),
            change=f"removed link to {req.project_id}",
        )],
        summary=f"Unlinked {req.global_vuln_id} ↛ {req.project_id}",
    )


def _action_refresh_links(kb_root: Path) -> KBUpdateResponse:
    """Scan all global entries and validate reverse links."""
    affected: list[AffectedEntry] = []
    stale_found = 0
    stale_cleaned = 0
    for idx_path in kb_root.rglob("global/*/_index.yaml"):
        idx_data = _load_index(idx_path)
        changed = False
        for entry in idx_data.get("entries", []):
            rp = entry.get("related_projects", [])
            valid = []
            for lnk in rp:
                target = kb_root / lnk.get("file", "")
                if target.exists():
                    valid.append(lnk)
                else:
                    stale_found += 1
                    stale_cleaned += 1
                    changed = True
            if len(valid) != len(rp):
                entry["related_projects"] = valid
        if changed:
            _save_index(idx_path, idx_data)
            affected.append(AffectedEntry(
                global_file=str(idx_path), change="refreshed links",
            ))
    return KBUpdateResponse(
        status="success", action=KBUpdateAction.refresh_links,
        affected_entries=affected,
        stale_links_found=stale_found,
        stale_links_cleaned=stale_cleaned,
        summary=f"Refreshed links: {stale_cleaned} stale removed",
    )


def _action_update_content(req: KBUpdateRequest, kb_root: Path) -> KBUpdateResponse:
    """Update global entry content."""
    _validate_category(req.global_category)
    idx_path = kb_root / "global" / req.global_category / "_index.yaml"
    if not _safe_path(kb_root, idx_path):
        return KBUpdateResponse(
            status="failed", action=req.action,
            summary=f"Path safety check failed for {req.global_category}",
        )
    idx_data = _load_index(idx_path)
    entry = _find_entry(idx_data, req.global_vuln_id)
    if not entry:
        return KBUpdateResponse(
            status="failed", action=req.action,
            summary=f"Entry {req.global_vuln_id} not found",
        )
    patch = req.content_patch
    if patch:
        if patch.update_keywords:
            kw = set(entry.get("keywords", []))
            kw.update(patch.update_keywords)
            entry["keywords"] = sorted(kw)
        if patch.update_tech_stack:
            ts = set(entry.get("tech_stack", []))
            ts.update(patch.update_tech_stack)
            entry["tech_stack"] = sorted(ts)
        if patch.append_section:
            sanitized = sanitize(patch.append_section)
            md_path = idx_path.parent / entry.get("file", "")
            if md_path.exists() and _safe_path(kb_root, md_path):
                content = md_path.read_text(encoding="utf-8")
                content += f"\n\n{sanitized.cleaned}\n"
                md_path.write_text(content, encoding="utf-8")
    _save_index(idx_path, idx_data)
    return KBUpdateResponse(
        status="success", action=req.action,
        affected_entries=[AffectedEntry(
            global_file=str(idx_path),
            change=f"updated content for {req.global_vuln_id}",
        )],
        summary=f"Updated {req.global_vuln_id}",
    )


def _action_cleanup_stale(kb_root: Path) -> KBUpdateResponse:
    """Remove stale reverse links (target file doesn't exist)."""
    return _action_refresh_links(kb_root)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def execute(request: KBUpdateRequest) -> KBUpdateResponse:
    """Execute a KB maintenance action."""
    settings = load_settings()
    kb_root = Path(settings.kb_path).resolve()

    handlers = {
        KBUpdateAction.link: lambda: _action_link(request, kb_root),
        KBUpdateAction.unlink: lambda: _action_unlink(request, kb_root),
        KBUpdateAction.refresh_links: lambda: _action_refresh_links(kb_root),
        KBUpdateAction.update_content: lambda: _action_update_content(request, kb_root),
        KBUpdateAction.cleanup_stale: lambda: _action_cleanup_stale(kb_root),
    }

    handler = handlers.get(request.action)
    if not handler:
        return KBUpdateResponse(
            status="failed", action=request.action,
            summary=f"Unknown action: {request.action}",
        )

    try:
        return handler()
    except Exception as exc:
        logger.error("KB update failed: %s", exc)
        return KBUpdateResponse(
            status="failed", action=request.action,
            summary=f"Error: {exc}",
        )
