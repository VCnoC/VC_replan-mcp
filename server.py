"""VC_replan-mcp — Architecture Review MCP Server.

Registers two tools:
  - mcp_audit_architecture: 7-dimension architecture review
  - mcp_kb_update: Knowledge base maintenance
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from mcp.server.fastmcp import FastMCP

from config import load_settings
from models.schemas import (
    AuditRequest,
    AuditResponse,
    KBUpdateRequest,
    KBUpdateResponse,
)
from tools.audit import execute as audit_execute
from tools.kb_update import execute as kb_update_execute

# ---------------------------------------------------------------------------
# Logging setup (API keys masked via config)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("server")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "VC_replan-mcp",
    json_response=True,
)


@mcp.tool()
async def mcp_audit_architecture(
    proposed_solution: str,
    tech_stack_keywords: list[str],
    relevant_local_context: str,
    project_id: str | None = None,
) -> dict:
    """Architecture review — 7-dimension matrix scan with web intelligence and KB history.

    Args:
        proposed_solution: The technical solution text to review.
        tech_stack_keywords: Core tech/framework keywords for intelligence retrieval.
        relevant_local_context: Relevant local code snippets (caller must supply).
        project_id: Optional project identifier for project-level KB.

    Returns:
        Structured vulnerability list with severity, matrix coverage, and audit metadata.
    """
    request = AuditRequest(
        proposed_solution=proposed_solution,
        tech_stack_keywords=tech_stack_keywords,
        relevant_local_context=relevant_local_context,
        project_id=project_id,
    )
    result = await audit_execute(request)
    return result.model_dump(mode="json")


@mcp.tool()
def mcp_kb_update(
    action: str,
    global_vuln_id: str | None = None,
    global_category: str | None = None,
    project_id: str | None = None,
    project_kb_file: str | None = None,
    content_patch: dict | None = None,
) -> dict:
    """Knowledge base maintenance — manage global ↔ project links and content.

    Args:
        action: One of: link, unlink, refresh_links, update_content, cleanup_stale.
        global_vuln_id: Target vulnerability ID (for link/unlink/update_content).
        global_category: Category directory (e.g. Security).
        project_id: Target project ID (for link/unlink).
        project_kb_file: Project KB file relative path (for link).
        content_patch: Content update patch (for update_content).

    Returns:
        Operation result with affected entries and summary.
    """
    from models.schemas import ContentPatch, KBUpdateAction

    patch = None
    if content_patch:
        patch = ContentPatch(**content_patch)

    request = KBUpdateRequest(
        action=KBUpdateAction(action),
        global_vuln_id=global_vuln_id,
        global_category=global_category,
        project_id=project_id,
        project_kb_file=project_kb_file,
        content_patch=patch,
    )
    result = kb_update_execute(request)
    return result.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    """Entry point for uvx / console_scripts."""
    try:
        settings = load_settings()
        logger.info("Starting VC_replan-mcp server")
        logger.info(settings.log_summary())
    except Exception as exc:
        logger.warning("Config not fully loaded (will retry on first call): %s", exc)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
