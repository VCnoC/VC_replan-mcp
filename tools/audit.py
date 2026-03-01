"""MCP Tool: mcp_audit_architecture — 7-dimension architecture review.

Pipeline: sanitizer → researcher + kb_retriever (parallel)
         → prompt_builder → reviewer → parser → kb_writer
"""

from __future__ import annotations

import asyncio
import logging

from config import load_settings
from engine.sanitizer import sanitize
from engine.researcher import research, WebSource
from engine.kb_retriever import retrieve as kb_retrieve
from engine.prompt_builder import build_prompt
from engine.reviewer import review
from engine.parser import parse
from engine.kb_writer import write_vulnerabilities
from models.schemas import (
    AuditRequest,
    AuditResponse,
    WebSourceHash,
)

logger = logging.getLogger("tools.audit")


async def execute(request: AuditRequest) -> AuditResponse:
    """Run the full audit pipeline."""
    settings = load_settings()

    # ⓪ Sanitize all untrusted inputs
    sol = sanitize(request.proposed_solution)
    ctx = sanitize(request.relevant_local_context)

    injection_warnings = sol.injection_hits + ctx.injection_hits
    if injection_warnings:
        logger.warning("Injection patterns found in input: %s", injection_warnings)

    # ① + ② Parallel: web research + KB retrieval
    research_task = asyncio.create_task(research(
        keywords=request.tech_stack_keywords,
        api_key=settings.unifuncs_api_key,
    ))
    kb_result = await asyncio.get_running_loop().run_in_executor(
        None,
        kb_retrieve,
        settings.kb_path,
        request.tech_stack_keywords,
        request.project_id,
        settings,
    )

    research_result = await research_task

    # Collect injection warnings from all sources
    injection_warnings.extend(research_result.injection_warnings)
    injection_warnings.extend(kb_result.injection_warnings)

    # Build KB text for prompt
    kb_text_parts = []
    for rec in kb_result.records:
        if rec.content:
            kb_text_parts.append(f"### [{rec.severity}] {rec.title}\n{rec.content}")
    kb_text = "\n\n".join(kb_text_parts)

    # ③ Build super-prompt
    system_prompt, user_prompt = build_prompt(
        proposed_solution=sol.cleaned,
        local_context=ctx.cleaned,
        web_intelligence=research_result.sanitized_text,
        kb_records=kb_text,
    )

    # ④ Matrix scan (Reviewer model)
    raw_response, is_valid_json = await review(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        api_base=settings.reviewer_api_base,
        api_key=settings.reviewer_api_key,
        model=settings.reviewer_model,
    )

    # ⑤ Parse structured output
    web_hashes = [
        WebSourceHash(url=s.url, content_hash=s.content_hash)
        for s in research_result.sources
        if s.content_hash
    ]

    audit_response = parse(
        raw_response=raw_response,
        is_valid_json=is_valid_json,
        reviewer_model=settings.reviewer_model,
        reviewer_api_base=settings.reviewer_api_base,
        prompt_template_version=settings.prompt_template_version,
        kb_snapshot_hash=kb_result.snapshot_hash,
        web_source_hashes=web_hashes,
        search_keywords=request.tech_stack_keywords,
        kb_records_found=len(kb_result.records),
        web_sources_consulted=len(research_result.sources),
    )

    # ⑥ KB auto-write
    if settings.kb_auto_write and audit_response.vulnerabilities:
        try:
            write_vulnerabilities(
                vulnerabilities=audit_response.vulnerabilities,
                audit_id=audit_response.audit_metadata.audit_id,
                kb_path=settings.kb_path,
                tech_keywords=request.tech_stack_keywords,
                project_id=request.project_id,
                write_s2=settings.kb_write_s2,
            )
        except Exception as exc:
            logger.error("KB write failed (non-fatal): %s", exc)

    # ⑦ Return
    return audit_response
