"""Intelligence gathering via UniFuncs web-search + web-reader APIs.

Searches by tech_stack_keywords in parallel, then deep-reads the top
results.  All returned content is sanitized before use.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from engine.sanitizer import sanitize, SanitizeResult

logger = logging.getLogger("engine.researcher")

# API endpoints
_SEARCH_URL = "https://api.unifuncs.com/api/web-search/search"
_READER_URL = "https://api.unifuncs.com/api/web-reader/read"

# Limits
_SEARCH_COUNT = 10      # results per keyword (UniFuncs API default)
_MAX_READ = 3           # pages to deep-read per keyword
_READ_MAX_WORDS = None  # no word limit (full content)
_READ_TIMEOUT_MS = 120_000


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WebSource:
    url: str
    title: str = ""
    snippet: str = ""
    content: str = ""
    content_hash: str = ""


@dataclass
class ResearchResult:
    """Aggregated research output."""
    sources: list[WebSource] = field(default_factory=list)
    sanitized_text: str = ""
    search_keywords: list[str] = field(default_factory=list)
    injection_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Low-level HTTP helpers (stdlib only — no extra deps)
# ---------------------------------------------------------------------------

def _post_json(url: str, body: dict, api_key: str, timeout: int = 60) -> dict | str:
    """POST JSON and return parsed response."""
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",  # UniFuncs API requires Authorization header
    }
    req = Request(url, data=payload, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
    except HTTPError as exc:
        logger.warning("HTTP %d from %s", exc.code, url)
        return {}
    except URLError as exc:
        logger.warning("Network error reaching %s: %s", url, exc.reason)
        return {}
    except Exception as exc:
        logger.warning("Request to %s failed: %s", url, exc)
        return {}


# ---------------------------------------------------------------------------
# Search + Read
# ---------------------------------------------------------------------------

def _search(keyword: str, api_key: str) -> list[dict]:
    """Return raw search result items for *keyword*."""
    body = {
        "query": keyword,
        "apiKey": api_key,
        "count": _SEARCH_COUNT,
        "format": "json",
    }
    resp = _post_json(_SEARCH_URL, body, api_key)

    # Debug logging
    logger.info(f"Search for '{keyword}': response type={type(resp)}")
    if isinstance(resp, dict):
        logger.info(f"Response keys: {list(resp.keys())}")

        # UniFuncs API returns: {"code": 0, "message": "OK", "data": {"webPages": [...]}}
        if resp.get("code") == 0:
            data = resp.get("data", {})
            if isinstance(data, dict):
                web_pages = data.get("webPages", [])
                if isinstance(web_pages, list):
                    logger.info(f"Found {len(web_pages)} results for '{keyword}'")
                    return web_pages
                else:
                    logger.warning(f"webPages field is not a list for '{keyword}': {type(web_pages)}")
            else:
                logger.warning(f"data field is not a dict for '{keyword}': {type(data)}")
        else:
            logger.warning(f"API returned error code {resp.get('code')} for '{keyword}': {resp.get('message')}")
    else:
        logger.warning(f"Unexpected response type for '{keyword}': {resp}")
    return []


def _read_page(url: str, api_key: str) -> str:
    """Deep-read a single URL and return markdown content."""
    body = {
        "url": url,
        "apiKey": api_key,
        "format": "md",  # UniFuncs API default format
        "liteMode": False,  # Full content mode
        "readTimeout": _READ_TIMEOUT_MS,
    }
    # Only add maxWords if it's set (None means no limit)
    if _READ_MAX_WORDS is not None:
        body["maxWords"] = _READ_MAX_WORDS

    logger.info(f"Calling web-reader API for: {url}")
    resp = _post_json(_READER_URL, body, api_key, timeout=180)

    if isinstance(resp, str):
        logger.info(f"Got string response, length: {len(resp)}")
        return resp
    if isinstance(resp, dict):
        content = resp.get("content", resp.get("text", str(resp)))
        logger.info(f"Got dict response, content length: {len(content)}")
        return content

    logger.warning(f"Unexpected response type from web-reader: {type(resp)}")
    return ""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def research(
    keywords: list[str],
    api_key: str,
) -> ResearchResult:
    """Run search + deep-read for each keyword (I/O in thread pool).

    Returns a *ResearchResult* with sanitized content ready for the prompt.
    """
    loop = asyncio.get_running_loop()
    all_sources: list[WebSource] = []
    seen_urls: set[str] = set()
    injection_warnings: list[str] = []

    for kw in keywords:
        items = await loop.run_in_executor(None, _search, kw, api_key)
        logger.info(f"Keyword '{kw}': got {len(items)} search results")
        urls_to_read: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            # UniFuncs API returns: {"name": "...", "url": "...", "snippet": "...", "summary": "..."}
            url = item.get("url", "")
            title = item.get("name", "")  # UniFuncs uses "name" not "title"
            snippet = item.get("snippet", "") or item.get("summary", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                all_sources.append(WebSource(url=url, title=title, snippet=snippet))
                if len(urls_to_read) < _MAX_READ:
                    urls_to_read.append(url)

        # Deep-read top pages
        logger.info(f"Keyword '{kw}': will deep-read {len(urls_to_read)} URLs")
        for url in urls_to_read:
            logger.info(f"Deep-reading: {url}")
            raw_content = await loop.run_in_executor(None, _read_page, url, api_key)
            if raw_content:
                logger.info(f"Successfully read {len(raw_content)} chars from {url}")
                result = sanitize(raw_content)
                if result.has_injections:
                    injection_warnings.extend(result.injection_hits)
                    logger.warning("Injection detected in %s: %s", url, result.injection_hits)
                # Find matching source and update
                for src in all_sources:
                    if src.url == url:
                        src.content = result.cleaned
                        src.content_hash = f"sha256:{_sha256(raw_content)}"
                        break

    # Build aggregated sanitized text
    parts: list[str] = []
    for src in all_sources:
        if src.content:
            parts.append(f"## Source: {src.title} ({src.url})\n{src.content}")
        elif src.snippet:
            parts.append(f"## Source: {src.title} ({src.url})\n{src.snippet}")

    return ResearchResult(
        sources=all_sources,
        sanitized_text="\n\n".join(parts),
        search_keywords=list(keywords),
        injection_warnings=injection_warnings,
    )
