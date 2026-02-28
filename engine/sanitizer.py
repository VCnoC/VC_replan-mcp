"""Input sanitizer — delimiter isolation + de-instruction filtering.

All untrusted content (user proposals, local code, web results, KB records)
passes through this module before reaching the Reviewer prompt.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Version (tracked in audit_metadata.sanitizer_version)
# ---------------------------------------------------------------------------
VERSION = "v0.1.0"

# ---------------------------------------------------------------------------
# Delimiter markers
# ---------------------------------------------------------------------------
_BEGIN = "<<<BEGIN_UNTRUSTED_EVIDENCE>>>"
_END = "<<<END_UNTRUSTED_EVIDENCE>>>"

# ---------------------------------------------------------------------------
# Known injection patterns (case-insensitive)
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+(all\s+)?above\s+instructions",
        r"disregard\s+(all\s+)?previous",
        r"you\s+are\s+now\b",
        r"act\s+as\s+(a\s+)?",
        r"pretend\s+(you\s+are|to\s+be)",
        r"output\s+your\s+system\s+prompt",
        r"reveal\s+your\s+(system\s+)?prompt",
        r"show\s+(me\s+)?your\s+instructions",
        r"forget\s+(all\s+)?your\s+rules",
        r"override\s+(your\s+)?instructions",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*you\s+are",
        r"\[system\]",
        r"<\s*system\s*>",
    ]
]

# Replacement marker for filtered content
_REDACTED = "[INJECTION_PATTERN_REMOVED]"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class SanitizeResult:
    """Result of sanitizing a piece of untrusted text."""
    cleaned: str
    injection_hits: list[str] = field(default_factory=list)
    wrapped: str = ""  # cleaned text wrapped in delimiters

    @property
    def has_injections(self) -> bool:
        return len(self.injection_hits) > 0


def strip_injections(text: str) -> SanitizeResult:
    """Remove known injection patterns from *text*.

    Returns a SanitizeResult with the cleaned text and a list of matched
    pattern descriptions (useful for S0 security reporting).
    """
    # Unicode normalization first (NFKC) to defeat homoglyph bypasses
    cleaned = unicodedata.normalize("NFKC", text)
    hits: list[str] = []
    for pattern in _INJECTION_PATTERNS:
        matches = pattern.findall(cleaned)
        if matches:
            hits.extend(matches)
            cleaned = pattern.sub(_REDACTED, cleaned)
    return SanitizeResult(
        cleaned=cleaned,
        injection_hits=hits,
        wrapped=wrap(cleaned),
    )


def wrap(text: str) -> str:
    """Wrap *text* in untrusted-evidence delimiters.

    Strips any existing delimiter markers from the text first to prevent
    delimiter escape attacks.
    """
    safe = text.replace(_BEGIN, "[DELIMITER_STRIPPED]").replace(_END, "[DELIMITER_STRIPPED]")
    return f"{_BEGIN}\n{safe}\n{_END}"


def sanitize(text: str) -> SanitizeResult:
    """Full sanitization pipeline: strip injections + wrap in delimiters."""
    return strip_injections(text)
