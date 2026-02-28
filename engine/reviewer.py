"""Matrix scanner — sends the super-prompt to the Reviewer model.

Uses the openai SDK with user-configured API base/key/model.
Implements retry with repair hints on JSON validation failure.
"""

from __future__ import annotations

import json
import logging

from openai import AsyncOpenAI

logger = logging.getLogger("engine.reviewer")

_MAX_RETRIES = 2


async def review(
    system_prompt: str,
    user_prompt: str,
    api_base: str,
    api_key: str,
    model: str,
) -> tuple[str, bool]:
    """Call the Reviewer model and return (raw_response, is_valid_json).

    Retries up to _MAX_RETRIES times if JSON parsing fails,
    appending a repair hint each time.
    """
    client = AsyncOpenAI(base_url=api_base, api_key=api_key)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    last_response = ""
    for attempt in range(1 + _MAX_RETRIES):
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.1,
                max_tokens=16384,
            )

            raw = resp.choices[0].message.content or ""
            last_response = raw

            # Try to parse as JSON
            # Strip markdown code fences if present (only outer fences)
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                # Remove only the first fence line and last fence line
                if lines and lines[0].strip().startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                cleaned = "\n".join(lines)

            json.loads(cleaned)
            logger.info("Reviewer returned valid JSON (attempt %d)", attempt + 1)
            return cleaned, True

        except json.JSONDecodeError as exc:
            logger.warning(
                "Invalid JSON from reviewer (attempt %d/%d): %s",
                attempt + 1, 1 + _MAX_RETRIES, exc,
            )
            if attempt < _MAX_RETRIES:
                # Append repair hint for next attempt
                messages.append({"role": "assistant", "content": last_response})
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your previous response was not valid JSON. "
                        f"Error: {exc}. "
                        f"Please output ONLY a valid JSON object matching the "
                        f"schema specified above. No markdown, no explanation."
                    ),
                })

        except Exception as exc:
            logger.error("Reviewer API call failed: %s", exc)
            last_response = f"API error: {exc}"
            break

    # All retries exhausted — return raw for regex fallback
    logger.warning("Returning raw response for regex fallback parsing")
    return last_response, False
