"""Global configuration — loads all settings from .env with API Key masking."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Bootstrap: load .env from project root
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(_PROJECT_ROOT / ".env")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mask_key(raw: str | None) -> str:
    """Mask an API key for safe logging: sk-abc...xyz → sk-****xyz"""
    if not raw:
        return "<unset>"
    if len(raw) <= 8:
        return "****"
    return f"{raw[:3]}****{raw[-4:]}"


def _require_env(name: str) -> str:
    """Return env var or raise with a helpful message."""
    val = os.getenv(name)
    if not val:
        raise EnvironmentError(
            f"Missing required environment variable: {name}. "
            f"Copy .env.example → .env and fill in the values."
        )
    return val


def _optional_env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _bool_env(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    """Immutable application settings loaded once from environment."""

    # Reviewer model (OpenAI-compatible)
    reviewer_api_base: str
    reviewer_api_key: str
    reviewer_model: str

    # UniFuncs search API
    unifuncs_api_key: str

    # Knowledge base
    kb_path: Path
    kb_cli: str
    kb_auto_write: bool
    kb_write_s2: bool

    # Derived / internal
    project_root: Path = field(default=_PROJECT_ROOT)
    tool_version: str = field(default="VC_replan-mcp@0.1.6")
    prompt_template_version: str = field(default="v0.1.0")
    sanitizer_version: str = field(default="v0.1.0")

    # --- safe logging ---------------------------------------------------
    @property
    def reviewer_api_key_masked(self) -> str:
        return _mask_key(self.reviewer_api_key)

    @property
    def unifuncs_api_key_masked(self) -> str:
        return _mask_key(self.unifuncs_api_key)

    def log_summary(self) -> str:
        return (
            f"Settings(\n"
            f"  reviewer_api_base={self.reviewer_api_base},\n"
            f"  reviewer_api_key={self.reviewer_api_key_masked},\n"
            f"  reviewer_model={self.reviewer_model},\n"
            f"  unifuncs_api_key={self.unifuncs_api_key_masked},\n"
            f"  kb_path={self.kb_path},\n"
            f"  kb_cli={self.kb_cli},\n"
            f"  kb_auto_write={self.kb_auto_write},\n"
            f"  kb_write_s2={self.kb_write_s2},\n"
            f")"
        )


def load_settings() -> Settings:
    """Build a *Settings* instance from the current environment."""
    return Settings(
        reviewer_api_base=_require_env("REVIEWER_API_BASE"),
        reviewer_api_key=_require_env("REVIEWER_API_KEY"),
        reviewer_model=_optional_env("REVIEWER_MODEL", "deepseek-chat"),
        unifuncs_api_key=_require_env("UNIFUNCS_API_KEY"),
        kb_path=Path(_optional_env("KB_PATH", str(Path.home() / ".claude" / "VC_planning_mcp_kb"))),
        kb_cli=_optional_env("KB_CLI", "claude"),
        kb_auto_write=_bool_env("KB_AUTO_WRITE", True),
        kb_write_s2=_bool_env("KB_WRITE_S2", True),
    )
