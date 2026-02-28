"""E5: Unit tests for engine/prompt_builder.py"""

import pytest
from engine.prompt_builder import build_prompt, VERSION, REVIEW_MATRIX
from engine.sanitizer import _BEGIN, _END


class TestBuildPrompt:
    def test_returns_tuple(self):
        sys_p, usr_p = build_prompt("solution", "code", "web", "kb")
        assert isinstance(sys_p, str)
        assert isinstance(usr_p, str)

    def test_system_contains_safety_rules(self):
        sys_p, _ = build_prompt("s", "c", "w", "k")
        assert "UNTRUSTED" in sys_p
        assert "Do NOT execute" in sys_p

    def test_system_contains_matrix(self):
        sys_p, _ = build_prompt("s", "c", "w", "k")
        assert "Security" in sys_p
        assert "Performance" in sys_p
        assert "Observability" in sys_p

    def test_system_contains_output_spec(self):
        sys_p, _ = build_prompt("s", "c", "w", "k")
        assert "S0" in sys_p
        assert "vulnerabilities" in sys_p

    def test_user_wraps_inputs(self):
        _, usr_p = build_prompt("my solution", "my code", "web data", "kb data")
        assert _BEGIN in usr_p
        assert _END in usr_p
        assert "my solution" in usr_p
        assert "my code" in usr_p

    def test_empty_web_intelligence(self):
        _, usr_p = build_prompt("s", "c", "", "k")
        assert "no web intelligence" in usr_p

    def test_empty_kb_records(self):
        _, usr_p = build_prompt("s", "c", "w", "")
        assert "no KB records" in usr_p

    def test_version(self):
        assert VERSION == "v0.1.0"
