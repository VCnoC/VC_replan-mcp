"""E4: Unit tests for tools/kb_update.py"""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from models.schemas import (
    KBUpdateRequest,
    KBUpdateAction,
    ContentPatch,
    Vulnerability,
    Severity,
    Category,
)
from engine.kb_writer import write_vulnerabilities


def _setup_kb_with_entry(tmp_path):
    """Create a KB with one global Security entry."""
    kb = tmp_path / "test_kb"
    from tests.test_kb_writer import _make_vuln
    write_vulnerabilities(
        [_make_vuln(severity=Severity.S0)],
        "audit-001", kb, ["python"],
    )
    return kb


class TestKBUpdateActions:
    @patch("tools.kb_update.load_settings")
    def test_link_action(self, mock_settings, tmp_path):
        kb = _setup_kb_with_entry(tmp_path)
        mock_settings.return_value.kb_path = kb

        from tools.kb_update import execute
        req = KBUpdateRequest(
            action=KBUpdateAction.link,
            global_vuln_id="V001",
            global_category="Security",
            project_id="proj-x",
            project_kb_file="projects/proj-x/Security/test.md",
        )
        resp = execute(req)
        assert resp.status == "success"

    @patch("tools.kb_update.load_settings")
    def test_unlink_action(self, mock_settings, tmp_path):
        kb = _setup_kb_with_entry(tmp_path)
        mock_settings.return_value.kb_path = kb

        from tools.kb_update import execute

        # First link
        link_req = KBUpdateRequest(
            action=KBUpdateAction.link,
            global_vuln_id="V001",
            global_category="Security",
            project_id="proj-x",
            project_kb_file="projects/proj-x/Security/test.md",
        )
        execute(link_req)

        # Then unlink
        unlink_req = KBUpdateRequest(
            action=KBUpdateAction.unlink,
            global_vuln_id="V001",
            global_category="Security",
            project_id="proj-x",
        )
        resp = execute(unlink_req)
        assert resp.status == "success"

    @patch("tools.kb_update.load_settings")
    def test_update_content_action(self, mock_settings, tmp_path):
        kb = _setup_kb_with_entry(tmp_path)
        mock_settings.return_value.kb_path = kb

        from tools.kb_update import execute
        req = KBUpdateRequest(
            action=KBUpdateAction.update_content,
            global_vuln_id="V001",
            global_category="Security",
            content_patch=ContentPatch(
                update_keywords=["new-keyword"],
                update_tech_stack=["FastAPI"],
            ),
        )
        resp = execute(req)
        assert resp.status == "success"

    @patch("tools.kb_update.load_settings")
    def test_refresh_links_action(self, mock_settings, tmp_path):
        kb = _setup_kb_with_entry(tmp_path)
        mock_settings.return_value.kb_path = kb

        from tools.kb_update import execute
        req = KBUpdateRequest(action=KBUpdateAction.refresh_links)
        resp = execute(req)
        assert resp.status == "success"

    @patch("tools.kb_update.load_settings")
    def test_cleanup_stale_action(self, mock_settings, tmp_path):
        kb = _setup_kb_with_entry(tmp_path)
        mock_settings.return_value.kb_path = kb

        from tools.kb_update import execute
        req = KBUpdateRequest(action=KBUpdateAction.cleanup_stale)
        resp = execute(req)
        assert resp.status == "success"

    @patch("tools.kb_update.load_settings")
    def test_nonexistent_vuln_fails(self, mock_settings, tmp_path):
        kb = _setup_kb_with_entry(tmp_path)
        mock_settings.return_value.kb_path = kb

        from tools.kb_update import execute
        req = KBUpdateRequest(
            action=KBUpdateAction.link,
            global_vuln_id="V999",
            global_category="Security",
            project_id="proj-x",
            project_kb_file="test.md",
        )
        resp = execute(req)
        assert resp.status == "failed"
