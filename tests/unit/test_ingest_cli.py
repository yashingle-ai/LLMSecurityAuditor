import json
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from llm_auditor.cli import app
from llm_auditor.render import safe
from scripts.generate_traffic import CONVERSATIONS

REPO_ROOT = Path(__file__).parents[2]
EXAMPLE_SCOPE = REPO_ROOT / "configs" / "audit_scope.example.yaml"
PLANTED_KEY = "acme_live_9fK2xQ7mRb4TzW1nLp8VcYe3"
TRAFFIC_RUNS = sum(len(messages) for _, messages in CONVERSATIONS)

runner = CliRunner()


@pytest.fixture(autouse=True)
def wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("llm_auditor.cli.console", Console(width=200))


def test_ingest_dump_lists_the_demo_apps_artifacts() -> None:
    result = runner.invoke(app, ["ingest", "--scope", str(EXAMPLE_SCOPE), "--dump"])

    assert result.exit_code == 0, result.output
    for expected in (
        "demo/vulnerable_app/prompts/system.txt",
        f"Interactions ({TRAFFIC_RUNS})",
        "get_billing_status",
        "demo/vulnerable_app/tools.py",
        "currency-tools",  # the MCP server
    ):
        assert expected in result.output
    assert PLANTED_KEY not in result.output


def test_ingest_without_dump_shows_only_the_summary() -> None:
    result = runner.invoke(app, ["ingest", "--scope", str(EXAMPLE_SCOPE)])

    assert result.exit_code == 0
    assert "Inputs for demo-vulnerable-app" in result.output
    assert "Interactions (" not in result.output


def test_invalid_scope_files_fail_clearly(tmp_path: Path) -> None:
    bad = tmp_path / "scope.yaml"
    bad.write_text("name: x\naccess: everything\n", encoding="utf-8")

    result = runner.invoke(app, ["ingest", "--scope", str(bad)])

    assert result.exit_code == 1
    assert "Invalid scope file" in result.output


def test_audited_content_cannot_restyle_or_spoof_the_terminal(tmp_path: Path) -> None:
    hostile = "[bold red]FAKE[/] \x1b[2J\x1b[31mcleared " + "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0"
    (tmp_path / "log.jsonl").write_text(
        json.dumps({"messages": [{"role": "user", "content": hostile}]}) + "\n", encoding="utf-8"
    )
    (tmp_path / "scope.yaml").write_text(
        "name: x\naccess: gray\ninputs: {logs: [log.jsonl]}\ncapability_profile:\n"
        "  {exposure: internal, autonomy: human_in_loop, data_sensitivity: low,"
        " multi_tenant: false, capabilities: []}\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["ingest", "--scope", str(tmp_path / "scope.yaml"), "--dump"])

    assert result.exit_code == 0, result.output
    assert "[bold red]FAKE[/]" in result.output  # printed literally, not as markup
    assert "\x1b" not in result.output
    assert "A1b2C3d4E5f6G7h8I9j0" not in result.output


def test_safe_truncates_long_values() -> None:
    assert str(safe("x" * 100, limit=10)) == "xxxxxxxxx…"
