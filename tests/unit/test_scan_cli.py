from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from llm_auditor.cli import app
from llm_auditor.models import AuditReport

REPO_ROOT = Path(__file__).parents[2]
EXAMPLE_SCOPE = REPO_ROOT / "configs" / "audit_scope.example.yaml"
HARDENED_SCOPE = REPO_ROOT / "configs" / "audit_scope.hardened.yaml"
P01_PROMPTS = REPO_ROOT / "tests" / "fixtures" / "checks" / "P-01" / "positive" / "prompt_dirs"

runner = CliRunner()


@pytest.fixture(autouse=True)
def wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("llm_auditor.cli.console", Console(width=200))


def test_scan_writes_every_report_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", "--scope", str(EXAMPLE_SCOPE), "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "report.json",
        "report.md",
        "report.sarif",
    ]
    report = AuditReport.model_validate_json((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert {f.check_id for f in report.findings} >= {"P-01", "A-01", "P-02", "P-09"}
    assert "F-0001" in result.output


def test_fail_on_exits_nonzero_when_a_finding_is_that_severe(tmp_path: Path) -> None:
    args = ["scan", "--scope", str(EXAMPLE_SCOPE), "--out", str(tmp_path), "--fail-on", "high"]

    assert runner.invoke(app, args).exit_code == 1


def test_the_hardened_app_passes_even_a_strict_fail_on(tmp_path: Path) -> None:
    args = ["scan", "--scope", str(HARDENED_SCOPE), "--out", str(tmp_path / "out")]

    result = runner.invoke(app, [*args, "--fail-on", "low"])

    assert result.exit_code == 0, result.output
    # Its logs hold attacks too, but none of them got through.
    assert "no findings;" in result.output
    assert "0 succeeded" in result.output


def test_quick_prompt_scan_says_severity_has_no_context(tmp_path: Path) -> None:
    args = ["scan", "prompts", str(P01_PROMPTS), "--out", str(tmp_path), "--format", "md"]

    result = runner.invoke(app, args)

    assert result.exit_code == 0, result.output
    assert [p.name for p in tmp_path.iterdir()] == ["report.md"]
    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Quick scan without a scope file" in markdown
    assert markdown.count("**Check:** P-01") == 3


def test_unknown_formats_are_rejected(tmp_path: Path) -> None:
    args = ["scan", "--scope", str(EXAMPLE_SCOPE), "--out", str(tmp_path), "--format", "pdf"]

    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert "unknown format pdf" in result.output


def test_scan_needs_a_scope_or_a_subcommand() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "give a scope file" in result.output
