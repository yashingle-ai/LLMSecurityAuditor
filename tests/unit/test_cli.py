from collections.abc import Callable

import pytest
from typer.testing import CliRunner

from llm_auditor import __version__
from llm_auditor.checks import Check, CheckRegistry
from llm_auditor.cli import app
from llm_auditor.models import CheckMeta

runner = CliRunner()


def test_version_prints_installed_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert f"llmaudit {__version__}" in result.output


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])

    assert "Usage" in result.output
    assert "version" in result.output


def test_checks_list_renders_an_empty_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("llm_auditor.cli.registry", CheckRegistry())

    result = runner.invoke(app, ["checks", "list"])

    assert result.exit_code == 0
    assert "No checks registered yet." in result.output


def test_checks_list_shows_registered_checks(
    monkeypatch: pytest.MonkeyPatch,
    make_meta: Callable[..., CheckMeta],
    make_check: Callable[[CheckMeta], type[Check]],
) -> None:
    catalog = CheckRegistry()
    catalog.register(make_check(make_meta(id="P-01", title="Secrets in prompts")))
    monkeypatch.setattr("llm_auditor.cli.registry", catalog)

    result = runner.invoke(app, ["checks", "list"])

    assert result.exit_code == 0
    assert "P-01" in result.output
    assert "No checks registered yet." not in result.output
