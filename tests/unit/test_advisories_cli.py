from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from llm_auditor.advisories import load_db
from llm_auditor.cli import app

runner = CliRunner()
VULN = {
    "id": "GHSA-test",
    "summary": "Prompt injection to code execution",
    "affected": [
        {
            "package": {"name": "langchain", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.1.0"}]}],
        }
    ],
}


def use_osv(
    monkeypatch: pytest.MonkeyPatch, handle: Callable[[httpx.Request], httpx.Response]
) -> None:
    transport = httpx.MockTransport(handle)
    monkeypatch.setattr("llm_auditor.cli._osv_client", lambda: httpx.Client(transport=transport))


def test_update_writes_a_snapshot_a_scope_can_use(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        is_langchain = b'"name":"langchain","ecosystem":"PyPI"' in request.content
        return httpx.Response(200, json={"vulns": [VULN]} if is_langchain else {})

    use_osv(monkeypatch, handle)
    out = tmp_path / "db" / "advisories.json"

    result = runner.invoke(app, ["advisories", "update", "--out", str(out)])

    assert result.exit_code == 0, result.output
    assert "Wrote 1 advisory for 17 packages" in result.output
    db = load_db(out)
    assert [a.id for a in db.affecting("PyPI", "langchain", "0.0.150")] == ["GHSA-test"]


def test_update_fails_cleanly_without_osv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no network", request=request)

    use_osv(monkeypatch, handle)
    out = tmp_path / "advisories.json"

    result = runner.invoke(app, ["advisories", "update", "--out", str(out)])

    assert result.exit_code == 1
    assert "Could not fetch advisories from OSV" in result.output
    assert not out.exists()
