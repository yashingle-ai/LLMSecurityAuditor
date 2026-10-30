import json
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest

from llm_auditor.advisories import (
    OSV_QUERY_URL,
    AdvisoryDb,
    builtin_db,
    fetch_db,
    in_range,
    load_db,
    normalize,
)

FIXED = [{"introduced": "0"}, {"fixed": "0.0.325"}]
LAST_AFFECTED = [{"introduced": "1.2.0"}, {"last_affected": "1.4.0"}]
REOPENED = [{"introduced": "1.0"}, {"fixed": "1.1"}, {"introduced": "2.0"}]


@pytest.mark.parametrize(
    ("version", "events", "affected"),
    [
        ("0.0.150", FIXED, True),
        ("0.0.325", FIXED, False),  # the fix itself
        ("0.1.0", FIXED, False),
        ("1.2.0", LAST_AFFECTED, True),
        ("1.4.0", LAST_AFFECTED, True),
        ("1.4.1", LAST_AFFECTED, False),
        ("1.1.9", LAST_AFFECTED, False),
        ("1.0.5", REOPENED, True),
        ("1.5", REOPENED, False),
        ("2.3", REOPENED, True),  # introduced again, never fixed
        ("not-a-version", FIXED, False),
    ],
)
def test_in_range(version: str, events: list[dict[str, str]], affected: bool) -> None:
    assert in_range(version, events) is affected


def test_pypi_names_are_normalized() -> None:
    assert normalize("PyPI", "LangChain_Community") == "langchain-community"
    assert normalize("npm", "@LangChain/core") == "@LangChain/core"  # npm names are exact


def test_the_builtin_snapshot_knows_old_and_current_langchain() -> None:
    db = builtin_db()

    assert db.watches("PyPI", "LangChain") and db.watches("npm", "@langchain/core")
    assert not db.watches("PyPI", "requests")
    old = db.affecting("PyPI", "langchain", "0.0.150")
    assert len(old) > 10
    assert all(advisory.package == "langchain" for advisory in old)
    assert db.affecting("PyPI", "langchain", "1.4.7") == []


def osv_api(pages: dict[str, list[dict[str, Any]]]) -> httpx.MockTransport:
    """A fake OSV query API. ``pages`` maps package name to its result pages."""

    def handle(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == OSV_QUERY_URL
        body = json.loads(request.content)
        results = pages.get(body["package"]["name"], [{}])
        page = int(body.get("page_token", 0))
        data = dict(results[page])
        if page + 1 < len(results):
            data["next_page_token"] = str(page + 1)
        return httpx.Response(200, json=data)

    return httpx.MockTransport(handle)


def vuln(vuln_id: str, name: str, fixed: str, ecosystem: str = "PyPI") -> dict[str, Any]:
    return {
        "id": vuln_id,
        "aliases": [f"CVE-{vuln_id}"],
        "summary": f"{vuln_id} summary",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "abc"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]},
                ],
            },
            {"package": {"name": "other-package", "ecosystem": ecosystem}, "ranges": []},
        ],
    }


def test_fetch_db_follows_pages_and_keeps_only_the_watched_package(tmp_path: Path) -> None:
    transport = osv_api(
        {
            "LangChain": [
                {"vulns": [vuln("GHSA-1", "langchain", "0.1.0")]},
                {
                    "vulns": [
                        vuln("GHSA-2", "langchain", "0.2.0"),
                        vuln("GHSA-1", "langchain", "0.1.0"),
                    ]
                },
            ]
        }
    )
    with httpx.Client(transport=transport) as client:
        db = fetch_db(client, {"PyPI": ("LangChain", "gradio")})

    assert db.fetched == date.today()
    assert db.watched == {"PyPI": ("langchain", "gradio")}
    assert [a.id for a in db.advisories] == ["GHSA-1", "GHSA-2"]
    assert db.advisories[0].aliases == ("CVE-GHSA-1",)
    assert db.advisories[0].severity == "HIGH"
    assert db.advisories[0].ranges == (({"introduced": "0"}, {"fixed": "0.1.0"}),)
    assert [a.id for a in db.affecting("PyPI", "langchain", "0.1.5")] == ["GHSA-2"]

    path = tmp_path / "advisories.json"
    path.write_text(db.model_dump_json(), encoding="utf-8")
    assert load_db(path) == db


def test_fetch_db_raises_on_an_api_error() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(503))
    with httpx.Client(transport=transport) as client, pytest.raises(httpx.HTTPStatusError):
        fetch_db(client, {"PyPI": ("langchain",)})


def test_load_db_rejects_a_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text('{"fetched": "2026-10-01"}', encoding="utf-8")

    with pytest.raises(ValueError, match="watched"):
        load_db(path)
    assert isinstance(builtin_db(), AdvisoryDb)
