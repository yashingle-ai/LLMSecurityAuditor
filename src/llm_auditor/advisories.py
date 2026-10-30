"""Known vulnerabilities in LLM frameworks, from the OSV database (https://osv.dev).

Audits check dependencies against a local snapshot, so they work offline and give
the same answer every time. The auditor ships one (``rules/advisories.json``);
``llmaudit advisories update`` fetches a fresh one, and ``advisory_db`` in the
scope file points an audit at it.
"""

import re
from collections.abc import Iterable, Mapping
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from llm_auditor.models._base import StrictModel
from llm_auditor.rules import RULES_DIR

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
BUILTIN_DB = RULES_DIR / "advisories.json"

# The packages whose advisories the snapshot holds: LLM frameworks, serving, and agent tooling.
WATCHED: dict[str, tuple[str, ...]] = {
    "PyPI": (
        "langchain",
        "langchain-core",
        "langchain-community",
        "langchain-experimental",
        "llama-index",
        "llama-index-core",
        "transformers",
        "litellm",
        "vllm",
        "haystack-ai",
        "chainlit",
        "gradio",
        "mcp",
    ),
    "npm": ("langchain", "@langchain/core", "@langchain/community", "@modelcontextprotocol/sdk"),
}


class Advisory(StrictModel, frozen=True):
    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    severity: str | None = None  # the database's rating, e.g. "CRITICAL"
    ecosystem: str
    package: str
    ranges: tuple[tuple[dict[str, str], ...], ...]  # OSV range events, one tuple per range


class AdvisoryDb(StrictModel):
    fetched: date
    source: str = "https://osv.dev"
    watched: dict[str, tuple[str, ...]]
    advisories: tuple[Advisory, ...]

    def affecting(self, ecosystem: str, package: str, version: str) -> list[Advisory]:
        name = normalize(ecosystem, package)
        return [
            advisory
            for advisory in self.advisories
            if advisory.ecosystem == ecosystem
            and advisory.package == name
            and any(in_range(version, events) for events in advisory.ranges)
        ]

    def watches(self, ecosystem: str, package: str) -> bool:
        return normalize(ecosystem, package) in self.watched.get(ecosystem, ())


def normalize(ecosystem: str, package: str) -> str:
    """PyPI names compare case- and separator-insensitively (PEP 503)."""
    return re.sub(r"[-_.]+", "-", package).lower() if ecosystem == "PyPI" else package


def in_range(version: str, events: Iterable[Mapping[str, str]]) -> bool:
    """Whether ``version`` falls in an OSV ECOSYSTEM range (introduced / fixed / last_affected)."""
    try:
        current = Version(version)
        start: Version | None = None
        for event in events:
            if "introduced" in event:
                start = Version("0") if event["introduced"] == "0" else Version(event["introduced"])
            elif "fixed" in event and start is not None:
                if start <= current < Version(event["fixed"]):
                    return True
                start = None
            elif "last_affected" in event and start is not None:
                if start <= current <= Version(event["last_affected"]):
                    return True
                start = None
    except InvalidVersion:
        return False
    return start is not None and current >= start


@cache
def builtin_db() -> AdvisoryDb:
    return load_db(BUILTIN_DB)


def load_db(path: Path) -> AdvisoryDb:
    return AdvisoryDb.model_validate_json(path.read_text(encoding="utf-8"))


def write_db(db: AdvisoryDb, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(db.model_dump_json(indent=1) + "\n", encoding="utf-8")


def fetch_db(client: httpx.Client, watched: Mapping[str, tuple[str, ...]] = WATCHED) -> AdvisoryDb:
    """Every OSV advisory for the watched packages. Needs network access."""
    advisories: list[Advisory] = []
    for ecosystem, packages in watched.items():
        for package in packages:
            for vuln in _query(client, ecosystem, package):
                advisories.extend(_advisories(vuln, ecosystem, package))
    unique = {(a.id, a.ecosystem, a.package): a for a in advisories}
    return AdvisoryDb(
        fetched=date.today(),
        watched={eco: tuple(normalize(eco, p) for p in pkgs) for eco, pkgs in watched.items()},
        advisories=tuple(sorted(unique.values(), key=lambda a: (a.ecosystem, a.package, a.id))),
    )


def _query(client: httpx.Client, ecosystem: str, package: str) -> Iterable[dict[str, Any]]:
    body: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    while True:
        response = client.post(OSV_QUERY_URL, json=body)
        response.raise_for_status()
        data = response.json()
        yield from data.get("vulns", [])
        if not data.get("next_page_token"):
            return
        body["page_token"] = data["next_page_token"]


def _advisories(vuln: dict[str, Any], ecosystem: str, package: str) -> Iterable[Advisory]:
    name = normalize(ecosystem, package)
    for affected in vuln.get("affected", []):
        target = affected.get("package", {})
        if (
            target.get("ecosystem") != ecosystem
            or normalize(ecosystem, target.get("name", "")) != name
        ):
            continue
        ranges = tuple(
            tuple(event for event in r.get("events", []))
            for r in affected.get("ranges", [])
            if r.get("type") in ("ECOSYSTEM", "SEMVER")
        )
        if ranges:
            yield Advisory(
                id=vuln["id"],
                aliases=tuple(vuln.get("aliases", [])),
                summary=vuln.get("summary", ""),
                severity=vuln.get("database_specific", {}).get("severity"),
                ecosystem=ecosystem,
                package=name,
                ranges=ranges,
            )
