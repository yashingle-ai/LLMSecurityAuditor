"""SC-01's pickle scanner, SC-02's advisory lookups, and SC-03's MCP install rules.

Pickles here are built with ``pickle.dumps`` (which only records references) or
from raw opcodes. Nothing is ever unpickled.
"""

import collections
import io
import os
import pickle
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from llm_auditor.detectors.supply_chain import (
    UNRESOLVED_IMPORT,
    is_dangerous,
    mcp_problems,
    model_imports,
    pickle_imports,
)
from llm_auditor.models import AuditReport, FindingKind, McpServerConfig

AuditOne = Callable[..., AuditReport]
PROTOCOLS = range(pickle.HIGHEST_PROTOCOL + 1)


class Call:
    """Pickles as ``target(*args)``. Dumping it records the reference; nothing is called."""

    def __init__(self, target: Any, *args: Any) -> None:
        self.target, self.args = target, args

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return self.target, self.args


def imports_of(data: bytes) -> list[str]:
    return pickle_imports(io.BytesIO(data))


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_finds_imports_in_every_protocol(protocol: int) -> None:
    data = pickle.dumps({"weights": [0.5], "hook": Call(os.system, "id")}, protocol=protocol)

    assert imports_of(data) == [f"{os.system.__module__}.system"]


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_repeated_modules_resolve_through_the_memo(protocol: int) -> None:
    # Protocol 4+ memoizes "collections" and "posix" and fetches them back with BINGET.
    data = pickle.dumps(
        [collections.OrderedDict, collections.Counter, os.getcwd, os.system], protocol=protocol
    )

    imports = imports_of(data)

    assert imports[-1] == f"{os.system.__module__}.system"
    assert len(imports) == 4 and all(is_dangerous(name) for name in imports[2:])


def test_a_memoized_module_name_cant_hide_an_import() -> None:
    evasive = (
        b"\x80\x04"  # PROTO 4
        b"\x8c\x05posix\x94"  # "posix", memoized as 0
        b"0"  # POP: never used directly
        b"h\x00"  # BINGET 0
        b"\x8c\x06system\x94"  # "system"
        b"\x93"  # STACK_GLOBAL
        b"\x8c\x02id\x94\x85R."  # ("id",) REDUCE STOP
    )

    assert imports_of(evasive) == ["posix.system"]


def test_a_computed_import_is_unresolved_and_dangerous() -> None:
    computed = b"\x80\x04\x8c\x05posix\x8c\x06system\x86\x93."  # STACK_GLOBAL on a tuple
    imports = imports_of(computed)

    assert imports == [UNRESOLVED_IMPORT]
    assert is_dangerous(UNRESOLVED_IMPORT)


def test_a_data_only_pickle_imports_nothing() -> None:
    assert imports_of(pickle.dumps({"weights": [0.1, 0.2], "labels": ("a", "b")})) == []


@pytest.mark.parametrize(
    ("name", "dangerous"),
    [
        ("os.system", True),
        ("posix.system", True),
        ("nt.system", True),
        ("subprocess.Popen", True),
        ("commands.getoutput", True),  # subprocess under protocols 0-2
        ("builtins.eval", True),
        ("__builtin__.getattr", True),
        ("os.path.join", True),
        ("builtins.dict", False),
        ("collections.OrderedDict", False),
        ("torch._utils._rebuild_tensor_v2", False),
        ("numpy.core.multiarray._reconstruct", False),
    ],
)
def test_is_dangerous(name: str, dangerous: bool) -> None:
    assert is_dangerous(name) is dangerous


def test_reads_the_pickles_inside_a_pytorch_archive(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("model/data.pkl", pickle.dumps(Call(subprocess.Popen, ["id"]), 4))
        archive.writestr("model/data/0", b"\x00" * 8)

    assert model_imports(path) == ["subprocess.Popen"]


def test_sc01_reports_a_safe_pickle_as_hardening(audit_one: AuditOne, tmp_path: Path) -> None:
    (tmp_path / "labels.pkl").write_bytes(pickle.dumps({"labels": ["refund", "invoice"]}))

    report = audit_one("SC-01", tmp_path, inputs={"model_dirs": ["."]})

    [finding] = report.findings
    assert finding.kind == FindingKind.HARDENING
    assert "no dangerous imports" in finding.evidence


def test_sc01_reports_an_unreadable_pickle_as_an_issue(audit_one: AuditOne, tmp_path: Path) -> None:
    (tmp_path / "broken.pkl").write_bytes(b"\x80\x04\x8c\xff")

    report = audit_one("SC-01", tmp_path, inputs={"model_dirs": ["."]})

    assert report.findings == ()
    assert report.coverage.ran == ("SC-01",)
    assert [issue.path for issue in report.coverage.ingest_issues] == ["broken.pkl"]


def test_sc02_reports_an_unpinned_framework_as_hardening(
    audit_one: AuditOne, tmp_path: Path
) -> None:
    (tmp_path / "requirements.txt").write_text("langchain>=0.0.100\nrequests\n", encoding="utf-8")

    report = audit_one("SC-02", tmp_path, inputs={"dependency_files": ["requirements.txt"]})

    [finding] = report.findings
    assert finding.kind == FindingKind.HARDENING
    assert finding.location.line == 1


def test_sc02_uses_the_scopes_advisory_db(audit_one: AuditOne, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("gradio==4.0.0\n", encoding="utf-8")
    (tmp_path / "advisories.json").write_text(
        '{"fetched": "2026-10-01", "watched": {"PyPI": ["gradio"]}, "advisories": [{"id": '
        '"GHSA-test", "summary": "Test", "ecosystem": "PyPI", "package": "gradio", '
        '"ranges": [[{"introduced": "0"}, {"fixed": "4.1.0"}]]}]}',
        encoding="utf-8",
    )

    report = audit_one(
        "SC-02",
        tmp_path,
        inputs={"dependency_files": ["requirements.txt"]},
        advisory_db="advisories.json",
    )

    [finding] = report.findings
    assert finding.title == "gradio 4.0.0 has 1 known vulnerability"
    assert finding.evidence == "GHSA-test: Test (OSV snapshot of 2026-10-01)"


def test_sc02_skips_when_the_advisory_db_is_unreadable(audit_one: AuditOne, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("gradio==4.0.0\n", encoding="utf-8")

    report = audit_one(
        "SC-02", tmp_path, inputs={"dependency_files": ["requirements.txt"]}, advisory_db="no.json"
    )

    [skipped] = report.coverage.skipped
    assert skipped.reason.startswith("can't read the advisory database")


def server(command: str | None = None, *args: str, url: str | None = None) -> McpServerConfig:
    transport = "stdio" if url is None else "sse"
    return McpServerConfig(
        name="s", source="mcp.json", transport=transport, command=command, args=args, url=url
    )


@pytest.mark.parametrize(
    ("config", "problem"),
    [
        (server("npx", "-y", "pkg"), "downloads an unpinned package at start-up (pkg) and "),
        (server("npx", "@scope/pkg@latest"), "downloads an unpinned package"),
        (server("/usr/local/bin/bunx", "@scope/pkg"), "downloads an unpinned package"),
        (server("pnpm", "dlx", "pkg@^1.2.0"), "downloads an unpinned package"),
        (server("uvx", "--from", "x==1.0", "mcp-server-git"), "(mcp-server-git)"),
        (server("pipx", "run", "mcp-server-fetch"), "downloads an unpinned package"),
        (server("docker", "run", "-i", "--rm", "-e", "TOKEN", "mcp/github"), "image"),
        (server("docker", "run", "mcp/github:latest"), "image"),
        (server(url="http://mcp.example.com/sse"), "unencrypted HTTP"),
    ],
)
def test_mcp_problems(config: McpServerConfig, problem: str) -> None:
    [found] = mcp_problems(config)

    assert problem in found


@pytest.mark.parametrize(
    "config",
    [
        server("npx", "-y", "pkg@1.2.3"),
        server("npx", "@scope/pkg@2025.8.21"),
        server("uvx", "mcp-server-fetch==2025.4.7"),
        server("docker", "run", "mcp/github:1.4.0"),
        server("docker", "run", "mcp/github@sha256:" + "0" * 64),
        server("node", "/opt/mcp/server.js"),
        server("python", "-m", "acme_mcp"),
        server(url="https://mcp.example.com/sse"),
        server(url="http://localhost:8931/sse"),
    ],
)
def test_mcp_no_problems(config: McpServerConfig) -> None:
    assert mcp_problems(config) == []
