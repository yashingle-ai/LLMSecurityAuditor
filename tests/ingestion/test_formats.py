"""HAR, OpenAPI, tool definition, MCP config, prompt, source, and config-file loaders."""

import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from llm_auditor.ingestion import Artifact, IngestReport, Loader
from llm_auditor.ingestion.config_files import ConfigFileLoader
from llm_auditor.ingestion.har import HarLoader
from llm_auditor.ingestion.mcp import McpConfigLoader
from llm_auditor.ingestion.openapi import OpenApiLoader
from llm_auditor.ingestion.prompts import PromptLoader
from llm_auditor.ingestion.tools import ToolDefinitionLoader
from llm_auditor.models import (
    ApiSpec,
    ConfigFile,
    HarEntry,
    IngestIssue,
    Interaction,
    McpServerConfig,
    PromptArtifact,
)

Load = Callable[[Loader, str], tuple[list[Artifact], list[IngestIssue]]]
Golden = Callable[[str, Sequence[Artifact]], None]


def test_har_matches_golden(load: Load, golden: Golden) -> None:
    artifacts, _ = load(HarLoader(), "har/session.har")

    golden("har_session", artifacts)


def test_har_llm_calls_become_interactions(load: Load) -> None:
    artifacts, issues = load(HarLoader(), "har/session.har")

    entries = [a for a in artifacts if isinstance(a, HarEntry)]
    [call] = [a for a in artifacts if isinstance(a, Interaction)]
    assert [e.method for e in entries] == ["POST", "GET"]
    assert entries[0].response_headers["x-request-id"] == "a, b"
    assert call.messages[-1].content == "Hi there."  # decoded from a base64 response body
    assert call.request_meta is not None
    assert call.request_meta.endpoint == "https://llm.example.com/v1/chat/completions"
    assert call.request_meta.params == {"max_tokens": 64}
    assert [issue.message for issue in issues] == ["entry 3 skipped: entry should be an object"]


def test_openapi_matches_golden(load: Load, golden: Golden) -> None:
    artifacts, issues = load(OpenApiLoader(), "openapi/api.yaml")

    assert not issues
    golden("openapi_api", artifacts)


def test_openapi_operations_keep_their_own_security(load: Load) -> None:
    [spec] = load(OpenApiLoader(), "openapi/api.yaml")[0]
    assert isinstance(spec, ApiSpec)

    security = {(op.method, op.path): op.security for op in spec.operations}

    assert spec.security == [{"bearerAuth": []}]
    assert security == {
        ("POST", "/chat"): None,  # inherits the default
        ("GET", "/health"): [],  # explicitly public
        ("POST", "/admin/reset"): [{"bearerAuth": ["admin"]}],
    }


def test_swagger_2_is_reported_as_unsupported(load: Load) -> None:
    artifacts, issues = load(OpenApiLoader(), "openapi/swagger2.json")

    assert not artifacts
    assert "Swagger 2 is not supported" in issues[0].message


@pytest.mark.parametrize("name", ["openai.json", "anthropic.json", "mcp_tools_list.json"])
def test_every_tool_schema_normalizes_the_same(load: Load, name: str) -> None:
    reference, _ = load(ToolDefinitionLoader(), "tools/anthropic.json")

    artifacts, _ = load(ToolDefinitionLoader(), f"tools/{name}")

    assert [a.model_dump(exclude={"source"}) for a in artifacts] == [
        a.model_dump(exclude={"source"}) for a in reference
    ]


def test_bad_tool_definitions_are_reported_and_skipped(load: Load, golden: Golden) -> None:
    artifacts, issues = load(ToolDefinitionLoader(), "tools/openai.json")

    golden("tools_openai", artifacts)
    assert [issue.message for issue in issues] == [
        "tool 2 skipped: a tool definition should be an object",
        "tool 3 skipped: tool definition has no name",
    ]


def test_mcp_config_matches_golden(load: Load, golden: Golden) -> None:
    artifacts, issues = load(McpConfigLoader(), "mcp/claude_desktop.json")

    golden("mcp_claude_desktop", artifacts)
    assert [issue.message for issue in issues] == [
        "server 'broken' skipped: needs a 'command' (stdio) or a 'url' (http/sse)"
    ]


def test_vscode_mcp_configs_are_supported(load: Load) -> None:
    [server] = load(McpConfigLoader(), "mcp/vscode.json")[0]

    assert isinstance(server, McpServerConfig)
    assert (server.name, server.transport, server.url) == (
        "github",
        "http",
        "https://api.example.com/mcp/",
    )


def test_files_without_mcp_servers_are_reported(load: Load) -> None:
    artifacts, issues = load(McpConfigLoader(), "mcp/not_mcp.json")

    assert not artifacts
    assert "no 'mcpServers' or 'servers' section" in issues[0].message


def test_loading_mcp_configs_never_starts_a_process(
    load: Load, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the MCP loader tried to start a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    for name in ("system", "posix_spawn", "posix_spawnp", "execv", "execve", "fork"):
        monkeypatch.setattr(os, name, forbidden, raising=False)

    artifacts, _ = load(McpConfigLoader(), "mcp/claude_desktop.json")

    assert [a.name for a in artifacts if isinstance(a, McpServerConfig)] == [
        "filesystem",
        "remote-search",
    ]


@pytest.mark.parametrize(
    ("name", "variables"),
    [
        ("system.txt", ()),
        ("support.jinja", ("customer_name", "order", "question")),
        ("answer.md", ("language", "question", "user")),
    ],
)
def test_prompts_record_their_template_variables(
    load: Load, name: str, variables: tuple[str, ...]
) -> None:
    [prompt] = load(PromptLoader(), f"prompts/{name}")[0]

    assert isinstance(prompt, PromptArtifact)
    assert prompt.variables == variables


def test_prompts_match_golden(load: Load, golden: Golden) -> None:
    prompts = [
        artifact
        for name in ("system.txt", "support.jinja", "answer.md")
        for artifact in load(PromptLoader(), f"prompts/{name}")[0]
    ]

    golden("prompts", prompts)


@pytest.mark.parametrize(
    ("name", "config_format", "data"),
    [
        (
            "app.yaml",
            "yaml",
            {
                "llm": {"provider": "openai", "model": "latest", "max_tokens": None},
                "logging": {"level": "debug"},
            },
        ),
        ("settings.toml", "toml", {"server": {"port": 8000, "debug": True}}),
        (
            ".env.example",
            "env",
            {"OPENAI_API_KEY": "replace-me", "LOG_LEVEL": "info", "EMPTY": ""},
        ),
    ],
)
def test_config_files_are_parsed(
    load: Load, name: str, config_format: str, data: dict[str, Any]
) -> None:
    [config] = load(ConfigFileLoader(), f"config/{name}")[0]

    assert isinstance(config, ConfigFile)
    assert (config.format, config.data) == (config_format, data)


def test_unreadable_files_are_reported_not_raised(tmp_path: Path) -> None:
    binary = tmp_path / "blob.json"
    binary.write_bytes(b"\xff\xfe\x00binary")
    report = IngestReport()

    assert ToolDefinitionLoader().load(binary, "blob.json", report) == []
    assert report.issues[0].message == "skipped: not UTF-8 text"
