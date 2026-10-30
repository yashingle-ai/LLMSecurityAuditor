"""MCP client config files (``mcpServers`` or VS Code's ``servers``).

Parsed statically only. The auditor never starts the servers these entries
describe: a config's ``command`` can run anything.
"""

from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from llm_auditor.ingestion.base import (
    Artifact,
    FormatError,
    IngestReport,
    describe,
    expect_dict,
    read_structured,
)
from llm_auditor.models import McpServerConfig

Transport = Literal["stdio", "http", "sse"]


class McpConfigLoader:
    extensions = frozenset({".json"})

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        data = read_structured(file, rel, report)
        if data is None:
            return []
        servers = data.get("mcpServers", data.get("servers")) if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            report.warn(rel, "skipped: no 'mcpServers' or 'servers' section")
            return []
        configs: list[Artifact] = []
        for name, raw in servers.items():
            try:
                configs.append(_server(str(name), raw, rel))
            except (FormatError, ValidationError) as error:
                report.warn(rel, f"server {name!r} skipped: {describe(error)}")
        return configs


def _server(name: str, raw: Any, source: str) -> McpServerConfig:
    entry = expect_dict(raw, "server entry")
    declared = entry.get("type")
    if isinstance(entry.get("url"), str):
        transport: Transport = "sse" if declared == "sse" else "http"
        return McpServerConfig(
            source=source,
            name=name,
            transport=transport,
            url=entry["url"],
            headers=_strings(entry.get("headers"), "headers"),
        )
    if isinstance(entry.get("command"), str):
        args = entry.get("args") or []
        if not isinstance(args, list):
            raise FormatError("args should be a list")
        return McpServerConfig(
            source=source,
            name=name,
            transport="stdio",
            command=entry["command"],
            args=tuple(str(arg) for arg in args),
            env=_strings(entry.get("env"), "env"),
        )
    raise FormatError("needs a 'command' (stdio) or a 'url' (http/sse)")


def _strings(value: Any, what: str) -> dict[str, str]:
    if value is None:
        return {}
    return {str(key): str(item) for key, item in expect_dict(value, what).items()}
