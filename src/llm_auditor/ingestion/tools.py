"""Tool definitions in OpenAI function, Anthropic tool, or MCP tool schema."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from llm_auditor.ingestion.base import (
    Artifact,
    FormatError,
    IngestReport,
    as_dict,
    describe,
    read_structured,
)
from llm_auditor.models import ToolDefinition

_SCHEMA_KEYS = ("parameters", "input_schema", "inputSchema")  # OpenAI, Anthropic, MCP


def parse_tool_definition(raw: Any, source: str | None) -> ToolDefinition:
    """Normalize one tool definition, whichever of the three schemas it uses."""
    if not isinstance(raw, dict):
        raise FormatError("a tool definition should be an object")
    spec = raw["function"] if isinstance(raw.get("function"), dict) else raw  # OpenAI wraps it
    name = spec.get("name")
    if not isinstance(name, str) or not name:
        raise FormatError("tool definition has no name")
    description = spec.get("description")
    parameters: dict[str, Any] = next(
        (spec[key] for key in _SCHEMA_KEYS if isinstance(spec.get(key), dict)), {}
    )
    return ToolDefinition(
        name=name,
        description=description if isinstance(description, str) else "",
        parameters=parameters,
        source=source,
    )


class ToolDefinitionLoader:
    """A list of tools, a single tool, an object with a ``tools`` list, or a captured
    MCP ``tools/list`` JSON-RPC response (``result.tools``)."""

    extensions = frozenset({".json", ".yaml", ".yml"})

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        data = read_structured(file, rel, report)
        if data is None:
            return []
        if isinstance(data, dict):
            if "name" in data or "function" in data:
                data = [data]
            else:
                data = data.get("tools", as_dict(data.get("result")).get("tools"))
        if not isinstance(data, list):
            report.warn(rel, "skipped: expected a list of tools or an object with a 'tools' list")
            return []
        tools: list[Artifact] = []
        for number, item in enumerate(data, 1):
            try:
                tools.append(parse_tool_definition(item, source=rel))
            except (FormatError, ValidationError) as error:
                report.warn(rel, f"tool {number} skipped: {describe(error)}")
        return tools
