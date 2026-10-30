"""Approved tool definitions, written by ``llmaudit tools lock`` and checked by T-12.

The lockfile records what each tool told the model (description and schema) when
someone reviewed it. A later difference is a "rug pull" until it is reviewed
again: a tool, often from an MCP server, quietly changing its instructions.
"""

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from llm_auditor.inventory import canonical
from llm_auditor.models import ToolDefinition
from llm_auditor.models._base import StrictModel


class LockedTool(StrictModel, frozen=True):
    source: str
    name: str
    sha256: str
    description: str
    parameters: dict[str, Any]


class ToolLock(StrictModel):
    version: Literal[1] = 1
    tools: tuple[LockedTool, ...] = ()

    def find(self, source: str, name: str) -> LockedTool | None:
        return next((t for t in self.tools if t.source == source and t.name == name), None)


def digest(tool: ToolDefinition) -> str:
    return hashlib.sha256(canonical(tool).encode()).hexdigest()


def lock_tools(definitions: Iterable[ToolDefinition]) -> ToolLock:
    """A lock approving every definition that came from a file."""
    unique = {(d.source, d.name): d for d in definitions if d.source}
    return ToolLock(
        tools=tuple(
            LockedTool(
                source=source,
                name=name,
                sha256=digest(tool),
                description=tool.description,
                parameters=tool.parameters,
            )
            for (source, name), tool in sorted(unique.items())
            if source is not None
        )
    )


def read_lock(path: Path) -> ToolLock | None:
    """The lock at ``path``, None if there is none. Raises ValueError if it's malformed."""
    if not path.is_file():
        return None
    try:
        return ToolLock.model_validate_json(path.read_text(encoding="utf-8"))
    except ValidationError as error:
        raise ValueError(str(error).splitlines()[0]) from error


def write_lock(lock: ToolLock, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = lock.model_dump(mode="json")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
