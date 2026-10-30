"""Shared by every loader: the loader interface, issue reporting, and safe file reading."""

import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TypeAlias

import yaml
from pydantic import ValidationError

from llm_auditor.models import (
    ApiSpec,
    ConfigFile,
    DependencyFile,
    Document,
    HarEntry,
    IngestIssue,
    Interaction,
    McpServerConfig,
    ModelFile,
    PromptArtifact,
    SourceFile,
    ToolDefinition,
)

MAX_FILE_BYTES = 10 * 1024 * 1024

Artifact: TypeAlias = (
    PromptArtifact
    | Interaction
    | ApiSpec
    | HarEntry
    | ToolDefinition
    | McpServerConfig
    | SourceFile
    | ConfigFile
    | DependencyFile
    | ModelFile
    | Document
)


class FormatError(ValueError):
    """Input that doesn't have the expected shape. Loaders report it and skip that part."""


class IngestReport:
    """Collects problems while loading. Loaders report and skip; they never raise."""

    def __init__(self) -> None:
        self.issues: list[IngestIssue] = []

    def warn(self, path: str, message: str, line: int | None = None) -> None:
        self.issues.append(IngestIssue(path=path, line=line, message=message))


class Loader(Protocol):
    @property
    def extensions(self) -> frozenset[str]:
        """File suffixes picked up when an input entry is a directory."""
        ...

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]: ...


def read_text(file: Path, rel: str, report: IngestReport) -> str | None:
    """The file as UTF-8 text, or None (reported) if it's too big, binary, or unreadable."""
    try:
        if file.stat().st_size > MAX_FILE_BYTES:
            report.warn(rel, f"skipped: larger than {MAX_FILE_BYTES // 2**20} MiB")
            return None
        return file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        report.warn(rel, "skipped: not UTF-8 text")
    except OSError as error:
        report.warn(rel, f"skipped: {error.strerror or error}")
    return None


def read_structured(file: Path, rel: str, report: IngestReport) -> Any:
    """Parse JSON, YAML, or TOML by suffix. None (reported) if it can't be read or parsed."""
    text = read_text(file, rel, report)
    if text is None:
        return None
    suffix = file.suffix.lower()
    try:
        if suffix in (".yaml", ".yml"):
            return yaml.safe_load(text)
        if suffix == ".toml":
            return tomllib.loads(text)
        return json.loads(text)
    except (json.JSONDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError) as error:
        report.warn(rel, f"skipped: could not parse: {_first_line(str(error))}")
        return None


def describe(error: Exception) -> str:
    """A one-line explanation of a FormatError or pydantic ValidationError."""
    if isinstance(error, ValidationError):
        first = error.errors()[0]
        where = ".".join(str(part) for part in first["loc"])
        return f"{where}: {first['msg']}" if where else first["msg"]
    return _first_line(str(error))


def as_dict(value: Any) -> dict[str, Any]:
    """``value`` if it's a dict, else an empty one: for optional sections."""
    return value if isinstance(value, dict) else {}


def expect_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FormatError(f"{what} should be an object")
    return value


def expect_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise FormatError(f"{what} should be a list")
    return value


def required_str(value: Any, what: str) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str) or not value:
        raise FormatError(f"missing {what}")
    return value


def optional_str(*values: Any) -> str | None:
    """The first value that is a non-empty string or an integer, as a string."""
    for value in values:
        if isinstance(value, str) and value:
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return None


def parse_timestamp(value: Any) -> datetime | None:
    """ISO 8601 strings or Unix epoch seconds. Naive times are taken as UTC."""
    try:
        if isinstance(value, int | float) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, UTC)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else "unknown error"


def split_source(source: str) -> tuple[str, int | None]:
    """An artifact source as (file, line): ``logs/a.jsonl:12`` or ``session.har#3``."""
    if "#" in source:
        return source.rsplit("#", 1)[0], None
    path, separator, line = source.rpartition(":")
    if separator and line.isdigit():
        return path, int(line)
    return source, None
