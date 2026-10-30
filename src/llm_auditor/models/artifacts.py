"""Artifacts produced by ingestion, one type per kind of input.

Values are raw, including any secrets: detectors need them. Redact before
writing an artifact anywhere.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from llm_auditor.models._base import StrictModel

Security = list[dict[str, list[str]]]  # OpenAPI security requirements


class PromptArtifact(StrictModel):
    path: str  # relative to the scope root
    format: Literal["text", "markdown", "jinja"]
    text: str
    variables: tuple[str, ...] = ()  # template variables, e.g. ("user_input",)


class SourceFile(StrictModel):
    path: str
    language: str
    size_bytes: int = Field(ge=0)


class ConfigFile(StrictModel):
    path: str
    format: Literal["yaml", "json", "toml", "env"]
    data: Any


class Dependency(StrictModel, frozen=True):
    name: str
    version: str | None = None  # the exact version, when pinned
    spec: str = ""  # as written, e.g. ">=0.1,<0.2"
    line: int | None = None


class DependencyFile(StrictModel):
    path: str
    ecosystem: Literal["PyPI", "npm"]
    dependencies: tuple[Dependency, ...] = ()


ModelFormat = Literal["pickle", "pytorch", "safetensors", "onnx", "gguf", "keras"]


class ModelFile(StrictModel):
    path: str
    format: ModelFormat
    size_bytes: int = Field(ge=0)


DocumentFormat = Literal["html", "markdown", "text", "pdf", "docx"]


class HiddenText(StrictModel, frozen=True):
    """Text a reader of the rendered document doesn't see, but a model reading it does."""

    how: str  # e.g. "display:none", "white text", "HTML comment", "hidden run"
    text: str
    page: int | None = None  # PDF page, from 1


class Document(StrictModel):
    """A document an LLM app retrieves or ingests (a RAG corpus, a knowledge base)."""

    path: str
    format: DocumentFormat
    text: str  # what a reader sees
    hidden: tuple[HiddenText, ...] = ()


class HarEntry(StrictModel):
    source: str  # e.g. "session.har#3"
    started: datetime | None = None
    method: str
    url: str
    status: int
    request_headers: dict[str, str] = Field(default_factory=dict)  # lower-case names
    response_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_body: str | None = None


class ApiOperation(StrictModel):
    method: str  # upper-case
    path: str
    operation_id: str | None = None
    security: Security | None = None  # None: inherits the spec's default


class ApiSpec(StrictModel):
    path: str
    openapi_version: str
    title: str | None = None
    servers: tuple[str, ...] = ()
    security_schemes: dict[str, Any] = Field(default_factory=dict)
    security: Security = Field(default_factory=list)  # default for every operation
    operations: tuple[ApiOperation, ...] = ()


class McpServerConfig(StrictModel):
    """An MCP server entry from a client config file. The auditor never starts it."""

    source: str
    name: str
    transport: Literal["stdio", "http", "sse"]
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
