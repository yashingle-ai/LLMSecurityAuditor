"""Normalized interactions: every log line, trace, and probe result becomes one of these."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import Field, model_validator

from llm_auditor.models._base import StrictModel


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolDefinition(StrictModel):
    name: str = Field(min_length=1)
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)  # JSON Schema
    source: str | None = None  # e.g. "mcp://browser-server" or "tools.json"


class ToolCall(StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResult(StrictModel):
    call_id: str = Field(min_length=1)
    content: str
    is_error: bool = False


class Message(StrictModel):
    """One turn. Assistant turns may make tool calls; tool turns carry exactly one result."""

    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_result: ToolResult | None = None

    @model_validator(mode="after")
    def _tool_fields_match_role(self) -> Self:
        if self.tool_calls and self.role is not Role.ASSISTANT:
            raise ValueError("only assistant messages can make tool calls")
        if (self.tool_result is not None) != (self.role is Role.TOOL):
            raise ValueError("tool messages, and only tool messages, carry a tool result")
        return self


class RequestMeta(StrictModel):
    endpoint: str | None = None
    method: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)  # raw; redact before writing anywhere
    params: dict[str, Any] = Field(default_factory=dict)  # model parameters, e.g. max_tokens


class Interaction(StrictModel):
    """One conversation or agent run.

    ``messages`` is the single source of ordering (user turn, tool call, tool
    result, ..., final answer), so sequence checks can see what happened when.
    ``tool_calls`` and ``tool_results`` are views over it.
    """

    id: str = Field(min_length=1)
    source: str = Field(min_length=1)  # where it came from, e.g. "logs/chat.jsonl:42"
    timestamp: datetime | None = None
    model: str | None = None
    user: str | None = None  # the end user this run served, when logged
    conversation_id: str | None = None
    system_prompt: str | None = None
    messages: list[Message] = Field(default_factory=list)
    tool_definitions: list[ToolDefinition] = Field(default_factory=list)
    request_meta: RequestMeta | None = None

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [call for message in self.messages for call in message.tool_calls]

    @property
    def tool_results(self) -> list[ToolResult]:
        return [m.tool_result for m in self.messages if m.tool_result is not None]
