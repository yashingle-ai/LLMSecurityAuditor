"""Chat types and the interface every LLM backend implements."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatMessage:
    role: Role
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()  # assistant messages only
    tool_call_id: str | None = None  # tool messages only


@dataclass(frozen=True)
class LLMReply:
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


class LLMBackend(Protocol):
    @property
    def name(self) -> str: ...

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSpec],
        max_tokens: int | None = None,
    ) -> LLMReply: ...
