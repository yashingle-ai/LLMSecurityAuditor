"""Trace logs: JSON Lines (or JSON) in OpenAI chat, Anthropic Messages, or a mapped format.

A record is either a request body itself (``{"messages": [...], ...}``) or a
request/response pair (``{"request": {...}, "response": {...}}``). Both formats
normalize to the same ``Interaction``: the system prompt is pulled out, tool
results become tool messages, and the model's reply is appended as the final
assistant message.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from llm_auditor.ingestion.base import (
    Artifact,
    FormatError,
    IngestReport,
    describe,
    expect_dict,
    expect_list,
    optional_str,
    parse_timestamp,
    read_text,
    required_str,
)
from llm_auditor.ingestion.tools import parse_tool_definition
from llm_auditor.models import (
    Interaction,
    LogMapping,
    Message,
    RequestMeta,
    Role,
    ToolCall,
    ToolDefinition,
    ToolResult,
)

TraceFormat = Literal["openai", "anthropic"]

# Request fields kept as model parameters (A-03 looks for unbounded max_tokens, for example).
MODEL_PARAMETERS = frozenset(
    {
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "temperature",
        "top_p",
        "top_k",
        "stop",
        "stop_sequences",
        "seed",
        "n",
        "stream",
        "tool_choice",
        "parallel_tool_calls",
        "response_format",
    }
)


class TraceLoader:
    extensions = frozenset({".jsonl", ".json"})

    def __init__(
        self,
        trace_format: Literal["auto", "openai", "anthropic", "mapped"] = "auto",
        mapping: LogMapping | None = None,
    ) -> None:
        if (trace_format == "mapped") != (mapping is not None):
            raise ValueError("the 'mapped' format needs a mapping, and only it takes one")
        self._format = trace_format
        self._mapping = mapping

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        text = read_text(file, rel, report)
        if text is None:
            return []
        interactions: list[Artifact] = []
        for source, line, record in _records(text, rel, file.suffix.lower() == ".json", report):
            try:
                interactions.append(self.normalize(record, source))
            except (FormatError, ValidationError) as error:
                where = "" if line else f"{source}: "
                report.warn(rel, f"{where}skipped: {describe(error)}", line=line)
        return interactions

    def normalize(self, record: Any, source: str) -> Interaction:
        record = expect_dict(record, "a trace record")
        if self._mapping is not None:
            return _from_mapping(record, source, self._mapping)
        explicit: TraceFormat | None = None
        if self._format == "openai" or self._format == "anthropic":
            explicit = self._format
        return normalize_trace(record, source, explicit)


def normalize_trace(
    record: dict[str, Any], source: str, trace_format: TraceFormat | None = None
) -> Interaction:
    """Normalize one OpenAI or Anthropic record, detecting the format unless given."""
    request = record["request"] if isinstance(record.get("request"), dict) else record
    response = record.get("response") if isinstance(record.get("response"), dict) else None
    detected = trace_format or detect_format(request, response)
    if detected is None:
        raise FormatError("not a recognized trace format (no 'messages' list)")
    parse = _parse_openai if detected == "openai" else _parse_anthropic
    system_prompt, messages = parse(request, response)
    return Interaction(
        id=optional_str(record.get("id")) or source,
        source=source,
        timestamp=parse_timestamp(record.get("timestamp", record.get("created_at"))),
        model=optional_str(request.get("model"), record.get("model")),
        user=optional_str(
            record.get("user"), request.get("user"), _lookup(request, "metadata.user_id")
        ),
        conversation_id=optional_str(
            record.get("conversation_id"), record.get("session_id"), record.get("thread_id")
        ),
        system_prompt=system_prompt,
        messages=messages,
        tool_definitions=_tools(request.get("tools")),
        request_meta=_request_meta(request),
    )


def detect_format(request: dict[str, Any], response: dict[str, Any] | None) -> TraceFormat | None:
    messages = request.get("messages")
    if not isinstance(messages, list):
        return None
    dicts = [m for m in messages if isinstance(m, dict)]
    raw_tools = request.get("tools")
    tools = [t for t in raw_tools if isinstance(t, dict)] if isinstance(raw_tools, list) else []
    openai = (
        any(m.get("role") in ("system", "developer", "tool") or "tool_calls" in m for m in dicts)
        or any("function" in t for t in tools)
        or (response is not None and "choices" in response)
    )
    anthropic = (
        "system" in request
        or any(_has_block(m.get("content"), ("tool_use", "tool_result")) for m in dicts)
        or any("input_schema" in t for t in tools)
        or (response is not None and isinstance(response.get("content"), list))
    )
    # Plain user/assistant text looks the same in both and normalizes identically.
    return "anthropic" if anthropic and not openai else "openai"


def _parse_openai(
    request: dict[str, Any], response: dict[str, Any] | None
) -> tuple[str | None, list[Message]]:
    raw = list(expect_list(request.get("messages"), "messages"))
    if response is not None:
        choices = expect_list(response.get("choices"), "response choices")
        if not choices:
            raise FormatError("response has no choices")
        raw.append(expect_dict(expect_dict(choices[0], "choice").get("message"), "message"))

    system_prompt: str | None = None
    messages: list[Message] = []
    for item in raw:
        message = expect_dict(item, "message")
        role = message.get("role")
        content = _text(message.get("content"))
        if role in ("system", "developer"):
            if system_prompt is None and not messages:
                system_prompt = content
            else:
                messages.append(Message(role=Role.SYSTEM, content=content))
        elif role == "user":
            messages.append(Message(role=Role.USER, content=content))
        elif role == "assistant":
            calls = expect_list(message.get("tool_calls") or [], "tool_calls")
            messages.append(
                Message(
                    role=Role.ASSISTANT,
                    content=content,
                    tool_calls=[_openai_tool_call(call) for call in calls],
                )
            )
        elif role == "tool":
            messages.append(_tool_message(message.get("tool_call_id"), content))
        else:
            raise FormatError(f"unknown message role {role!r}")
    return system_prompt, messages


def _openai_tool_call(raw: Any) -> ToolCall:
    call = expect_dict(raw, "tool call")
    function = expect_dict(call.get("function"), "tool call function")
    return ToolCall(
        id=required_str(call.get("id"), "tool call id"),
        name=required_str(function.get("name"), "tool call name"),
        arguments=_arguments(function.get("arguments")),
    )


def _parse_anthropic(
    request: dict[str, Any], response: dict[str, Any] | None
) -> tuple[str | None, list[Message]]:
    system_prompt = _text(request["system"]) if "system" in request else None
    raw = list(expect_list(request.get("messages"), "messages"))
    if response is not None:
        raw.append({"role": "assistant", "content": response.get("content")})

    messages: list[Message] = []
    for item in raw:
        message = expect_dict(item, "message")
        role = message.get("role")
        blocks = _blocks(message.get("content"))
        if role == "user":
            texts: list[str] = []
            for block in blocks:
                if block.get("type") == "tool_result":
                    if texts:
                        messages.append(Message(role=Role.USER, content="\n".join(texts)))
                        texts = []
                    messages.append(
                        _tool_message(
                            block.get("tool_use_id"),
                            _text(block.get("content")),
                            is_error=block.get("is_error") is True,
                        )
                    )
                elif block.get("type") == "text":
                    texts.append(_text(block.get("text")))
            if texts:
                messages.append(Message(role=Role.USER, content="\n".join(texts)))
        elif role == "assistant":
            text = "\n".join(_text(b.get("text")) for b in blocks if b.get("type") == "text")
            calls = [
                ToolCall(
                    id=required_str(b.get("id"), "tool_use id"),
                    name=required_str(b.get("name"), "tool_use name"),
                    arguments=_arguments(b.get("input")),
                )
                for b in blocks
                if b.get("type") == "tool_use"
            ]
            messages.append(Message(role=Role.ASSISTANT, content=text, tool_calls=calls))
        else:
            raise FormatError(f"unknown message role {role!r}")
    return system_prompt, messages


def _from_mapping(record: dict[str, Any], source: str, mapping: LogMapping) -> Interaction:
    user_text = _lookup(record, mapping.user)
    if not isinstance(user_text, str):
        raise FormatError(f"no user message at {mapping.user!r}")
    messages = [Message(role=Role.USER, content=user_text)]
    if mapping.assistant is not None:
        reply = _lookup(record, mapping.assistant)
        if reply is not None:
            messages.append(Message(role=Role.ASSISTANT, content=_text(reply)))
    system = _lookup(record, mapping.system) if mapping.system else None
    return Interaction(
        id=(optional_str(_lookup(record, mapping.id)) if mapping.id else None) or source,
        source=source,
        timestamp=parse_timestamp(_lookup(record, mapping.timestamp))
        if mapping.timestamp
        else None,
        model=optional_str(_lookup(record, mapping.model)) if mapping.model else None,
        system_prompt=_text(system) if system is not None else None,
        messages=messages,
    )


def _records(
    text: str, rel: str, whole_file: bool, report: IngestReport
) -> Iterator[tuple[str, int | None, Any]]:
    """(source, line number, record) for each record; bad JSON is reported and skipped."""
    if whole_file:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            report.warn(rel, f"skipped: not valid JSON ({error.msg})")
            return
        for number, item in enumerate(data if isinstance(data, list) else [data], 1):
            yield f"{rel}#{number}", None, item
        return
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            report.warn(rel, f"skipped: not valid JSON ({error.msg})", line=number)
            continue
        yield f"{rel}:{number}", number, record


def _tool_message(call_id: Any, content: str, is_error: bool = False) -> Message:
    return Message(
        role=Role.TOOL,
        tool_result=ToolResult(
            call_id=required_str(call_id, "tool result call id"),
            content=content,
            is_error=is_error,
        ),
    )


def _tools(value: Any) -> list[ToolDefinition]:
    if value is None:
        return []
    return [parse_tool_definition(tool, source=None) for tool in expect_list(value, "tools")]


def _request_meta(request: dict[str, Any]) -> RequestMeta | None:
    params = {key: value for key, value in request.items() if key in MODEL_PARAMETERS}
    return RequestMeta(params=params) if params else None


def _arguments(value: Any) -> dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"_raw": value}
        return parsed if isinstance(parsed, dict) else {"_raw": value}
    raise FormatError("tool arguments should be an object or a JSON string")


def _text(value: Any) -> str:
    """Text from a string, or from a list of content parts (non-text parts are dropped)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [
            part if isinstance(part, str) else part["text"]
            for part in value
            if isinstance(part, str)
            or (isinstance(part, dict) and isinstance(part.get("text"), str))
        ]
        return "\n".join(parts)
    raise FormatError(f"expected text, got {type(value).__name__}")


def _blocks(content: Any) -> list[dict[str, Any]]:
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [expect_dict(block, "content block") for block in expect_list(content, "content")]


def _has_block(content: Any, types: tuple[str, ...]) -> bool:
    return isinstance(content, list) and any(
        isinstance(block, dict) and block.get("type") in types for block in content
    )


def _lookup(data: Any, path: str) -> Any:
    """Follow a dotted path through dicts and lists (``choices.0.text``); None if absent."""
    for key in path.split("."):
        if isinstance(data, dict):
            data = data.get(key)
        elif isinstance(data, list) and key.isdigit() and int(key) < len(data):
            data = data[int(key)]
        else:
            return None
    return data
