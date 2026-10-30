"""Conversion to and from the OpenAI chat-completions format.

Used both to talk to real models and to write trace logs, since it is the
format most LLM gateways and observability tools log in.
"""

import json
from typing import Any

from demo.common.llm import ChatMessage, LLMReply, ToolCall, ToolSpec


def message_to_openai(message: ChatMessage) -> dict[str, Any]:
    data: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        data["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
            }
            for call in message.tool_calls
        ]
    if message.tool_call_id is not None:
        data["tool_call_id"] = message.tool_call_id
    return data


def tool_to_openai(tool: ToolSpec) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        },
    }


def reply_from_openai(message: dict[str, Any]) -> LLMReply:
    """Parse ``choices[0].message`` from a chat-completions response."""
    calls = tuple(
        ToolCall(
            id=call["id"],
            name=call["function"]["name"],
            arguments=_parse_arguments(call["function"].get("arguments")),
        )
        for call in message.get("tool_calls") or []
    )
    return LLMReply(content=message.get("content") or "", tool_calls=calls)


def _parse_arguments(raw: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"_raw": raw}
    return parsed if isinstance(parsed, dict) else {"_raw": raw}
