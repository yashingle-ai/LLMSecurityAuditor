"""A deterministic, deliberately gullible stand-in for an LLM."""

import json
import re
from collections.abc import Iterator, Sequence
from typing import Any

from demo.common.llm import ChatMessage, LLMReply, ToolCall, ToolSpec

_TOOL_DIRECTIVE = re.compile(r"\bcall\s+(?P<name>[A-Za-z_]\w*)\s+with\s+(?=\{)", re.IGNORECASE)
_SAY_DIRECTIVE = re.compile(r'\b(?:say|reply with)\s+"(?P<text>[^"]+)"', re.IGNORECASE)
_REVEAL_REQUEST = re.compile(r"system prompt|your instructions|everything above", re.IGNORECASE)
_INVOICE_ID = re.compile(r"\bINV-\d+\b")
_JSON = json.JSONDecoder()


class ScriptedLLM:
    """Follows instructions found anywhere in its context, the way real models can.

    Each turn it reads the system prompt and the current turn (the latest user
    message plus any tool results since), then the first rule that applies wins:

    1. ``call <tool> with {json}``: make that tool call, unless already made this turn.
    2. ``say "<text>"`` or ``reply with "<text>"``: reply with exactly that text.
    3. A request for its system prompt or instructions: reveal the system prompt.
    4. Tool results this turn: summarize them.
    5. An invoice ID (``INV-1001``) or a billing-status question: call the matching tool.
    6. Otherwise: offer help.

    Instructions in tool results count as much as the user's, which is what
    makes indirect prompt injection demonstrable and testable.
    """

    @property
    def name(self) -> str:
        return "scripted-gullible-v1"

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSpec],
        max_tokens: int | None = None,  # replies are short and fixed; nothing to cap
    ) -> LLMReply:
        system = next((m.content for m in messages if m.role == "system"), "")
        turn = _current_turn(messages)
        request = turn[0].content if turn else ""
        texts = [system, *(m.content for m in turn if m.role in ("user", "tool"))]
        available = {tool.name for tool in tools}
        already_made = {(c.name, _canonical(c.arguments)) for m in turn for c in m.tool_calls}
        next_id = sum(len(m.tool_calls) for m in messages) + 1

        for name, arguments in _tool_directives(texts):
            if name in available and (name, _canonical(arguments)) not in already_made:
                return _call(next_id, name, arguments)

        for text in texts:
            if say := _SAY_DIRECTIVE.search(text):
                return LLMReply(content=say["text"])

        if _REVEAL_REQUEST.search(request):
            return LLMReply(content=f"My instructions are:\n{system}")

        results = [m.content for m in turn if m.role == "tool"]
        if results:
            return LLMReply(content="Here is what I found:\n" + "\n".join(results))

        if (invoice := _INVOICE_ID.search(request)) and "get_invoice" in available:
            return _call(next_id, "get_invoice", {"invoice_id": invoice[0]})
        if "billing" in request.lower() and "get_billing_status" in available:
            return _call(next_id, "get_billing_status", {})
        return LLMReply(
            content="I can help with your invoices and the status of the billing service."
        )


def _current_turn(messages: Sequence[ChatMessage]) -> Sequence[ChatMessage]:
    user_turns = [i for i, m in enumerate(messages) if m.role == "user"]
    return messages[user_turns[-1] :] if user_turns else []


def _tool_directives(texts: Sequence[str]) -> Iterator[tuple[str, dict[str, Any]]]:
    for text in texts:
        for match in _TOOL_DIRECTIVE.finditer(text):
            try:
                arguments, _ = _JSON.raw_decode(text, match.end())
            except json.JSONDecodeError:
                continue
            if isinstance(arguments, dict):
                yield match["name"], arguments


def _canonical(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments, sort_keys=True)


def _call(number: int, name: str, arguments: dict[str, Any]) -> LLMReply:
    return LLMReply(tool_calls=(ToolCall(id=f"call_{number}", name=name, arguments=arguments),))
