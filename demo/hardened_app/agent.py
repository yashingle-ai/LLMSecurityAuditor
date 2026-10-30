"""The agent loop: ask the model, run the tools it calls, repeat until it answers."""

import itertools
import json
import logging
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import yaml

from demo.common.guardrails import flagged
from demo.common.llm import ChatMessage, LLMBackend

from .tools import TOOL_SPECS, execute

SETTINGS: dict[str, Any] = yaml.safe_load(
    (Path(__file__).parent / "agent.yaml").read_text(encoding="utf-8")
)
AGENT = SETTINGS["agent"]
MAX_STEPS: int | None = AGENT.get("max_steps")
REQUIRE_APPROVAL = frozenset(AGENT.get("require_approval") or ())
MAX_TOKENS: int | None = (SETTINGS.get("llm") or {}).get("max_tokens")
INJECTION_FILTER: dict[str, Any] = (SETTINGS.get("guardrails") or {}).get("injection_filter") or {}
AUDIT_ENABLED = bool((SETTINGS.get("audit_log") or {}).get("enabled"))

NEEDS_APPROVAL = "This action needs the customer's confirmation in the portal, so it was not run."
BLOCKED = "Sorry, I can't help with that request."
FILTERED = "[removed by the injection filter]"
LOG = logging.getLogger("acme.agent")
AUDIT = logging.getLogger("acme.audit")


def blocked(boundary: str, text: str) -> bool:
    """Whether the injection filter stops ``text`` here. In monitor mode it only logs."""
    if boundary not in (INJECTION_FILTER.get("apply_to") or ()) or not flagged(text):
        return False
    LOG.warning("injection filter flagged %s", boundary)
    return INJECTION_FILTER.get("mode") == "block"


def run_agent(
    llm: LLMBackend,
    system_prompt: str,
    history: Sequence[ChatMessage],
    user_message: str,
    user: str,
) -> list[ChatMessage]:
    """Answer ``user_message`` and return the whole conversation, system prompt first."""
    messages = [ChatMessage("system", system_prompt), *history, ChatMessage("user", user_message)]
    if blocked("user_input", user_message):
        messages.append(ChatMessage("assistant", BLOCKED))
        return messages
    steps: Iterable[int] = itertools.count() if MAX_STEPS is None else range(MAX_STEPS)
    for _ in steps:
        reply = llm.complete(messages, TOOL_SPECS, max_tokens=MAX_TOKENS)
        if not reply.tool_calls:
            answer = BLOCKED if blocked("model_output", reply.content) else reply.content
            messages.append(ChatMessage("assistant", answer))
            return messages
        messages.append(ChatMessage("assistant", reply.content, reply.tool_calls))
        for call in reply.tool_calls:
            approved = call.name not in REQUIRE_APPROVAL
            result = execute(call, user) if approved else NEEDS_APPROVAL
            if blocked("tool_results", result):
                result = FILTERED
            if AUDIT_ENABLED:
                record = {"user": user, "tool": call.name, "arguments": sorted(call.arguments)}
                AUDIT.info(json.dumps({**record, "ran": approved}))
            messages.append(ChatMessage("tool", result, tool_call_id=call.id))
    messages.append(ChatMessage("assistant", "Sorry, I couldn't finish that request."))
    return messages
