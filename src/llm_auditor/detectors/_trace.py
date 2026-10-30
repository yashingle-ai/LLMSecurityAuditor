"""Helpers for checks that read logged agent runs: where a run was logged, what each tool
can do, whether an attack in a run worked, system prompt leaks, and taint tracking."""

import base64
import binascii
import json
import re
from collections import defaultdict
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus

from llm_auditor.checks import CheckUnavailable
from llm_auditor.classifiers import ClassifierUnavailable, InjectionClassifier, build_classifier
from llm_auditor.detectors._text import split_source
from llm_auditor.ingestion import AuditContext
from llm_auditor.inventory import tool_inventory
from llm_auditor.models import (
    Capability,
    IncidentOutcome,
    Interaction,
    Location,
    Role,
    ToolCall,
)

REFUSAL = re.compile(
    r"(?i)\b(I can(no|')t|I am not able|I'm not able|unable to|I won't|I will not|not allowed"
    r"|can't help|cannot help|not permitted)\b"
)
GUARDRAIL_MARKER = re.compile(
    r"(?i)\[(removed|blocked|filtered|redacted)\b|\b(blocked|removed) by\b"
)
DEMANDED_REPLY = re.compile(
    r"(?i)\b(?:say|reply with|respond with|answer with|output|print)\s+[\"“]([^\"”]{8,})"
)
SHINGLE = 8  # words per shingle when comparing a reply with the system prompt
LEAK_FRACTION = 0.5  # of the system prompt's shingles found in one reply
MIN_FRAGMENT = 8  # shorter values ("yes", "1", "paid") are too common to track
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_TOKEN = re.compile(r"[\w.@+:/-]{8,}")


def log_location(interaction: Interaction) -> Location:
    file, line = split_source(interaction.source)
    return Location(file=file, line=line)


def tool_capabilities(context: AuditContext) -> dict[str, frozenset[Capability]]:
    """Each tool name's capabilities, from the inventory."""
    found: dict[str, set[Capability]] = defaultdict(set)
    for tool in tool_inventory(context):
        found[tool.profile.name] |= set(tool.profile.capabilities)
    return {name: frozenset(capabilities) for name, capabilities in found.items()}


def injection_classifier(context: AuditContext) -> InjectionClassifier:
    """The scope's injection classifier, built once per audit."""
    cached = context.cache.get("injection_classifier")
    if cached is None:
        try:
            cached = build_classifier(context.scope.injection_classifier)
        except ClassifierUnavailable as error:
            cached = CheckUnavailable(f"injection classifier: {error}")
        context.cache["injection_classifier"] = cached
    if isinstance(cached, CheckUnavailable):
        raise cached
    classifier: InjectionClassifier = cached
    return classifier


@dataclass(frozen=True)
class ToolStep:
    """A tool result in a run, with the call that produced it."""

    index: int  # position of the result in interaction.messages
    call: ToolCall | None
    content: str
    is_error: bool


def tool_steps(interaction: Interaction) -> Iterator[ToolStep]:
    calls = {call.id: call for call in interaction.tool_calls}
    for index, message in enumerate(interaction.messages):
        if message.tool_result is not None:
            result = message.tool_result
            yield ToolStep(index, calls.get(result.call_id), result.content, result.is_error)


def calls_after(interaction: Interaction, index: int) -> Iterator[tuple[int, ToolCall]]:
    for position, message in enumerate(interaction.messages[index + 1 :], index + 1):
        for call in message.tool_calls:
            yield position, call


def result_of(interaction: Interaction, call: ToolCall) -> str | None:
    return next(
        (s.content for s in tool_steps(interaction) if s.call and s.call.id == call.id), None
    )


def outcome(
    interaction: Interaction, index: int, attack: str, tools: Collection[str]
) -> tuple[IncidentOutcome, str]:
    """Whether the model did what ``attack`` (the text at ``messages[index]``) asked, and why
    we think so."""
    after = interaction.messages[index + 1 :]
    named = {tool for tool in tools if re.search(rf"\b{re.escape(tool)}\b", attack)}
    demanded = [text.split("{")[0].strip() for text in DEMANDED_REPLY.findall(attack)]
    for message in after:
        called = [call.name for call in message.tool_calls if call.name in named]
        if called:
            return IncidentOutcome.SUCCEEDED, f"the model then called {called[0]}, as it asked"
        if message.role is Role.ASSISTANT and message.content:
            if any(len(text) >= 8 and text in message.content for text in demanded):
                return IncidentOutcome.SUCCEEDED, "the model replied with the text it dictated"
            if leaks_prompt(interaction.system_prompt, message.content):
                return IncidentOutcome.SUCCEEDED, "the model's reply reproduced its system prompt"
    reply = next((m.content for m in after if m.role is Role.ASSISTANT and m.content), "")
    if REFUSAL.search(reply) or GUARDRAIL_MARKER.search(reply):
        return IncidentOutcome.FAILED, "the model refused or a guardrail blocked it"
    return IncidentOutcome.UNKNOWN, "nothing in the log shows whether it worked"


def leaks_prompt(system_prompt: str | None, reply: str) -> bool:
    """Whether ``reply`` reproduces most of ``system_prompt``."""
    if not system_prompt or not system_prompt.strip():
        return False
    prompt_words, reply_words = _words(system_prompt), _words(reply)
    if len(prompt_words) < SHINGLE:
        return " ".join(prompt_words) in " ".join(reply_words)
    wanted = _shingles(prompt_words)
    return len(wanted & _shingles(reply_words)) / len(wanted) >= LEAK_FRACTION


def _words(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _shingles(words: list[str]) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + SHINGLE]) for i in range(len(words) - SHINGLE + 1)}


# Taint tracking: values from one tool's results reappearing in a later call's arguments.


@dataclass(frozen=True)
class Taint:
    value: str  # the value from the source, as found
    encoding: str  # how it was found: "as is", "URL-encoded", or "base64"


def fragments(text: str) -> set[str]:
    """Values worth tracking from ``text``: whole lines of 20+ characters, and tokens of 8+
    characters that contain a digit or an @ (IDs, emails, amounts, keys). Short or common
    values ("yes", "1", "paid") would match by coincidence, so they aren't tracked."""
    found = {" ".join(line.split()) for line in text.splitlines() if len(line.strip()) >= 20}
    found |= {
        token.strip(".,:;")
        for token in _TOKEN.findall(text)
        if any(c.isdigit() for c in token) or "@" in token
    }
    return {value for value in found if len(value) >= MIN_FRAGMENT}


def views(value: str) -> dict[str, str]:
    """``value`` as is, URL-decoded, and with base64 blobs decoded."""
    found = {"as is": value}
    unquoted = unquote_plus(unquote_plus(value))
    if unquoted != value:
        found["URL-encoded"] = unquoted
    decoded = [text for blob in _BASE64.findall(value) if (text := _from_base64(blob))]
    if decoded:
        found["base64"] = "\n".join(decoded)
    return {encoding: " ".join(text.split()) for encoding, text in found.items()}


def taint(sources: Collection[str], arguments: dict[str, Any]) -> Taint | None:
    """The first source value found in any string inside ``arguments``."""
    values = sorted(sources, key=len, reverse=True)
    for leaf in _strings(arguments):
        for encoding, text in views(leaf).items():
            hit = next((value for value in values if value in text), None)
            if hit is not None:
                return Taint(hit, encoding)
    return None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield json.dumps(value)


def _from_base64(blob: str) -> str | None:
    padded = blob + "=" * (-len(blob) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = decode(padded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) >= 0.95:
            return text
    return None
