"""P-09: obfuscated or hidden text.

Text a person reviewing a prompt or document can't see, but a model reads:
Unicode tag characters ("ASCII smuggling"), zero-width characters, bidirectional
overrides, base64-encoded instructions, and words that mix scripts to spoof
look-alike letters.
"""

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator
from typing import ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._text import split_source
from llm_auditor.detectors._trace import outcome, tool_capabilities
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Role,
    Surface,
)

_TAGS = range(0xE0000, 0xE0080)
_BIDI = frozenset({0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})
_INVISIBLE = frozenset(
    {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD}
)
_ZWJ, _VARIATION_SELECTOR = 0x200D, 0xFE0F
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_WORD = re.compile(r"\w+")
MIN_INVISIBLE = 3  # a stray zero-width space is common in copied text; a run of them is not


def hidden_text(text: str) -> Iterator[tuple[int, str, str]]:
    """(line number, title, evidence) for each hidden-text technique on each line."""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.removeprefix("\ufeff") if number == 1 else raw  # a byte-order mark is normal
        smuggled = "".join(chr(ord(c) - 0xE0000) for c in line if ord(c) in _TAGS)
        readable = "".join(c for c in smuggled if c.isprintable())
        if readable:
            yield number, "Invisible Unicode tag characters", f"hidden text reads: {readable!r}"
        if any(ord(c) in _BIDI for c in line):
            yield number, "Bidirectional control characters", visible(line)
        invisible = [
            i for i, c in enumerate(line) if ord(c) in _INVISIBLE and not _joins_emoji(line, i)
        ]
        if len(invisible) >= MIN_INVISIBLE:
            yield number, "Zero-width characters", f"{len(invisible)} invisible: {visible(line)}"
        for blob in _BASE64.findall(line):
            decoded = _decoded_text(blob)
            if decoded:
                yield number, "Base64-encoded text", f"decodes to: {decoded[:160]!r}"
        for word in _WORD.findall(line):
            other = mixed_script(word)
            if other:
                yield (
                    number,
                    f"Word mixing Latin and {other} letters",
                    f"{word!r} ({visible(word)})",
                )


def visible(text: str, limit: int = 160) -> str:
    """``text`` with invisible and formatting characters shown as ``<U+200B>``."""
    shown = "".join(
        f"<U+{ord(c):04X}>" if unicodedata.category(c) == "Cf" or ord(c) in _TAGS else c
        for c in text
    )
    return shown if len(shown) <= limit else shown[: limit - 1] + "…"


def _joins_emoji(line: str, index: int) -> bool:
    """A zero-width joiner inside an emoji sequence (woman + ZWJ + laptop) is normal."""
    if ord(line[index]) != _ZWJ or not 0 < index < len(line) - 1:
        return False
    return _is_emoji(line[index - 1]) and _is_emoji(line[index + 1])


def _is_emoji(char: str) -> bool:
    return (
        ord(char) >= 0x1F000
        or ord(char) == _VARIATION_SELECTOR
        or unicodedata.category(char) == "So"
    )


def _decoded_text(blob: str) -> str | None:
    """The blob decoded, if it is base64 of readable text (natural-language instructions)."""
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(c.isprintable() or c in "\n\t" for c in decoded)
    if len(decoded) >= 20 and printable / len(decoded) >= 0.95 and decoded.count(" ") >= 3:
        return decoded
    return None


def mixed_script(word: str) -> str | None:
    """The non-Latin script a word mixes with Latin letters, if any."""
    scripts = {unicodedata.name(c, "").split(" ")[0] for c in word if c.isalpha()}
    if "LATIN" in scripts:
        for other in ("CYRILLIC", "GREEK"):
            if other in scripts:
                return other.title()
    return None


@register
class ObfuscatedText:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="P-09",
        title="Obfuscated or hidden text",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.PROMPT_DIRS, InputKind.LOGS),
        boundaries=(Boundary.B1, Boundary.B3),
        maps_to=("LLM01",),
        base_impact=5,
        amplified_by=frozenset(
            {
                Capability.EXTERNAL_COMMUNICATION,
                Capability.CODE_EXECUTION,
                Capability.FILE_WRITE,
                Capability.DESTRUCTIVE,
                Capability.FINANCIAL,
            }
        ),
        remediation=(
            "Remove the hidden text, and find out how it got there: content the model reads "
            "should be reviewed as the model sees it, not as it renders. Strip or reject "
            "invisible and bidirectional control characters on ingestion."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for prompt in context.artifacts.prompts:
            for line, title, evidence in hidden_text(prompt.text):
                yield Detection(
                    title=f"{title} in a prompt file",
                    location=Location(file=prompt.path, line=line),
                    evidence=evidence,
                    confidence=0.9,
                )
        # In logs these are attack attempts: incidents, aggregated in the report.
        tools = set(tool_capabilities(context))
        for interaction in context.artifacts.interactions:
            file, record_line = split_source(interaction.source)
            for index, message in enumerate(interaction.messages):
                if message.role is Role.USER:
                    where, text = "a user message", message.content
                elif message.tool_result is not None:
                    where, text = "a tool result", message.tool_result.content
                else:
                    continue
                for _, title, evidence in hidden_text(text):
                    result, why = outcome(interaction, index, text, tools)
                    yield Detection(
                        title=f"{title} in {where}",
                        location=Location(file=file, line=record_line),
                        evidence=f"{evidence} -> {result}: {why}",
                        confidence=0.9,
                        kind=FindingKind.INCIDENT,
                        outcome=result,
                    )
