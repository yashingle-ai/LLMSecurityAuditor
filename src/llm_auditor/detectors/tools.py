"""Tool and MCP checks: T-09 to T-13. They read tool definitions; nothing is run or contacted."""

import re
import unicodedata
from collections.abc import Iterator
from itertools import combinations
from typing import Any, ClassVar

from llm_auditor.checks import CheckUnavailable, Detection, register
from llm_auditor.classifiers import InjectionClassifier, flagged
from llm_auditor.detectors._text import find_line
from llm_auditor.detectors._trace import injection_classifier
from llm_auditor.detectors.obfuscation import hidden_text, mixed_script, visible
from llm_auditor.ingestion import AuditContext
from llm_auditor.inventory import (
    COMMAND_PARAMS,
    DESTINATION_PARAMS,
    PATH_PARAMS,
    SHELL_WORDS,
    URL_PARAMS,
    InventoryTool,
    is_free_text,
    properties,
    tool_inventory,
    words,
)
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Surface,
    ToolDefinition,
)
from llm_auditor.tool_lock import digest, read_lock

_TOOL_INPUTS = (InputKind.TOOL_DEFS, InputKind.LOGS)
_INJECTION_AMPLIFIERS = frozenset(
    {
        Capability.EXTERNAL_COMMUNICATION,
        Capability.CODE_EXECUTION,
        Capability.FILE_WRITE,
        Capability.DESTRUCTIVE,
        Capability.FINANCIAL,
        Capability.WRITES_MEMORY,
    }
)


def tool_check(
    check_id: str,
    title: str,
    boundaries: tuple[Boundary, ...],
    maps_to: tuple[str, ...],
    base_impact: int,
    remediation: str,
    inputs: tuple[InputKind, ...] = _TOOL_INPUTS,
    amplified_by: frozenset[Capability] = frozenset(),
) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title=title,
        surface=Surface.TOOL,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=inputs,
        boundaries=boundaries,
        maps_to=maps_to,
        base_impact=base_impact,
        amplified_by=amplified_by,
        remediation=remediation,
    )


def tool_location(context: AuditContext, tool: InventoryTool) -> Location:
    """The tool's definition: its file, and the line naming it when that can be found."""
    source = tool.profile.source
    line = find_line(context.read_text(source) or "", f'"{tool.profile.name}"') if source else None
    return Location(file=source or None, line=line, artifact=f"tool:{tool.profile.name}")


def summary(tool: ToolDefinition, limit: int = 200) -> str:
    """``name(params): description``, shortened, with hidden characters made visible."""
    params = ", ".join(properties(tool.parameters))
    text = visible(f"{tool.name}({params}): {tool.description}".replace("\n", " "), limit)
    return text


@register
class ExcessiveToolPermissions:
    meta: ClassVar[CheckMeta] = tool_check(
        "T-09",
        "Tool with excessive permissions",
        (Boundary.B4,),
        ("LLM06", "ASI02"),
        6,
        "Give each tool the narrowest power its job needs: no general shell, a fixed or "
        "allow-listed destination instead of any URL or recipient, one directory instead of "
        "any path. Constrain parameters in the schema (enum, pattern) and enforce it in code.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for tool in tool_inventory(context):
            for problem in excessive_permissions(tool):
                yield Detection(
                    title=f"Tool '{tool.profile.name}' {problem}",
                    location=tool_location(context, tool),
                    evidence=summary(tool.definition),
                    confidence=0.8,
                )


def excessive_permissions(tool: InventoryTool) -> list[str]:
    definition, capabilities = tool.definition, tool.profile.capabilities
    parameters = properties(definition.parameters)
    free = {p.lower() for p, schema in parameters.items() if is_free_text(schema)}
    text = words(definition.name) | words(definition.description)
    problems = []
    if Capability.CODE_EXECUTION in capabilities and (text & SHELL_WORDS or free & COMMAND_PARAMS):
        problems.append("can run any shell command")
    if free & URL_PARAMS:
        problems.append(f"can request any URL ({', '.join(sorted(free & URL_PARAMS))})")
    recipients = free & (DESTINATION_PARAMS - URL_PARAMS)
    if Capability.EXTERNAL_COMMUNICATION in capabilities and recipients:
        problems.append(f"can send to any recipient ({', '.join(sorted(recipients))})")
    if Capability.FILE_WRITE in capabilities:
        problems.append(f"can write to any path ({', '.join(sorted(free & PATH_PARAMS))})")
    return problems


_LEGS = {
    Capability.READS_PRIVATE_DATA: "reads private data",
    Capability.INGESTS_UNTRUSTED_CONTENT: "reads untrusted content",
    Capability.EXTERNAL_COMMUNICATION: "can send data out",
}


@register
class LethalTrifecta:
    meta: ClassVar[CheckMeta] = tool_check(
        "T-10",
        "Lethal trifecta: private data, untrusted content, and a way to send data out",
        (Boundary.B3, Boundary.B4),
        ("LLM06", "ASI01"),
        8,
        "Break one leg of the trifecta for this agent: drop tools that send data to a "
        "model-chosen destination, keep untrusted content away from an agent that holds "
        "private data, or split the work between agents that never hold all three.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        inventory = tool_inventory(context)
        legs = {
            capability: sorted(
                t.profile.name for t in inventory if capability in t.profile.capabilities
            )
            for capability in _LEGS
        }
        if all(legs.values()):
            sender = next(
                t for t in inventory if Capability.EXTERNAL_COMMUNICATION in t.profile.capabilities
            )
            yield Detection(
                title="The agent's tools combine private data, untrusted content, and a way out",
                location=Location(file=sender.profile.source or None, artifact="agent:tools"),
                evidence="; ".join(f"{_LEGS[c]}: {', '.join(names)}" for c, names in legs.items()),
                confidence=0.8,
            )


_POISONING = (
    (
        r"\bignore\b.{0,40}\b(instructions|rules|guidelines|previous|above)\b",
        "says to ignore instructions",
    ),
    (
        r"\bbefore (using|calling|you use|running|you call)\b",
        "gives steps to take before using a tool",
    ),
    (
        r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show)\b"
        r"|\bwithout (telling|informing|notifying)\b",
        "says to keep something from the user",
    ),
    (
        r"<\s*/?\s*(important|system|instructions?)\s*>|\[(important|system)\]",
        "uses markup that imitates system instructions",
    ),
    (
        r"~/\.ssh|\bid_rsa\b|\.env\b|/etc/passwd|\.aws/credentials|\bcredentials\.json\b"
        r"|\bmcp\.json\b",
        "points the model at credential files",
    ),
    (r"\b(bcc|cc|forward|copy|send)\b[^.]{0,40}@", "sends a copy to an address"),
)
_POISONING_PATTERNS = tuple((re.compile(p, re.IGNORECASE), reason) for p, reason in _POISONING)


@register
class ToolPoisoning:
    meta: ClassVar[CheckMeta] = tool_check(
        "T-11",
        "Instructions for the model hidden in a tool definition (tool poisoning)",
        (Boundary.B7,),
        ("LLM01", "ASI04"),
        7,
        "Remove the tool, or the server that provides it, until its definition is reviewed. "
        "Tool descriptions reach the model as instructions; only connect servers you trust, "
        "and pin and review their definitions (see T-12).",
        amplified_by=_INJECTION_AMPLIFIERS,
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        inventory = tool_inventory(context)
        names = {t.profile.name for t in inventory}
        try:
            classifier: InjectionClassifier | None = injection_classifier(context)
        except CheckUnavailable:
            classifier = None  # the patterns below still work without it
        for tool in inventory:
            signals = poisoning_signals(tool.definition, names - {tool.profile.name})
            if classifier is not None:
                texts = [tool.definition.description, *descriptions(tool.definition.parameters)]
                verdict = flagged(classifier, texts, "content")
                if verdict.score >= classifier.threshold:
                    signals.append(f"reads as prompt injection ({', '.join(verdict.signals)})")
            if signals:
                yield Detection(
                    title=f"Tool '{visible(tool.profile.name)}' definition {signals[0]}",
                    location=tool_location(context, tool),
                    evidence=f"{'; '.join(signals)}. {summary(tool.definition, 300)}",
                    confidence=0.9 if len(signals) > 1 else 0.6,
                )


def poisoning_signals(tool: ToolDefinition, other_tools: set[str]) -> list[str]:
    texts = [tool.description, *descriptions(tool.parameters)]
    signals: list[str] = []
    for text in texts:
        signals += [reason for pattern, reason in _POISONING_PATTERNS if pattern.search(text)]
        signals += [f"hides text ({title.lower()})" for _, title, _ in hidden_text(text)]
    joined = " ".join(texts)
    mentioned = sorted(n for n in other_tools if re.search(rf"\b{re.escape(n)}\b", joined))
    if mentioned:
        signals.append(f"tells the model about other tools ({', '.join(mentioned)})")
    return list(dict.fromkeys(signals))


def descriptions(schema: Any) -> Iterator[str]:
    """Every description string inside a JSON schema."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in ("description", "title") and isinstance(value, str):
                yield value
            else:
                yield from descriptions(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from descriptions(item)


@register
class ToolDefinitionDrift:
    meta: ClassVar[CheckMeta] = tool_check(
        "T-12",
        "Tool definition changed since it was approved",
        (Boundary.B7,),
        ("ASI04",),
        6,
        "Review the new definition. If the change is expected, approve it again with "
        "`llmaudit tools lock`; if not, disconnect the server that changed it.",
        inputs=(InputKind.TOOL_DEFS,),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        scope = context.scope
        try:
            lock = read_lock(scope.root / scope.tool_lock)
        except ValueError as error:
            raise CheckUnavailable(
                f"the tool lockfile {scope.tool_lock} is invalid: {error}"
            ) from error
        if lock is None:
            raise CheckUnavailable(
                f"no approved tool lockfile at {scope.tool_lock}; run "
                "`llmaudit tools lock --scope <file>` to approve the current definitions"
            )
        tools = {(t.definition.source, t.profile.name): t for t in tool_inventory(context)}
        for definition in context.artifacts.tool_definitions:
            tool = tools[(definition.source, definition.name)]
            approved = lock.find(definition.source or "", definition.name)
            if approved is None:
                yield Detection(
                    title=f"Tool '{visible(definition.name)}' isn't in the approved lockfile",
                    location=tool_location(context, tool),
                    evidence=summary(definition),
                    confidence=0.7,
                )
            elif approved.sha256 != digest(definition):
                changed = [
                    part
                    for part, before, now in (
                        ("description", approved.description, definition.description),
                        ("parameters", approved.parameters, definition.parameters),
                    )
                    if before != now
                ]
                yield Detection(
                    title=f"Tool '{visible(definition.name)}' changed since it was approved "
                    f"({' and '.join(changed)})",
                    location=tool_location(context, tool),
                    evidence=f"approved: {visible(approved.description, 150)!r}; "
                    f"now: {visible(definition.description, 300)!r}",
                    confidence=0.95,
                )


# Look-alike characters folded to the Latin letter they imitate (a subset of Unicode TR39).
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
        "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
        "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u0578": "n", "\u057d": "u",
        "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03b9": "i",
        "\u03ba": "k", "\u03c4": "t", "\u03b5": "e", "I": "l", "1": "l", "|": "l",
        "0": "o", "-": "_",
    }
)  # fmt: skip


def skeleton(name: str) -> str:
    """What a name looks like, ignoring look-alike characters and case."""
    return unicodedata.normalize("NFKC", name).translate(_CONFUSABLES).lower()


def edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


@register
class ToolNameShadowing:
    meta: ClassVar[CheckMeta] = tool_check(
        "T-13",
        "Tool name shadows or imitates another tool",
        (Boundary.B7,),
        ("ASI04",),
        6,
        "Give every tool a unique, plain-ASCII name, and reject servers whose tools duplicate "
        "or imitate the names of tools from other sources. A look-alike can capture calls "
        "meant for the real tool.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        inventory = tool_inventory(context)
        for tool in inventory:
            script = mixed_script(tool.profile.name)
            if script:
                yield Detection(
                    title=f"Tool name '{visible(tool.profile.name)}' mixes Latin and "
                    f"{script} letters",
                    location=tool_location(context, tool),
                    evidence=summary(tool.definition),
                    confidence=0.9,
                )
        for first, second in combinations(inventory, 2):
            if first.profile.source == second.profile.source:
                continue
            a, b = first.profile.name, second.profile.name
            if a == b:
                title, confidence = f"Two sources define a tool named '{a}'", 0.9
            elif skeleton(a) == skeleton(b):
                title, confidence = f"Tool '{visible(b)}' looks like '{visible(a)}'", 0.9
            elif min(len(a), len(b)) >= 6 and edit_distance(a, b) == 1:
                title, confidence = f"Tool '{visible(b)}' is one character away from '{a}'", 0.5
            else:
                continue
            yield Detection(
                title=title,
                location=tool_location(context, second),
                evidence=f"{first.profile.source}: {summary(first.definition, 120)} | "
                f"{second.profile.source}: {summary(second.definition, 120)}",
                confidence=confidence,
            )
