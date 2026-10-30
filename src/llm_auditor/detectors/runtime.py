"""What tools did in logged runs: T-02 (dangerous arguments), T-04 (sensitive data in
results), and taint tracking between tools: T-05 (outside content into code or
destructive actions), T-07 (private data sent out), T-16 (outside content into memory).

Taint tracking follows values from one tool's results into a later call's arguments,
as is, URL-encoded, or base64-encoded. A match is a recorded fact, not a guess, so these
are reported as vulnerabilities.
"""

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._trace import (
    calls_after,
    fragments,
    injection_classifier,
    log_location,
    taint,
    tool_capabilities,
    tool_steps,
)
from llm_auditor.detectors.injection import AMPLIFIERS, excerpt
from llm_auditor.detectors.pii import personal_data
from llm_auditor.detectors.secrets import secret_hits
from llm_auditor.ingestion import AuditContext
from llm_auditor.inventory import properties, tool_inventory
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    IncidentOutcome,
    InputKind,
    Interaction,
    Oracle,
    Surface,
    ToolCall,
)


def _tool_check(
    check_id: str,
    title: str,
    boundary: Boundary,
    maps_to: tuple[str, ...],
    base_impact: int,
    remediation: str,
    kind: FindingKind = FindingKind.VULNERABILITY,
    amplified_by: frozenset[Capability] = frozenset(),
) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title=title,
        surface=Surface.TOOL,
        kind=kind,
        min_access=Access.GRAY,
        inputs=(InputKind.LOGS,),
        boundaries=(boundary,),
        maps_to=maps_to,
        base_impact=base_impact,
        amplified_by=amplified_by,
        remediation=remediation,
    )


# T-02: arguments that attack the system behind the tool.

SQL_ATTACK = re.compile(
    r"(?i)'\s*(or|and)\s+'?\w+'?\s*=\s*'?\w+|\bunion\s+(all\s+)?select\b"
    r"|;\s*(drop|delete|truncate|alter|insert|update)\s+\w+|'\s*;?\s*--"
)
COMMAND_INJECTION = re.compile(
    r"(;|&&|\|\||\|)\s*(rm|cat|curl|wget|nc|bash|sh|python3?|perl|chmod|chown|id|whoami|uname"
    r"|ping|nslookup|env)\b|`[^`]*\b(curl|wget|id|whoami|cat)\b[^`]*`|\$\([^)]+\)"
)
DANGEROUS_COMMAND = re.compile(
    r"(?i)\brm\s+-\w*r\w*f?\s+(/|~|\*)|\b(curl|wget)\b[^|\n]*\|\s*(sh|bash|python)"
    r"|/dev/tcp/|\bnc\s+(-\w+\s+)*-e\b|\bbash\s+-i\b|\bchmod\s+(-R\s+)?777\s+/"
    r"|/etc/shadow|\.ssh/(id_|authorized_keys)|\bos\.environ\b|\bprintenv\b"
)
PATH_TRAVERSAL = re.compile(
    r"(?i)\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|^/etc/(passwd|shadow|hosts)\b|(^|/)\.env$"
    r"|^~?/?\.ssh/|/proc/self/"
)
URL = re.compile(r"(?i)\b(?:https?|file|gopher|dict|ftp)://[^\s\"'<>]+")
INTERNAL_NAMES = re.compile(
    r"(?i)^(localhost|metadata\.google\.internal|metadata|.*\.internal|.*\.local)$"
)
REJECTED = re.compile(
    r"(?i)\b(invalid|not allowed|rejected|denied|forbidden|refused|must be one of|unknown"
    r"|error|not permitted|blocked|can only)\b"
)
# A result like this means the value was most likely handled as plain data.
EMPTY = re.compile(r"(?i)^\W*(no (matching|results?|rows|records)\b|not found\b|none\W*$|\W*$)")


def argument_attacks(value: str, runs_code: bool) -> list[tuple[str, tuple[str, ...]]]:
    """(attack, checks it would exploit) for one argument value."""
    found: list[tuple[str, tuple[str, ...]]] = []
    if runs_code:
        if DANGEROUS_COMMAND.search(value):
            found.append(("A dangerous command", ("T-09", "T-18")))
        return found
    if SQL_ATTACK.search(value):
        found.append(("SQL injection", ("C-03",)))
    if COMMAND_INJECTION.search(value):
        found.append(("Command injection", ("C-02",)))
    if PATH_TRAVERSAL.search(value):
        found.append(("Path traversal", ("C-05",)))
    for url in URL.findall(value):
        if _internal(url):
            found.append(("A request to an internal address (SSRF)", ("C-05", "T-09")))
    return found


def _internal(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        return True  # file://, gopher://, and the like reach things the web can't
    host = parts.hostname or ""
    if INTERNAL_NAMES.match(host):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _schema_violation(schema: dict[str, Any], name: str, value: Any) -> str | None:
    rule = properties(schema).get(name)
    if not isinstance(rule, dict):
        return None
    if "enum" in rule and value not in rule["enum"]:
        return f"not one of the allowed values {rule['enum']}"
    pattern = rule.get("pattern")
    if isinstance(pattern, str) and isinstance(value, str):
        try:
            if re.search(pattern, value) is None:
                return f"doesn't match the schema pattern {pattern}"
        except re.error:
            return None
    return None


@register
class DangerousToolArguments:
    meta: ClassVar[CheckMeta] = _tool_check(
        "T-02",
        "Dangerous arguments in a tool call",
        Boundary.B4,
        ("LLM05", "LLM06"),
        6,
        "Validate every tool argument in the tool, against its schema and an allow-list: pass "
        "values to SQL as parameters, never to a shell, resolve paths inside one directory, and "
        "block internal addresses. The model's arguments are attacker-influenced input.",
        kind=FindingKind.INCIDENT,
        amplified_by=AMPLIFIERS,
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        capabilities = tool_capabilities(context)
        schemas = {
            tool.definition.name: tool.definition.parameters for tool in tool_inventory(context)
        }
        for interaction in context.artifacts.interactions:
            for call in interaction.tool_calls:
                runs_code = Capability.CODE_EXECUTION in capabilities.get(call.name, frozenset())
                for name, value in _arguments(call.arguments):
                    for attack, checks in argument_attacks(value, runs_code):
                        violation = _schema_violation(schemas.get(call.name, {}), name, value)
                        result, why = _accepted(interaction, call)
                        note = f"; {violation}" if violation else ""
                        yield Detection(
                            title=f"{attack} in {call.name}'s {name} argument",
                            location=log_location(interaction),
                            evidence=f"{call.name}({name}={excerpt(value, 200)!r}){note} -> "
                            f"{result}: {why}",
                            confidence=0.9 if violation else 0.75,
                            outcome=result,
                            corroborates=checks,
                        )


def _arguments(arguments: dict[str, Any], prefix: str = "") -> Iterator[tuple[str, str]]:
    for name, value in arguments.items():
        if isinstance(value, str):
            yield f"{prefix}{name}", value
        elif isinstance(value, dict):
            yield from _arguments(value, f"{prefix}{name}.")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    yield f"{prefix}{name}", item


def _accepted(interaction: Interaction, call: ToolCall) -> tuple[IncidentOutcome, str]:
    step = next((s for s in tool_steps(interaction) if s.call and s.call.id == call.id), None)
    if step is None:
        return IncidentOutcome.UNKNOWN, "no result was logged"
    if step.is_error or REJECTED.search(step.content):
        return IncidentOutcome.FAILED, f"the tool rejected it ({excerpt(step.content, 80)})"
    if EMPTY.match(step.content):
        return IncidentOutcome.FAILED, f"the tool found nothing ({excerpt(step.content, 80)})"
    return IncidentOutcome.SUCCEEDED, "the tool accepted it and returned a result"


@register
class SensitiveDataInToolResults:
    meta: ClassVar[CheckMeta] = _tool_check(
        "T-04",
        "Sensitive data in tool results",
        Boundary.B3,
        ("LLM02", "LLM08"),
        5,
        "Return only what the agent needs: mask card numbers and identifiers, leave out "
        "credentials, and filter records to the requesting user before the model sees them. "
        "Everything in a tool result can end up in a response.",
        kind=FindingKind.WEAKNESS,
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        seen: dict[tuple[str | None, str, str], tuple[Detection, set[str]]] = {}
        for interaction in context.artifacts.interactions:
            location = log_location(interaction)
            for step in tool_steps(interaction):
                tool = step.call.name if step.call else "a tool"
                found = [(m.title, m.value, 0.8) for m in personal_data(step.content)]
                found += [(h.title, h.value, h.confidence) for h in secret_hits(step.content)]
                for title, value, confidence in found:
                    key = (location.file, tool, title)
                    if key not in seen:
                        lines = step.content.splitlines()
                        line = next((x for x in lines if value in x), value)
                        detection = Detection(
                            title=f"{title} in results from {tool}",
                            location=location,
                            evidence=f"{title}: {line.strip()[:300]}",  # redacted later
                            confidence=confidence,
                        )
                        seen[key] = (detection, set())
                    seen[key][1].add(interaction.id)
        for detection, runs in seen.values():
            yield Detection(
                title=f"{detection.title} ({len(runs)} run{'s' if len(runs) != 1 else ''})",
                location=detection.location,
                evidence=detection.evidence,
                confidence=detection.confidence,
            )


@dataclass(frozen=True)
class Flow:
    source: str  # the tool whose result the value came from
    sink: ToolCall
    value: str
    encoding: str


def flows(
    context: AuditContext,
    interaction: Interaction,
    sources: frozenset[Capability],
    sinks: frozenset[Capability],
) -> Iterator[Flow]:
    """Values from results of tools with a ``sources`` capability that reappear in the
    arguments of a later call to a tool with a ``sinks`` capability."""
    capabilities = tool_capabilities(context)
    for step in tool_steps(interaction):
        if step.call is None or not capabilities.get(step.call.name, frozenset()) & sources:
            continue
        values = fragments(step.content)
        for _, call in calls_after(interaction, step.index):
            if call.id == step.call.id or not capabilities.get(call.name, frozenset()) & sinks:
                continue
            found = taint(values, call.arguments)
            if found is not None:
                yield Flow(step.call.name, call, found.value, found.encoding)


def _flow_detections(
    context: AuditContext,
    sources: frozenset[Capability],
    sinks: frozenset[Capability],
    describe: str,
    corroborates: tuple[str, ...],
) -> Iterator[Detection]:
    reported: set[tuple[str | None, str, str]] = set()
    for interaction in context.artifacts.interactions:
        location = log_location(interaction)
        for flow in flows(context, interaction, sources, sinks):
            key = (location.file, flow.source, flow.sink.name)
            if key in reported:
                continue
            reported.add(key)
            encoding = "" if flow.encoding == "as is" else f" ({flow.encoding})"
            yield Detection(
                title=f"{describe}: {flow.source} -> {flow.sink.name}",
                location=location,
                evidence=f"from {flow.source}'s result: {excerpt(flow.value, 160)!r} found in "
                f"{flow.sink.name}'s arguments{encoding}",
                confidence=0.9,
                oracle=Oracle.DETERMINISTIC,
                corroborates=corroborates,
            )


UNTRUSTED = frozenset({Capability.INGESTS_UNTRUSTED_CONTENT})


@register
class UntrustedContentUsedUnsafely:
    meta: ClassVar[CheckMeta] = _tool_check(
        "T-05",
        "Outside content used unsafely by a later tool",
        Boundary.B5,
        ("LLM05", "ASI05"),
        8,
        "Never let content from the web, email, or files decide code that runs, files that are "
        "written, or destructive actions. Require approval after the agent has read outside "
        "content, and run code only in a sandbox with no network or secrets.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        sinks = frozenset(
            {
                Capability.CODE_EXECUTION,
                Capability.FILE_WRITE,
                Capability.DESTRUCTIVE,
                Capability.FINANCIAL,
            }
        )
        yield from _flow_detections(
            context, UNTRUSTED, sinks, "Outside content reached", ("T-09", "T-18")
        )


@register
class ExfiltrationChain:
    meta: ClassVar[CheckMeta] = _tool_check(
        "T-07",
        "Private data sent out by a later tool (exfiltration chain)",
        Boundary.B4,
        ("LLM02", "LLM06", "ASI02"),
        8,
        "Break the chain: don't let one agent both read private data and send to a destination "
        "the model chooses. Fix outbound destinations in code, or require approval for any "
        "outbound call made after private data was read.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield from _flow_detections(
            context,
            frozenset({Capability.READS_PRIVATE_DATA}),
            frozenset({Capability.EXTERNAL_COMMUNICATION}),
            "Private data sent out",
            ("T-10",),
        )


@register
class MemoryPoisoning:
    meta: ClassVar[CheckMeta] = _tool_check(
        "T-16",
        "Memory written from outside content (memory poisoning)",
        Boundary.B6,
        ("ASI06",),
        7,
        "Don't save outside content to long-term memory. Write memory only from what the user "
        "said, with the user's confirmation, record where each memory came from, and treat "
        "recalled memories as data, not instructions.",
        amplified_by=AMPLIFIERS,
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        memory = frozenset({Capability.WRITES_MEMORY})
        yield from _flow_detections(
            context, UNTRUSTED, memory, "Outside content saved to memory", ("G-01:tool results",)
        )
        classifier = injection_classifier(context)
        capabilities = tool_capabilities(context)
        for interaction in context.artifacts.interactions:
            for call in interaction.tool_calls:
                if Capability.WRITES_MEMORY not in capabilities.get(call.name, frozenset()):
                    continue
                for name, value in _arguments(call.arguments):
                    verdict = classifier.classify(value, "content")
                    if verdict.score >= classifier.threshold:
                        yield Detection(
                            title=f"Instructions saved to memory by {call.name}",
                            location=log_location(interaction),
                            evidence=f"{call.name}({name}={excerpt(value, 200)!r}) "
                            f"({', '.join(verdict.signals)})",
                            confidence=verdict.score,
                            oracle=classifier.oracle,
                            kind=FindingKind.WEAKNESS,
                        )
