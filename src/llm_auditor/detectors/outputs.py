"""What the model said: O-01 (personal data), O-02 (secrets), O-03 (its system prompt),
O-04 (payloads for downstream sinks), and O-05 (links that carry data out).

These read the assistant's replies in logged runs.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import parse_qsl, urlsplit

from llm_auditor.checks import CheckUnavailable, Detection, register
from llm_auditor.detectors._text import line_at
from llm_auditor.detectors._trace import fragments, leaks_prompt, log_location, views
from llm_auditor.detectors.code import semgrep_matches
from llm_auditor.detectors.injection import excerpt
from llm_auditor.detectors.pii import personal_data
from llm_auditor.detectors.secrets import secret_hits
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    CheckMeta,
    FindingKind,
    InputKind,
    Interaction,
    Location,
    Oracle,
    Role,
    Surface,
)


def _output_check(
    check_id: str,
    title: str,
    maps_to: tuple[str, ...],
    base_impact: int,
    remediation: str,
    kind: FindingKind = FindingKind.WEAKNESS,
) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title=title,
        surface=Surface.OUTPUT,
        kind=kind,
        min_access=Access.GRAY,
        inputs=(InputKind.LOGS,),
        boundaries=(Boundary.B5,),
        maps_to=maps_to,
        base_impact=base_impact,
        remediation=remediation,
    )


def replies(interaction: Interaction) -> Iterator[str]:
    for message in interaction.messages:
        if message.role is Role.ASSISTANT and message.content.strip():
            yield message.content


def _said_by_user(interaction: Interaction, value: str) -> bool:
    return any(m.role is Role.USER and value in m.content for m in interaction.messages)


@dataclass
class _Tally:
    """One finding's worth of sightings across several logged runs."""

    location: Location
    evidence: str
    confidence: float
    runs: set[str] = field(default_factory=set)

    def count(self) -> str:
        return f"{len(self.runs)} run{'s' if len(self.runs) != 1 else ''}"


@register
class PiiInResponses:
    meta: ClassVar[CheckMeta] = _output_check(
        "O-01",
        "Personal data in model responses",
        ("LLM02",),
        5,
        "Find where the data came from (the prompt, a tool, or another user's records) and "
        "stop it reaching the model, or redact personal data from responses before they're "
        "shown. Tools should return only the requesting user's own data.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        tallies: dict[tuple[str | None, str], _Tally] = {}
        for interaction in context.artifacts.interactions:
            location = log_location(interaction)
            for reply in replies(interaction):
                for match in personal_data(reply):
                    if _said_by_user(interaction, match.value):
                        continue  # repeating the user's own words back to them
                    key = (location.file, match.title)
                    # The type leads the evidence: two types on one line are two findings.
                    evidence = f"{match.title}: {line_at(reply, match.start).strip()[:300]}"
                    tally = tallies.setdefault(key, _Tally(location, evidence, 0.8))
                    tally.runs.add(interaction.id)
        for (_, title), tally in tallies.items():
            yield Detection(
                title=f"{title} in model responses ({tally.count()})",
                location=tally.location,
                evidence=tally.evidence,  # raw; the runner redacts it
                confidence=tally.confidence,
            )


@register
class SecretsInResponses:
    meta: ClassVar[CheckMeta] = _output_check(
        "O-02",
        "Secret or credential in model responses",
        ("LLM02", "LLM07"),
        8,
        "Rotate the credential now, then remove it from wherever the model read it (the "
        "system prompt or a tool result). Scan responses for credentials before they're shown.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        tallies: dict[tuple[str | None, str], tuple[_Tally, bool, str]] = {}
        for interaction in context.artifacts.interactions:
            location = log_location(interaction)
            internal = [interaction.system_prompt or ""] + [
                m.tool_result.content for m in interaction.messages if m.tool_result
            ]
            for reply in replies(interaction):
                for hit in secret_hits(reply):
                    leaked = any(hit.value in text for text in internal)
                    key = (location.file, hit.value)
                    if key not in tallies:
                        tallies[key] = (
                            _Tally(location, hit.evidence, hit.confidence),
                            leaked,
                            hit.title,
                        )
                    tallies[key][0].runs.add(interaction.id)
        for tally, leaked, title in tallies.values():
            source = " from the system prompt or a tool result" if leaked else ""
            yield Detection(
                title=f"{title} in model responses{source} ({tally.count()})",
                location=tally.location,
                evidence=tally.evidence,
                confidence=tally.confidence,
                # Seen leaving: the secret the model was given is in what it said.
                kind=FindingKind.VULNERABILITY if leaked else None,
                oracle=Oracle.DETERMINISTIC if leaked else Oracle.RULE,
                corroborates=("P-01",),
            )


@register
class SystemPromptLeak:
    meta: ClassVar[CheckMeta] = _output_check(
        "O-03",
        "System prompt revealed in a response",
        ("LLM07",),
        3,
        "Assume users can extract the system prompt: keep secrets, personal data, and "
        "internal details out of it. Planting a canary token in it shows when it leaks.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        canaries = [c for c in context.scope.canaries if c.strip()]
        tallies: dict[tuple[str | None, bool], _Tally] = {}
        for interaction in context.artifacts.interactions:
            prompt = interaction.system_prompt or ""
            for reply in replies(interaction):
                canary = next((c for c in canaries if c in reply), None)
                if canary is None and not leaks_prompt(prompt, reply):
                    continue
                sensitive = bool(list(secret_hits(prompt)) or personal_data(prompt))
                how = f"canary {canary!r} found" if canary else "most of the system prompt"
                key = (log_location(interaction).file, sensitive)
                tally = tallies.setdefault(
                    key,
                    _Tally(
                        log_location(interaction),
                        f"{how}: {excerpt(reply)}",
                        0.95 if canary else 0.85,
                    ),
                )
                tally.runs.add(interaction.id)
        for (_, sensitive), tally in tallies.items():
            if sensitive:
                yield Detection(
                    title=f"System prompt leaked, with the secrets or personal data in it "
                    f"({tally.count()})",
                    location=tally.location,
                    evidence=tally.evidence,
                    confidence=tally.confidence,
                    kind=FindingKind.VULNERABILITY,
                    oracle=Oracle.DETERMINISTIC,
                    corroborates=("P-01", "P-02"),
                )
            else:
                yield Detection(
                    title=f"The model reveals its system prompt; it holds nothing sensitive "
                    f"({tally.count()})",
                    location=tally.location,
                    evidence=tally.evidence,
                    confidence=tally.confidence,
                    kind=FindingKind.HARDENING,
                )


PAYLOADS = (
    (
        "HTML or script",
        re.compile(
            r"(?i)<script\b|<iframe\b|\bjavascript:|<[a-z]+[^>]*\son[a-z]+\s*=|<svg[^>]*\son\w+\s*="
        ),
        ("C-04",),
    ),
    (
        "SQL",
        re.compile(
            r"(?i)'\s*(or|and)\s+'?\w+'?\s*=\s*'?\w+|\bunion\s+(all\s+)?select\b"
            r"|;\s*(drop|delete|truncate|alter)\s+(table|from)\b"
        ),
        ("C-03",),
    ),
    (
        "shell",
        re.compile(
            r"(?i);\s*(rm\s+-rf|curl\s|wget\s|nc\s+-e|bash\s+-i)|\|\s*(sh|bash)\b"
            r"|\$\((curl|wget)\b|/dev/tcp/"
        ),
        ("C-02",),
    ),
)


@register
class PayloadForDownstreamSink:
    meta: ClassVar[CheckMeta] = _output_check(
        "O-04",
        "Dangerous payload in output reaches a sink",
        ("LLM05",),
        6,
        "Treat model output as untrusted input to whatever consumes it: escape it for HTML, "
        "pass it to SQL only as parameters, and never to a shell or an interpreter.",
        kind=FindingKind.INCIDENT,
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        sinks = _sinks(context)
        for interaction in context.artifacts.interactions:
            for reply in replies(interaction):
                for kind, pattern, checks in PAYLOADS:
                    found = pattern.search(reply)
                    if found is None:
                        continue
                    payload = line_at(reply, found.start()).strip()[:200]
                    sink = next((sinks[c] for c in checks if c in sinks), None)
                    if sink is not None:
                        yield Detection(
                            title=f"{kind} payload in a response, and the app passes responses "
                            f"to that sink unescaped",
                            location=log_location(interaction),
                            evidence=f"{payload} -> {sink}",
                            confidence=0.8,
                            kind=FindingKind.VULNERABILITY,
                            corroborates=checks,
                        )
                    else:
                        yield Detection(
                            title=f"{kind} payload in a response",
                            location=log_location(interaction),
                            evidence=f"{payload} (no unescaped sink for it found in the code)",
                            confidence=0.7,
                        )


def _sinks(context: AuditContext) -> dict[str, str]:
    """Where the code passes model output to each kind of sink (C-02, C-03, C-04)."""
    try:
        matches = semgrep_matches(context)
    except CheckUnavailable:
        return {}
    found: dict[str, str] = {}
    for match in matches:
        found.setdefault(match.check_id, f"{match.check_id} at {match.path}:{match.start_line}")
    return found


MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)")
HTML_IMAGE = re.compile(r"(?i)<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)")
TERMINAL_ESCAPE = re.compile(r"\x1b\[|\x1b\]8;|\x9b")
SPREADSHEET_FORMULA = re.compile(
    r"(?im)(^|[,;\t\"])\s*[=+@-]\s*(HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMAGE"
    r"|WEBSERVICE|cmd\s*\|)"
)
MIN_DATA = 20  # a query value this long can carry real data


@register
class ExfiltrationLinks:
    meta: ClassVar[CheckMeta] = _output_check(
        "O-05",
        "Response carries data out through links, images, or escapes",
        ("LLM05", "LLM02"),
        6,
        "Don't render images or links to hosts outside an allow-list in model output, strip "
        "query strings from untrusted URLs, strip terminal escape sequences, and prefix cells "
        "that start with =, +, - or @ before exporting output to spreadsheets.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        tallies: dict[tuple[str | None, str], _Tally] = {}
        for interaction in context.artifacts.interactions:
            context_values = _conversation_values(interaction)
            for reply in replies(interaction):
                for title, evidence, confidence in _channels(reply, context_values):
                    key = (log_location(interaction).file, title)
                    tally = tallies.setdefault(
                        key, _Tally(log_location(interaction), evidence, confidence)
                    )
                    tally.runs.add(interaction.id)
        for (_, title), tally in tallies.items():
            yield Detection(
                title=f"{title} ({tally.count()})",
                location=tally.location,
                evidence=tally.evidence,
                confidence=tally.confidence,
            )


def _conversation_values(interaction: Interaction) -> set[str]:
    texts = [m.content for m in interaction.messages if m.role is Role.USER]
    texts += [m.tool_result.content for m in interaction.messages if m.tool_result]
    return {value for text in texts for value in fragments(text)}


def _channels(reply: str, conversation: set[str]) -> Iterator[tuple[str, str, float]]:
    """(title, evidence, confidence) for each way ``reply`` could carry data out."""
    links = [(url, "image", 0.85) for url in MARKDOWN_IMAGE.findall(reply)]
    links += [(url, "image", 0.85) for url in HTML_IMAGE.findall(reply)]
    links += [(url, "link", 0.6) for url in MARKDOWN_LINK.findall(reply)]
    for url, how, confidence in links:
        parts = urlsplit(url)
        values = [value for _, value in parse_qsl(parts.query, keep_blank_values=True)]
        carried = [
            value
            for value in values
            if any(fragment in view for view in views(value).values() for fragment in conversation)
        ]
        if carried:
            yield (
                f"An {how} URL to {parts.hostname} carries conversation data",
                f"{url[:300]}",
                min(0.95, confidence + 0.1),
            )
        elif how == "image" and any(len(value) >= MIN_DATA for value in values):
            yield (
                f"An image URL to {parts.hostname} carries data in its query",
                url[:300],
                confidence,
            )
    if TERMINAL_ESCAPE.search(reply):
        yield "Terminal escape sequences in a response", excerpt(repr(reply)), 0.8
    formula = SPREADSHEET_FORMULA.search(reply)
    if formula:
        yield "Spreadsheet formula in a response", line_at(reply, formula.start()).strip(), 0.8
