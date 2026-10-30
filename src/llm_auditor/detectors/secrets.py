"""P-01 (secrets in prompts) and A-01 (keys exposed in code, configs, logs, HTTP traffic)."""

import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._text import (
    har_texts,
    interaction_texts,
    line_at,
    line_number,
    split_source,
)
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Surface,
)
from llm_auditor.redaction import Match, find_secrets, mask_spans

# Generic matches (no known format) are only reported with corroborating evidence.
_SECRET_KEYWORD = re.compile(r"(?i)api[_-]?key|secret|token|passw(?:or)?d|credential|bearer|auth")
_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9_+/=-])")
_PLACEHOLDER = re.compile(
    r"(?i)your|example|replace|change_?me|placeholder|redacted|dummy|sample|xxxx|\*\*\*"
)
MIN_ENTROPY = 4.0  # bits per character: random keys are well above, words and identifiers below


@dataclass(frozen=True)
class SecretHit:
    title: str
    value: str
    line: int
    evidence: str  # the line it was found on, with every secret on it masked
    confidence: float


def secret_hits(text: str) -> Iterator[SecretHit]:
    """Secrets in ``text``: known credential formats, plus high-entropy strings near a keyword."""
    matches = [m for m in find_secrets(text) if not m.generic or _plausible(m.value)]
    matches += _high_entropy(text, taken=matches)
    for match in sorted(matches, key=lambda m: m.start):
        start = text.rfind("\n", 0, match.start) + 1
        end = text.find("\n", match.start)
        end = len(text) if end == -1 else end
        on_line = [_shifted(m, start) for m in matches if start <= m.start and m.end <= end]
        yield SecretHit(
            title=match.title,
            value=match.value,
            line=line_number(text, match.start),
            evidence=mask_spans(text[start:end], on_line).strip(),
            confidence=0.6 if match.generic else 0.95,
        )


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _plausible(value: str) -> bool:
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_letter and has_digit and not _PLACEHOLDER.search(value) and entropy(value) >= 3.0


def _high_entropy(text: str, taken: list[Match]) -> list[Match]:
    found = []
    for candidate in _CANDIDATE.finditer(text):
        start, end, value = candidate.start(), candidate.end(), candidate[0]
        if any(start < m.end and m.start < end for m in taken):
            continue
        if not _SECRET_KEYWORD.search(line_at(text, start)):
            continue
        if _plausible(value) and entropy(value) >= MIN_ENTROPY:
            found.append(
                Match(
                    "high_entropy",
                    "High-entropy string near a secret keyword",
                    start,
                    end,
                    value,
                    True,
                )
            )
    return found


def _shifted(match: Match, offset: int) -> Match:
    return Match(match.kind, match.title, match.start - offset, match.end - offset, match.value)


@register
class SecretsInPrompts:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="P-01",
        title="Secret or credential embedded in a prompt",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.PROMPT_DIRS,),
        boundaries=(Boundary.B2,),
        maps_to=("LLM02", "LLM07"),
        base_impact=7,
        remediation=(
            "Remove the credential from the prompt and rotate it. Users can extract system "
            "prompts, so treat everything in one as public. Let the backend use the credential, "
            "loaded from a secrets manager or the environment, instead of the model."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for prompt in context.artifacts.prompts:
            for hit in secret_hits(prompt.text):
                yield Detection(
                    title=f"{hit.title} in a prompt",
                    location=Location(file=prompt.path, line=hit.line),
                    evidence=hit.evidence,
                    confidence=hit.confidence,
                )


@dataclass
class _Sighting:
    """One secret seen across several log records or HTTP entries."""

    hit: SecretHit
    file: str
    line: int | None
    records: set[str] = field(default_factory=set)


@register
class ExposedApiKeys:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="A-01",
        title="API key exposed in code, config, logs, or HTTP traffic",
        surface=Surface.API,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.SOURCE_DIRS, InputKind.CONFIG_FILES, InputKind.LOGS, InputKind.HAR),
        boundaries=(Boundary.B8,),
        maps_to=("LLM02",),
        base_impact=7,
        remediation=(
            "Rotate the key, then remove it. Keep provider keys on the server, out of client "
            "code, URLs, and committed config, and redact credentials before anything is logged."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        files = [
            *((f.path, "source code") for f in context.artifacts.source_files),
            *((f.path, "a config file") for f in context.artifacts.config_files),
        ]
        for path, where in files:
            for hit in secret_hits(context.read_text(path) or ""):
                yield Detection(
                    title=f"{hit.title} in {where}",
                    location=Location(file=path, line=hit.line),
                    evidence=hit.evidence,
                    confidence=hit.confidence,
                )
        logs = ((i.source, interaction_texts(i)) for i in context.artifacts.interactions)
        yield from _grouped(logs, "logs")
        traffic = ((e.source, har_texts(e)) for e in context.artifacts.har_entries)
        yield from _grouped(traffic, "HTTP traffic")


def _grouped(records: Iterable[tuple[str, Iterable[str]]], where: str) -> Iterator[Detection]:
    """One detection per secret per file, however many records repeat it."""
    sightings: dict[tuple[str, str], _Sighting] = {}
    for source, texts in records:
        file, line = split_source(source)
        for text in texts:
            for hit in secret_hits(text):
                sighting = sightings.setdefault((file, hit.value), _Sighting(hit, file, line))
                sighting.records.add(source)
    for sighting in sightings.values():
        count = len(sighting.records)
        yield Detection(
            title=f"{sighting.hit.title} in {where} ({count} record{'s' if count > 1 else ''})",
            location=Location(file=sighting.file, line=sighting.line),
            evidence=sighting.hit.evidence,
            confidence=sighting.hit.confidence,
        )
