"""Personal data: P-02 (in prompts) and A-06 (stored unredacted in logs).

Pattern-based (emails, phone numbers, payment cards, US SSNs), shared with
redaction. Names and street addresses need NER (e.g. Microsoft Presidio) and are
not detected yet.
"""

from collections import Counter, defaultdict
from collections.abc import Iterator
from typing import ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._text import interaction_texts, line_at, line_number, split_source
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
from llm_auditor.redaction import Match, find_pii

# RFC 2606/6761 reserved names: addresses here are placeholders, not real people.
_RESERVED_DOMAINS = ("example.com", "example.org", "example.net", ".example", ".test", ".invalid")
_CONFIDENCE = {"email": 0.95, "card": 0.9, "ssn": 0.85, "phone": 0.7}


@register
class PiiInPrompts:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="P-02",
        title="Personal data embedded in a prompt",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.PROMPT_DIRS,),
        boundaries=(Boundary.B2,),
        maps_to=("LLM02",),
        base_impact=5,
        remediation=(
            "Replace real personal data in prompts and examples with obviously fake "
            "placeholders. Prompts go to the model provider on every request, end up in logs, "
            "and can be extracted by users."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for prompt in context.artifacts.prompts:
            by_line: dict[int, list[Match]] = defaultdict(list)
            for match in personal_data(prompt.text):
                by_line[line_number(prompt.text, match.start)].append(match)
            for line, matches in by_line.items():
                kinds = list(dict.fromkeys(m.title.lower() for m in matches))
                # The evidence is the raw line; the runner redacts it before reporting.
                yield Detection(
                    title=f"Personal data in a prompt ({', '.join(kinds)})",
                    location=Location(file=prompt.path, line=line),
                    evidence=line_at(prompt.text, matches[0].start).strip(),
                    confidence=max(_CONFIDENCE.get(m.kind, 0.8) for m in matches),
                )


def personal_data(text: str) -> list[Match]:
    """Personal data in ``text``, leaving out addresses at reserved example domains."""
    return [m for m in find_pii(text) if not (m.kind == "email" and _reserved(m.value))]


@register
class PiiInLogs:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="A-06",
        title="Personal data stored unredacted in logs",
        surface=Surface.API,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.LOGS,),
        boundaries=(Boundary.B8,),
        maps_to=("LLM02",),
        base_impact=4,
        remediation=(
            "Redact personal data (and secrets) before prompts, outputs, and tool calls are "
            "logged, keep raw logs only where they are needed, with access control and a "
            "retention limit."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        kinds: dict[str, Counter[str]] = defaultdict(Counter)
        example: dict[str, tuple[int | None, str, float]] = {}
        for interaction in context.artifacts.interactions:
            file, line = split_source(interaction.source)
            for text in interaction_texts(interaction):
                for match in personal_data(text):
                    kinds[file][match.title.lower()] += 1
                    confidence = _CONFIDENCE.get(match.kind, 0.8)
                    if confidence > example.get(file, (None, "", 0.0))[2]:
                        example[file] = (line, line_at(text, match.start).strip(), confidence)
        for file, counts in kinds.items():
            line, evidence, confidence = example[file]
            listed = ", ".join(f"{kind} ({count})" for kind, count in counts.most_common())
            yield Detection(
                title=f"Personal data stored unredacted in logs: {listed}",
                location=Location(file=file, line=line),
                evidence=evidence[:300],  # raw; the runner redacts it
                confidence=confidence,
            )


def _reserved(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].lower()
    return any(
        domain == d or domain.endswith(d if d.startswith(".") else f".{d}")
        for d in _RESERVED_DOMAINS
    )
