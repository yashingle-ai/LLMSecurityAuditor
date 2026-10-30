"""Find and redact secrets and personal data before anything leaves the process.

Detectors see raw content in memory. Everything shown in the terminal, written
to a report or log, or sent to an LLM goes through ``redact()`` first. The
``find_*`` functions are the shared matching that both redaction and the
secret and PII checks use.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from llm_auditor.rules import SecretPattern, secret_patterns


@dataclass(frozen=True)
class Match:
    kind: str  # rule ID for secrets, e.g. "openai_key"; PII type for personal data, e.g. "email"
    title: str
    start: int
    end: int
    value: str
    generic: bool = False


@dataclass(frozen=True)
class PiiPattern:
    kind: str
    title: str
    placeholder: str
    regex: re.Pattern[str]
    validate: Callable[[str], bool] | None = None


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    checksum = sum(digits[-1::-2]) + sum(sum(divmod(2 * d, 10)) for d in digits[-2::-2])
    return checksum % 10 == 0


PII_PATTERNS: tuple[PiiPattern, ...] = (
    PiiPattern(
        "email",
        "Email address",
        "[EMAIL]",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    PiiPattern(
        "card",
        "Payment card number",
        "[CARD]",
        re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
        _luhn_valid,
    ),
    PiiPattern("ssn", "US Social Security number", "[SSN]", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    PiiPattern(
        "phone",
        "Phone number",
        "[PHONE]",
        re.compile(r"(?<![\w-])(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w-])"),
    ),
)


def find_secrets(text: str) -> list[Match]:
    """Secrets in ``text``, in order. Where patterns overlap, the earlier rule wins."""
    return _non_overlapping(
        Match(
            kind=pattern.id,
            title=pattern.title,
            start=match.start(pattern.group),
            end=match.end(pattern.group),
            value=match[pattern.group],
            generic=pattern.generic,
        )
        for pattern in secret_patterns()
        for match in pattern.regex.finditer(text)
    )


def find_pii(text: str) -> list[Match]:
    """Personal data in ``text``, in order."""
    return _non_overlapping(
        Match(kind=pattern.kind, title=pattern.title, start=m.start(), end=m.end(), value=m[0])
        for pattern in PII_PATTERNS
        for m in pattern.regex.finditer(text)
        if pattern.validate is None or pattern.validate(m[0])
    )


def redact(text: str) -> str:
    """Replace secrets and personal data with placeholders. Idempotent."""
    replacements = {pattern.id: pattern for pattern in secret_patterns()}
    text = _replace(text, find_secrets(text), lambda m: _secret_placeholder(m, replacements))
    placeholders = {pattern.kind: pattern.placeholder for pattern in PII_PATTERNS}
    return _replace(text, find_pii(text), lambda m: placeholders[m.kind])


def redact_data(data: Any) -> Any:
    """``redact()`` every string inside nested dicts and lists."""
    if isinstance(data, str):
        return redact(data)
    if isinstance(data, dict):
        return {key: redact_data(value) for key, value in data.items()}
    if isinstance(data, list | tuple):
        return [redact_data(item) for item in data]
    return data


def mask(secret: str) -> str:
    """Keep just enough of a secret to recognize it: ``acme****cYe3``."""
    if len(secret) <= 12:
        return "****"
    return f"{secret[:4]}****{secret[-4:]}"


def mask_spans(text: str, matches: list[Match]) -> str:
    """``text`` with each match's value masked."""
    return _replace(text, matches, lambda m: mask(m.value))


def _secret_placeholder(match: Match, patterns: dict[str, SecretPattern]) -> str:
    replacement = patterns[match.kind].replacement
    return replacement if replacement is not None else mask(match.value)


def _replace(text: str, matches: list[Match], placeholder: Callable[[Match], str]) -> str:
    for match in sorted(matches, key=lambda m: m.start, reverse=True):
        text = text[: match.start] + placeholder(match) + text[match.end :]
    return text


def _non_overlapping(matches: Iterable[Match]) -> list[Match]:
    kept: list[Match] = []
    for match in matches:
        if not any(match.start < other.end and other.start < match.end for other in kept):
            kept.append(match)
    return sorted(kept, key=lambda m: m.start)
