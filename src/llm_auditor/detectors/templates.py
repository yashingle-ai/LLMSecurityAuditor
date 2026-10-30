"""P-03: untrusted values interpolated into prompt templates without delimiters.

A template variable named like user-supplied content (``customer_message``,
``question``, ``document``) that sits in the prompt as bare text is
indistinguishable, to the model, from the developer's instructions. Delimiting
it (an XML-style tag pair, a code fence, triple quotes, or JSON encoding) is the
standard mitigation. This is a heuristic based on variable names.
"""

import re
from collections.abc import Iterator
from typing import ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._text import line_at, line_number
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Surface,
)

_UNTRUSTED = re.compile(
    r"(?i)user|customer|client|input|message|query|question|request|content|text|document"
    r"|email|page|body|comment|feedback|transcript|conversation|history|note|review"
)
_JINJA_USE = re.compile(r"\{\{\s*([A-Za-z_]\w*)[^}]*\}\}")
_FORMAT_USE = re.compile(r"(?<!\{)\{([A-Za-z_]\w*)(?:![rsa])?(?::[^{}]*)?\}(?!\})")
_JSON_FILTER = re.compile(r"\|\s*tojson\b")
_OPEN_TAG = re.compile(r"<([A-Za-z_][\w-]*)(?:\s[^<>]*)?>")


def undelimited_variables(text: str) -> Iterator[tuple[int, str, str]]:
    """(line number, variable, line text) for untrusted-looking variables placed as bare text."""
    for pattern in (_JINJA_USE, _FORMAT_USE):
        for use in pattern.finditer(text):
            name = use[1]
            if not _UNTRUSTED.search(name) or _JSON_FILTER.search(use[0]):
                continue
            if _delimited(text[: use.start()], text[use.end() :]):
                continue
            yield line_number(text, use.start()), name, line_at(text, use.start()).strip()


def _delimited(before: str, after: str) -> bool:
    if before.count("```") % 2 == 1 or before.count('"""') % 2 == 1:
        return True
    for tag in reversed(_OPEN_TAG.findall(before)):
        closing = f"</{tag}>"
        if closing not in before[before.rfind(f"<{tag}") :] and closing in after:
            return True
    return False


@register
class UndelimitedTemplateVariables:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="P-03",
        title="Untrusted template variable without delimiters",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.PROMPT_DIRS,),
        boundaries=(Boundary.B2,),
        maps_to=("LLM01",),
        base_impact=4,
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
            "Wrap untrusted values in clear delimiters, such as <customer_message>…"
            "</customer_message>, tell the model the content is data rather than instructions, "
            "and escape the delimiter characters inside the value."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for prompt in context.artifacts.prompts:
            for line, name, text in undelimited_variables(prompt.text):
                yield Detection(
                    title=f"Template variable '{name}' inserted without delimiters",
                    location=Location(file=prompt.path, line=line),
                    evidence=text,
                    confidence=0.6,
                )
