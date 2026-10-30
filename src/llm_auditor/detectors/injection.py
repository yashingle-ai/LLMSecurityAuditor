"""Prompt injection seen in logs and documents: P-07 (user messages), P-08 (documents the
app retrieves), and T-03 (tool results).

In logs, injection attempts are incidents: attacks someone tried, with whether they
worked. A successful one is evidence for the weakness it got through.
"""

from collections.abc import Iterator
from typing import ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.classifiers import Verdict
from llm_auditor.detectors._trace import (
    injection_classifier,
    leaks_prompt,
    log_location,
    outcome,
    tool_capabilities,
    tool_steps,
)
from llm_auditor.extractors import extract_text
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    InputKind,
    Interaction,
    Location,
    Role,
    Surface,
)

AMPLIFIERS = frozenset(
    {
        Capability.EXTERNAL_COMMUNICATION,
        Capability.CODE_EXECUTION,
        Capability.FILE_WRITE,
        Capability.DESTRUCTIVE,
        Capability.FINANCIAL,
        Capability.WRITES_MEMORY,
    }
)
EXCERPT = 300


def excerpt(text: str, limit: int = EXCERPT) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def tool_names(context: AuditContext, interaction: Interaction) -> set[str]:
    return set(tool_capabilities(context)) | {t.name for t in interaction.tool_definitions}


def _signals(verdict: Verdict) -> str:
    return ", ".join(verdict.signals) or "classifier"


@register
class InjectionInUserMessages:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="P-07",
        title="Prompt injection attempt in a user message",
        surface=Surface.PROMPT,
        kind=FindingKind.INCIDENT,
        min_access=Access.GRAY,
        inputs=(InputKind.LOGS,),
        boundaries=(Boundary.B1,),
        maps_to=("LLM01", "LLM07"),
        base_impact=5,
        amplified_by=AMPLIFIERS,
        remediation=(
            "Assume users will try this. Keep secrets out of the prompt, give the agent only the "
            "tools and data the user may use, and filter both what comes in and what goes out."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        classifier = injection_classifier(context)
        for interaction in context.artifacts.interactions:
            for index, message in enumerate(interaction.messages):
                if message.role is not Role.USER or not message.content.strip():
                    continue
                verdict = classifier.classify(message.content, "user")
                if verdict.score < classifier.threshold:
                    continue
                result, why = outcome(
                    interaction, index, message.content, tool_names(context, interaction)
                )
                leaked = any(
                    later.role is Role.ASSISTANT
                    and leaks_prompt(interaction.system_prompt, later.content)
                    for later in interaction.messages[index + 1 :]
                )
                yield Detection(
                    title=f"Injection attempt in a user message ({_signals(verdict)})",
                    location=log_location(interaction),
                    evidence=f"{excerpt(message.content)} -> {result}: {why}",
                    confidence=verdict.score,
                    oracle=classifier.oracle,
                    outcome=result,
                    corroborates=("O-03",) if leaked else (),
                )


@register
class InjectionInDocuments:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="P-08",
        title="Prompt injection in a document the app retrieves",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.DOCUMENTS,),
        boundaries=(Boundary.B3,),
        maps_to=("LLM01", "LLM08"),
        base_impact=6,
        amplified_by=AMPLIFIERS,
        remediation=(
            "Remove the instructions from the document and find out how they got in. Extract "
            "only visible text when indexing, strip hidden content (CSS-hidden, white or tiny "
            "text, comments, metadata), and scan documents for injection before indexing them."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        classifier = injection_classifier(context)
        for document in context.artifacts.documents:
            for hidden in document.hidden:
                verdict = classifier.classify(hidden.text, "content")
                if verdict.score >= classifier.threshold:
                    page = f" on page {hidden.page}" if hidden.page else ""
                    yield Detection(
                        title=f"Hidden instructions in a document ({hidden.how}{page})",
                        location=Location(file=document.path),
                        evidence=f"{hidden.how}{page}: {excerpt(hidden.text)} "
                        f"({_signals(verdict)})",
                        # Hidden text that reads as instructions is rarely innocent.
                        confidence=min(0.95, verdict.score + 0.1),
                        oracle=classifier.oracle,
                    )
            paragraphs = [p for p in document.text.split("\n") if p.strip()]
            scored = [(classifier.classify(p, "content"), p) for p in paragraphs]
            if not scored:
                continue
            verdict, paragraph = max(scored, key=lambda pair: pair[0].score)
            if verdict.score >= classifier.threshold:
                yield Detection(
                    title="Instructions aimed at the model in a document",
                    location=Location(file=document.path),
                    evidence=f"{excerpt(paragraph)} ({_signals(verdict)})",
                    confidence=verdict.score,
                    oracle=classifier.oracle,
                )


@register
class InjectionInToolResults:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="T-03",
        title="Prompt injection in a tool result",
        surface=Surface.TOOL,
        kind=FindingKind.INCIDENT,
        min_access=Access.GRAY,
        inputs=(InputKind.LOGS,),
        boundaries=(Boundary.B3,),
        maps_to=("LLM01", "ASI01"),
        base_impact=6,
        amplified_by=AMPLIFIERS,
        remediation=(
            "Treat tool results as untrusted data: scan them for instructions before the model "
            "reads them, mark them clearly as data, and require approval for consequential "
            "actions taken after the agent has read outside content."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        classifier = injection_classifier(context)
        for interaction in context.artifacts.interactions:
            tools = tool_names(context, interaction)
            for step in tool_steps(interaction):
                extraction = extract_text(step.content)
                parts = [("", extraction.text)] + [
                    (f" (hidden: {h.how})", h.text) for h in extraction.hidden
                ]
                scored = [(classifier.classify(text, "content"), how, text) for how, text in parts]
                verdict, how, text = max(scored, key=lambda item: item[0].score)
                if verdict.score < classifier.threshold:
                    continue
                result, why = outcome(interaction, step.index, step.content, tools)
                tool = step.call.name if step.call else "a tool"
                yield Detection(
                    title=f"Prompt injection in a result from {tool}{how}",
                    location=log_location(interaction),
                    evidence=f"{excerpt(text)} ({_signals(verdict)}) -> {result}: {why}",
                    confidence=verdict.score,
                    oracle=classifier.oracle,
                    outcome=result,
                    # P-08 too, if it found the same instructions in a document the app retrieves
                    corroborates=("G-01:tool results", "T-10", f"P-08:{excerpt(text)}"),
                )
