"""Guardrail checks: G-01 (a boundary with no guardrail) and G-02 (a guardrail that only logs).

The guardrail inventory comes from agent config (a ``guardrails`` section saying
where each guardrail applies and in which mode) and from calls to well-known
guardrail libraries in code.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.detectors.agent_config import agent_configs, config_location, find_keys
from llm_auditor.ingestion import AuditContext
from llm_auditor.inventory import tool_inventory
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

GUARDRAIL_SECTIONS = re.compile(
    r"(?i)^(guardrails?|moderation|safety|content_filters?|input_filters?|output_filters?)$"
)
STAGE_KEYS = ("on", "apply_to", "applies_to", "stages", "boundaries", "scope")
MODE_KEYS = ("mode", "action", "enforcement", "on_violation")
MONITOR_MODES = re.compile(r"(?i)^(monitor\w*|log\w*|dry[_-]?run|audit|shadow|warn\w*|observe)$")
STAGE_NAMES = {
    "user_input": re.compile(r"(?i)^(user_?input|input|inputs|prompt|prompts|request)$"),
    "tool_results": re.compile(
        r"(?i)^(tool_?results?|tool_?outputs?|tools|retrieval|rag|documents|context)$"
    ),
    "model_output": re.compile(r"(?i)^(model_?output|output|outputs|response|completion)$"),
}
STAGE_LABELS = {
    "user_input": "user input",
    "tool_results": "tool results and retrieved content (B3)",
    "model_output": "the model's output (B5)",
}
# Calls to guardrail libraries in code, and the stages they cover.
LIBRARY_CALLS = (
    (re.compile(r"\bscan_prompt\("), ("user_input",)),
    (re.compile(r"\bscan_output\("), ("model_output",)),
    (re.compile(r"\bmoderations\.create\("), ("user_input",)),
    (re.compile(r"\bLLMRails\("), ("user_input", "model_output")),
    (re.compile(r"\bGuard\(\)|\bGuard\.from_\w+\("), ("model_output",)),
)


@dataclass
class Guardrail:
    name: str
    where: str  # file it was found in
    stages: set[str] = field(default_factory=set)
    mode: str | None = None


def guardrail_inventory(context: AuditContext) -> list[Guardrail]:
    found = []
    for config, _, section in find_keys(agent_configs(context), GUARDRAIL_SECTIONS):
        for name, settings in section.items() if isinstance(section, dict) else []:
            if not isinstance(settings, dict) or settings.get("enabled") is False:
                continue
            guardrail = Guardrail(str(name), config.path, mode=_mode(settings))
            for key in STAGE_KEYS:
                # YAML 1.1 reads a bare `on:` key as the boolean true; accept it as "on".
                values = settings.get(key) or (settings.get(True) if key == "on" else None) or []
                for value in values if isinstance(values, list) else [values]:
                    guardrail.stages |= {s for s, p in STAGE_NAMES.items() if p.match(str(value))}
            found.append(guardrail)
    for source in context.artifacts.source_files:
        text = context.read_text(source.path) or ""
        for pattern, stages in LIBRARY_CALLS:
            if pattern.search(text):
                found.append(Guardrail(pattern.pattern, source.path, set(stages)))
    return found


def _mode(settings: dict[str, Any]) -> str | None:
    return next((str(settings[key]) for key in MODE_KEYS if key in settings), None)


@register
class MissingGuardrail:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="G-01",
        title="No guardrail on a boundary that needs one",
        surface=Surface.CONFIG,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.CONFIG_FILES, InputKind.SOURCE_DIRS),
        boundaries=(Boundary.B3, Boundary.B5),
        maps_to=("LLM01", "LLM05"),
        base_impact=5,
        remediation=(
            "Apply guardrails where untrusted text enters or leaves: on tool results and "
            "retrieved documents before the model reads them, and on the model's output before "
            "it's shown or acted on, not only on what the user types."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        guardrails = guardrail_inventory(context)
        if not guardrails:
            configs = context.artifacts.config_files
            yield Detection(
                title="No guardrails found",
                location=Location(file=configs[0].path if configs else None, artifact="guardrails"),
                evidence="no guardrails section in the agent config and no guardrail library calls",
                confidence=0.5,
                kind=FindingKind.HARDENING,
            )
            return
        covered = set().union(*(g.stages for g in guardrails))
        needed = {"model_output"}
        if any(
            Capability.INGESTS_UNTRUSTED_CONTENT in t.profile.capabilities
            for t in tool_inventory(context)
        ):
            needed.add("tool_results")
        anchor = guardrails[0]
        config = next((c for c in context.artifacts.config_files if c.path == anchor.where), None)
        location = (
            config_location(context, config, anchor.name) if config else Location(file=anchor.where)
        )
        for stage in sorted(needed - covered):
            yield Detection(
                title=f"No guardrail checks {STAGE_LABELS[stage]}",
                location=location,
                evidence=f"unguarded: {STAGE_LABELS[stage]}; guardrails cover: "
                + (", ".join(STAGE_LABELS[s] for s in sorted(covered)) or "nothing identifiable"),
                confidence=0.8,
            )


@register
class MonitorOnlyGuardrail:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="G-02",
        title="Guardrail only logs instead of blocking",
        surface=Surface.CONFIG,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.CONFIG_FILES,),
        boundaries=(Boundary.B3, Boundary.B5),
        maps_to=("LLM01",),
        base_impact=4,
        remediation=(
            "Switch the guardrail to blocking once its false positives are acceptable. A "
            "monitor-only guardrail records an attack but doesn't stop it."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for guardrail in guardrail_inventory(context):
            if guardrail.mode and MONITOR_MODES.match(guardrail.mode):
                config = next(
                    c for c in context.artifacts.config_files if c.path == guardrail.where
                )
                yield Detection(
                    title=f"Guardrail '{guardrail.name}' only logs (mode: {guardrail.mode})",
                    location=config_location(context, config, guardrail.mode),
                    evidence=f"{guardrail.name}: mode {guardrail.mode}, on "
                    + (", ".join(sorted(guardrail.stages)) or "unspecified stages"),
                    confidence=0.9,
                )
