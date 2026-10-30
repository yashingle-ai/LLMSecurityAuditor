"""Provider account and credential checks: A-10 and T-15.

Much of this can't be seen in code (how long the provider keeps prompts, whether
keys rotate), so these checks read attestations: answers a person gives in the
scope file's ``attestations`` section. A check missing any answer is skipped and
says which ones, instead of passing silently.
"""

import json
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from llm_auditor.checks import CheckUnavailable, Detection, register
from llm_auditor.detectors.agent_config import agent_configs, config_location, find_keys
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Oracle,
    Surface,
)


@dataclass(frozen=True)
class Question:
    key: str
    kind: type
    asks: str
    problem: Callable[[Any], str | None]  # what's wrong with an answer, or None if it's fine


PROVIDER_QUESTIONS = (
    Question(
        "provider_retention_days",
        int,
        "how many days the LLM provider keeps prompts and outputs (0 for zero retention)",
        lambda days: (
            f"the provider keeps prompts and outputs for {days} days" if days > 30 else None
        ),
    ),
    Question(
        "provider_trains_on_data",
        bool,
        "whether the provider may train models on your prompts and outputs",
        lambda yes: "the provider may train on your prompts and outputs" if yes else None,
    ),
    Question(
        "api_keys_scoped",
        bool,
        "whether API keys are restricted to this application (project, models, permissions)",
        lambda yes: None if yes else "API keys aren't restricted to this application",
    ),
    Question(
        "api_key_rotation_days",
        int,
        "how often, in days, API keys are rotated",
        lambda days: f"API keys are only rotated every {days} days" if days > 90 else None,
    ),
    Question(
        "spend_limit",
        bool,
        "whether a hard spend limit is set with the provider",
        lambda yes: None if yes else "there's no spend limit at the provider",
    ),
)
CREDENTIAL_QUESTIONS = (
    Question(
        "agent_credentials_least_privilege",
        bool,
        "whether the agent's credentials allow only what its tools need",
        lambda yes: None if yes else "the agent's credentials allow more than its tools need",
    ),
    Question(
        "agent_credential_max_age_days",
        int,
        "the longest, in days, any agent credential stays valid",
        lambda days: f"agent credentials stay valid for {days} days" if days > 30 else None,
    ),
)

CREDENTIAL_SECTIONS = re.compile(r"(?i)^(credentials|service_accounts|api_keys|tokens)$")
SCOPE_KEYS = re.compile(r"(?i)^(scopes?|roles?|permissions?|access)$")
BROAD_SCOPE = re.compile(r"(?i)^(admin\w*|root|owner|superuser|full[_-]?access|all|\*|.*:\*)$")
LIFETIME_KEYS = re.compile(r"(?i)^(expires|expiry|expiration|ttl\w*|max_age\w*|lifetime\w*)$")


def answers(context: AuditContext, questions: tuple[Question, ...]) -> dict[str, Any]:
    """The scope's answers, or CheckUnavailable naming the missing or malformed ones."""
    given = context.scope.attestations
    missing = [q.key for q in questions if q.key not in given]
    if missing:
        raise CheckUnavailable(
            "needs attestations: " + ", ".join(missing) + " (answer them under `attestations:` "
            "in the scope file)"
        )
    wrong = [
        f"{q.key} should be {'true/false' if q.kind is bool else 'a whole number'}"
        for q in questions
        if not _is(given[q.key], q.kind)
    ]
    if wrong:
        raise CheckUnavailable("invalid attestations: " + "; ".join(wrong))
    return {q.key: given[q.key] for q in questions}


def _is(value: Any, kind: type) -> bool:
    if kind is bool:
        return isinstance(value, bool)
    return isinstance(value, int) and not isinstance(value, bool)


def attested(questions: tuple[Question, ...], given: Mapping[str, Any]) -> Iterator[Detection]:
    for question in questions:
        problem = question.problem(given[question.key])
        if problem:
            yield Detection(
                title=problem[0].upper() + problem[1:],
                location=Location(artifact=f"attestation:{question.key}"),
                evidence=f"{question.key}: {json.dumps(given[question.key])} ({question.asks})",
                confidence=0.9,
                oracle=Oracle.ATTESTATION,
            )


@register
class ProviderAccountSettings:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="A-10",
        title="Provider account settings expose data or cost",
        surface=Surface.CONFIG,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.ATTESTATIONS,),
        boundaries=(Boundary.B8,),
        maps_to=("LLM02", "LLM10"),
        base_impact=4,
        remediation=(
            "Use zero (or short) data retention and opt out of training, restrict each API "
            "key to one application, rotate keys at least every 90 days, and set a hard "
            "spend limit with the provider."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield from attested(PROVIDER_QUESTIONS, answers(context, PROVIDER_QUESTIONS))


@register
class OverScopedCredentials:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="T-15",
        title="Agent credentials are over-scoped or long-lived",
        surface=Surface.CONFIG,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.CONFIG_FILES, InputKind.ATTESTATIONS),
        boundaries=(Boundary.B8,),
        maps_to=("ASI03",),
        base_impact=7,
        remediation=(
            "Give the agent credentials scoped to exactly what its tools do (read-only where "
            "possible) and short-lived, issued per session or per user instead of one "
            "long-lived admin token."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        sections = find_keys(agent_configs(context), CREDENTIAL_SECTIONS)
        given = context.scope.attestations
        has_answers = any(q.key in given for q in CREDENTIAL_QUESTIONS)
        if not sections and not has_answers:
            raise CheckUnavailable(
                "needs a credentials section in the agent config, or attestations "
                + " and ".join(q.key for q in CREDENTIAL_QUESTIONS)
            )
        # Check the answers before reporting anything: a skip discards what was reported.
        answered = answers(context, CREDENTIAL_QUESTIONS) if has_answers else None
        for config, _, section in sections:
            for name, settings in section.items() if isinstance(section, dict) else []:
                if isinstance(settings, dict):
                    for problem, needle in credential_problems(str(name), settings):
                        yield Detection(
                            title=problem,
                            location=config_location(context, config, needle),
                            evidence=f"{name}: {json.dumps(settings)}",
                            confidence=0.85,
                        )
        if answered is not None:
            yield from attested(CREDENTIAL_QUESTIONS, answered)


def credential_problems(name: str, settings: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(problem, text to find its line by) for one configured credential."""
    for key, value in settings.items():
        values = value if isinstance(value, list) else [value]
        if SCOPE_KEYS.match(str(key)) and any(BROAD_SCOPE.match(str(v)) for v in values):
            yield f"Credential '{name}' is over-scoped ({key}: {json.dumps(value)})", str(key)
        if LIFETIME_KEYS.match(str(key)) and _long_lived(str(key), value):
            yield f"Credential '{name}' is long-lived ({key}: {json.dumps(value)})", str(key)


def _long_lived(key: str, value: Any) -> bool:
    """Never expires, or stays valid for more than 30 days."""
    if value is None or str(value).lower() in ("never", "none", "0", "false"):
        return True
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    unit = key.lower()
    if "hour" in unit:
        days = value / 24
    elif "second" in unit or unit == "ttl":
        days = value / 86400
    else:
        days = value
    return days > 30
