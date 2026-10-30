from collections.abc import Callable

import pytest

from llm_auditor.models import (
    AttackSuccessRate,
    Autonomy,
    Capability,
    CapabilityProfile,
    CheckMeta,
    DataSensitivity,
    Exposure,
    Severity,
)
from llm_auditor.scoring import RUBRIC_VERSION, assess_severity, severity_for_score

MakeMeta = Callable[..., CheckMeta]

INTERNAL_CHATBOT = CapabilityProfile(
    exposure=Exposure.INTERNAL,
    autonomy=Autonomy.HUMAN_IN_LOOP,
    data_sensitivity=DataSensitivity.MEDIUM,
    multi_tenant=False,
    capabilities=frozenset(),
)
AUTONOMOUS_EMAIL_AGENT = CapabilityProfile(
    exposure=Exposure.INTERNET,
    autonomy=Autonomy.AUTONOMOUS,
    data_sensitivity=DataSensitivity.HIGH,
    multi_tenant=True,
    capabilities=frozenset({Capability.EXTERNAL_COMMUNICATION}),
)


def test_same_check_is_medium_on_internal_chatbot_and_critical_on_autonomous_agent(
    make_meta: MakeMeta,
) -> None:
    injection_in_tool_results = make_meta()

    assert assess_severity(injection_in_tool_results, INTERNAL_CHATBOT).severity is Severity.MEDIUM
    assert (
        assess_severity(injection_in_tool_results, AUTONOMOUS_EMAIL_AGENT).severity
        is Severity.CRITICAL
    )


def test_capabilities_only_amplify_checks_they_affect(make_meta: MakeMeta) -> None:
    plain_http = make_meta(id="A-04", amplified_by=frozenset())
    with_every_capability = INTERNAL_CHATBOT.model_copy(
        update={"capabilities": frozenset(Capability)}
    )

    assert (
        assess_severity(plain_http, with_every_capability).score
        == assess_severity(plain_http, INTERNAL_CHATBOT).score
    )


def test_capability_bonus_is_capped(make_meta: MakeMeta) -> None:
    check = make_meta()
    with_every_capability = INTERNAL_CHATBOT.model_copy(
        update={"capabilities": frozenset(Capability)}
    )

    bonus = (
        assess_severity(check, with_every_capability).score
        - assess_severity(check, INTERNAL_CHATBOT).score
    )

    assert bonus == 2


@pytest.mark.parametrize(
    ("asr", "delta"),
    [
        (AttackSuccessRate(successes=15, trials=20), 1),
        (AttackSuccessRate(successes=5, trials=20), 0),
        (AttackSuccessRate(successes=1, trials=20), -1),
        (AttackSuccessRate(successes=0, trials=20), -1),
    ],
)
def test_attack_success_rate_adjusts_the_score(
    make_meta: MakeMeta, asr: AttackSuccessRate, delta: int
) -> None:
    check = make_meta()
    without_probe = assess_severity(check, INTERNAL_CHATBOT).score

    assert assess_severity(check, INTERNAL_CHATBOT, asr).score == without_probe + delta


def test_score_is_clamped_to_0_10(make_meta: MakeMeta) -> None:
    low_stakes = INTERNAL_CHATBOT.model_copy(update={"data_sensitivity": DataSensitivity.LOW})

    assert assess_severity(make_meta(base_impact=10), AUTONOMOUS_EMAIL_AGENT).score == 10
    assert assess_severity(make_meta(base_impact=0), low_stakes).score == 0


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0, Severity.INFO),
        (1, Severity.LOW),
        (3, Severity.LOW),
        (4, Severity.MEDIUM),
        (6, Severity.MEDIUM),
        (7, Severity.HIGH),
        (8, Severity.HIGH),
        (9, Severity.CRITICAL),
        (10, Severity.CRITICAL),
    ],
)
def test_scores_map_to_cvss_ranges(score: int, severity: Severity) -> None:
    assert severity_for_score(score) is severity


def test_factors_explain_the_score(make_meta: MakeMeta) -> None:
    assessment = assess_severity(make_meta(base_impact=4), AUTONOMOUS_EMAIL_AGENT)

    assert sum(factor.delta for factor in assessment.factors) == assessment.score
    assert [factor.name for factor in assessment.factors] == [
        "base impact",
        "internet-facing",
        "acts without human approval",
        "high-sensitivity data",
        "multi-tenant",
        "target can: external_communication",
    ]
    assert assessment.rubric_version == RUBRIC_VERSION
