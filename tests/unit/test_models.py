from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from llm_auditor.models import (
    Access,
    AttackSuccessRate,
    CheckMeta,
    Finding,
    FindingKind,
    Interaction,
    Location,
    Message,
    Oracle,
    Repro,
    Role,
    Severity,
    ToolCall,
    ToolResult,
)


def make_finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "id": "F-0001",
        "fingerprint": "0123abcd",
        "check_id": "P-01",
        "kind": FindingKind.WEAKNESS,
        "title": "Hard-coded API key in system prompt",
        "severity": Severity.HIGH,
        "confidence": 0.98,
        "oracle": Oracle.RULE,
        "location": Location(file="prompts/support.txt", line=12),
        "evidence": "use key sk-****9f2a to call the billing API",
        "remediation": "Move the key to a secrets manager.",
    }
    return Finding(**(fields | overrides))


def make_agent_run() -> Interaction:
    return Interaction(
        id="int_0001",
        source="logs/chat.jsonl:42",
        timestamp=datetime(2026, 10, 1, 10, 15, tzinfo=UTC),
        system_prompt="You are a support bot.",
        messages=[
            Message(role=Role.USER, content="Summarize https://example.com/doc"),
            Message(
                role=Role.ASSISTANT,
                tool_calls=[
                    ToolCall(
                        id="call_1", name="fetch_url", arguments={"url": "https://example.com/doc"}
                    )
                ],
            ),
            Message(role=Role.TOOL, tool_result=ToolResult(call_id="call_1", content="page text")),
            Message(
                role=Role.ASSISTANT,
                tool_calls=[ToolCall(id="call_2", name="send_email", arguments={"to": "x@y.z"})],
            ),
            Message(role=Role.TOOL, tool_result=ToolResult(call_id="call_2", content="sent")),
            Message(role=Role.ASSISTANT, content="Done."),
        ],
    )


def test_finding_round_trips_through_json() -> None:
    finding = make_finding(
        kind=FindingKind.VULNERABILITY,
        oracle=Oracle.DETERMINISTIC,
        asr=AttackSuccessRate(successes=4, trials=20),
        repro=Repro(
            steps=["Ask the bot to repeat its instructions"],
            model="demo-model",
            recorded_at=datetime(2026, 10, 27, tzinfo=UTC),
        ),
        related=["F-0002"],
    )

    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_interaction_round_trips_through_json() -> None:
    run = make_agent_run()

    assert Interaction.model_validate_json(run.model_dump_json()) == run


def test_interaction_exposes_tool_calls_and_results_in_order() -> None:
    run = make_agent_run()

    assert [call.name for call in run.tool_calls] == ["fetch_url", "send_email"]
    assert [result.call_id for result in run.tool_results] == ["call_1", "call_2"]


@pytest.mark.parametrize("kind", [FindingKind.VULNERABILITY, FindingKind.WEAKNESS])
def test_vulnerabilities_and_weaknesses_need_a_severity(kind: FindingKind) -> None:
    with pytest.raises(ValidationError, match="need a severity"):
        make_finding(kind=kind, severity=None)


@pytest.mark.parametrize("kind", [FindingKind.HARDENING, FindingKind.INCIDENT])
def test_hardening_and_incidents_carry_no_severity(kind: FindingKind) -> None:
    with pytest.raises(ValidationError, match="carry no severity"):
        make_finding(kind=kind, severity=Severity.LOW)

    assert make_finding(kind=kind, severity=None).severity is None


def test_a_vulnerability_needs_a_successful_trial() -> None:
    with pytest.raises(ValidationError, match="at least one successful trial"):
        make_finding(kind=FindingKind.VULNERABILITY, asr=AttackSuccessRate(successes=0, trials=20))


def test_attack_success_rate_cannot_exceed_trials() -> None:
    with pytest.raises(ValidationError, match="cannot exceed trials"):
        AttackSuccessRate(successes=21, trials=20)


def test_confidence_must_be_between_0_and_1() -> None:
    with pytest.raises(ValidationError):
        make_finding(confidence=1.5)


def test_a_location_needs_a_file_or_an_artifact() -> None:
    with pytest.raises(ValidationError, match="file or an artifact"):
        Location(line=3)

    assert Location(artifact="tool:send_email").file is None


def test_only_assistant_messages_make_tool_calls() -> None:
    with pytest.raises(ValidationError, match="only assistant messages"):
        Message(role=Role.USER, tool_calls=[ToolCall(id="c", name="run_shell")])


@pytest.mark.parametrize(
    ("role", "result"),
    [(Role.TOOL, None), (Role.USER, ToolResult(call_id="c", content="x"))],
)
def test_tool_results_belong_to_tool_messages(role: Role, result: ToolResult | None) -> None:
    with pytest.raises(ValidationError, match="only tool messages"):
        Message(role=role, tool_result=result)


@pytest.mark.parametrize("check_id", ["P-1", "X-01", "p-01", "SC01"])
def test_check_ids_follow_the_catalog_format(
    make_meta: Callable[..., CheckMeta], check_id: str
) -> None:
    with pytest.raises(ValidationError):
        make_meta(id=check_id)


@pytest.mark.parametrize("risk_id", ["LLM1", "OWASP01", "asi01"])
def test_risk_ids_must_be_owasp_llm_or_agentic(
    make_meta: Callable[..., CheckMeta], risk_id: str
) -> None:
    with pytest.raises(ValidationError):
        make_meta(maps_to=(risk_id,))


def test_base_impact_is_0_to_10(make_meta: Callable[..., CheckMeta]) -> None:
    with pytest.raises(ValidationError):
        make_meta(base_impact=11)


def test_check_meta_is_immutable(make_meta: Callable[..., CheckMeta]) -> None:
    meta = make_meta()

    with pytest.raises(ValidationError):
        meta.base_impact = 9  # type: ignore[misc]


def test_wider_access_covers_narrower_checks() -> None:
    assert Access.WHITE.covers(Access.GRAY)
    assert Access.GRAY.covers(Access.GRAY)
    assert not Access.BLACK.covers(Access.GRAY)


def test_severities_rank_from_info_to_critical() -> None:
    ranked = sorted(Severity, key=lambda severity: severity.rank)

    assert ranked == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
