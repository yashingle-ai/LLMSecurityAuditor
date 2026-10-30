"""Checks that read attestations skip, and say which answers they need, when answers are missing."""

from collections.abc import Callable
from pathlib import Path

import pytest

from llm_auditor.models import AuditReport, FindingKind, Oracle

AuditOne = Callable[..., AuditReport]

GOOD_PROVIDER = {
    "provider_retention_days": 0,
    "provider_trains_on_data": False,
    "api_keys_scoped": True,
    "api_key_rotation_days": 30,
    "spend_limit": True,
}


def test_no_attestations_skips_a10_and_names_every_question(
    audit_one: AuditOne, tmp_path: Path
) -> None:
    report = audit_one("A-10", tmp_path)

    assert report.findings == ()
    assert report.coverage.ran == ()
    [skipped] = report.coverage.skipped
    assert skipped.check_id == "A-10"
    assert skipped.reason.startswith("needs attestations: provider_retention_days, ")
    assert all(key in skipped.reason for key in GOOD_PROVIDER)


def test_a_partial_answer_skips_and_names_only_whats_missing(
    audit_one: AuditOne, tmp_path: Path
) -> None:
    answers = {k: v for k, v in GOOD_PROVIDER.items() if k != "spend_limit"}

    report = audit_one("A-10", tmp_path, attestations=answers)

    assert [s.reason for s in report.coverage.skipped] == [
        "needs attestations: spend_limit (answer them under `attestations:` in the scope file)"
    ]


def test_a_wrongly_typed_answer_skips_instead_of_guessing(
    audit_one: AuditOne, tmp_path: Path
) -> None:
    report = audit_one(
        "A-10", tmp_path, attestations={**GOOD_PROVIDER, "spend_limit": "yes", "api_keys_scoped": 1}
    )

    [skipped] = report.coverage.skipped
    assert "spend_limit should be true/false" in skipped.reason
    assert "api_keys_scoped should be true/false" in skipped.reason


def test_attested_findings_point_at_the_answer(audit_one: AuditOne, tmp_path: Path) -> None:
    report = audit_one("A-10", tmp_path, attestations={**GOOD_PROVIDER, "spend_limit": False})

    [finding] = report.findings
    assert finding.oracle == Oracle.ATTESTATION
    assert finding.location.artifact == "attestation:spend_limit"
    assert finding.kind == FindingKind.WEAKNESS


def test_t15_without_config_or_answers_is_skipped(audit_one: AuditOne, tmp_path: Path) -> None:
    report = audit_one("T-15", tmp_path)

    [skipped] = report.coverage.skipped
    assert skipped.reason.startswith("needs a credentials section in the agent config")


def test_t15_with_a_config_but_partial_answers_is_skipped(
    audit_one: AuditOne, tmp_path: Path
) -> None:
    (tmp_path / "agent.yaml").write_text(
        "agent:\n  model: m\ncredentials:\n  crm:\n    scope: admin\n", encoding="utf-8"
    )

    report = audit_one(
        "T-15",
        tmp_path,
        inputs={"config_files": ["agent.yaml"]},
        attestations={"agent_credentials_least_privilege": True},
    )

    # Finish answering or remove the answers; half an answer doesn't half-run the check.
    assert report.findings == ()
    assert [s.reason for s in report.coverage.skipped] == [
        "needs attestations: agent_credential_max_age_days (answer them under `attestations:` "
        "in the scope file)"
    ]


@pytest.mark.parametrize("value", [365, 31])
def test_a_long_retention_is_reported(audit_one: AuditOne, tmp_path: Path, value: int) -> None:
    report = audit_one(
        "A-10", tmp_path, attestations={**GOOD_PROVIDER, "provider_retention_days": value}
    )

    assert [f.title for f in report.findings] == [
        f"The provider keeps prompts and outputs for {value} days"
    ]
