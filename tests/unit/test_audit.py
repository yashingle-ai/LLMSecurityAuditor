from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from llm_auditor.audit import run_audit
from llm_auditor.checks import Check, CheckRegistry, CheckUnavailable, Detection
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    AuditReport,
    AuditScope,
    Boundary,
    CapabilityProfile,
    CheckMeta,
    FindingKind,
    IncidentOutcome,
    InputKind,
    Location,
    ScopeInputs,
    Severity,
    Surface,
)

PROMPTS = Path(__file__).parents[1] / "fixtures" / "ingestion" / "prompts"
FAKE_KEY = "acme_live_" + "Zr8Pq2Wx5Ty9Lm3Nb6Vc1Hk"


def meta(check_id: str, base_impact: int = 5) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title="test check",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.PROMPT_DIRS,),
        boundaries=(Boundary.B2,),
        base_impact=base_impact,
        remediation="Fix it.",
    )


def detection(evidence: str = "x", line: int = 1, kind: FindingKind | None = None) -> Detection:
    return Detection(
        title="something",
        location=Location(file="prompts/system.txt", line=line),
        evidence=evidence,
        kind=kind,
    )


class LeakyCheck:
    """Reports the same raw secret twice (on different lines) plus a hardening note."""

    meta: ClassVar[CheckMeta] = meta("P-01", base_impact=7)

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield detection(f"key {FAKE_KEY}", line=3)
        yield detection(f"key {FAKE_KEY}", line=9)  # same issue, moved: same fingerprint
        yield detection("use delimiters", kind=FindingKind.HARDENING)


class MildCheck:
    meta: ClassVar[CheckMeta] = meta("P-02", base_impact=2)

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield detection("mild")


class BrokenCheck:
    meta: ClassVar[CheckMeta] = meta("P-03")

    def run(self, context: AuditContext) -> Iterator[Detection]:
        raise RuntimeError("detector bug")


class UnavailableCheck:
    meta: ClassVar[CheckMeta] = meta("P-04")

    def run(self, context: AuditContext) -> Iterator[Detection]:
        raise CheckUnavailable("semgrep is not installed")


class WeakSpots:
    """Two weaknesses: one about tool results, one not."""

    meta: ClassVar[CheckMeta] = meta("P-02")

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield detection("tool results reach the prompt undelimited", line=2)
        yield detection("no length limit on user input", line=5)


INCIDENT = meta("P-07").model_copy(update={"kind": FindingKind.INCIDENT})


class AttackThatWorked:
    meta: ClassVar[CheckMeta] = INCIDENT

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield Detection(
            title="attack",
            location=Location(file="logs/run.jsonl", line=1),
            evidence="it worked",
            outcome=IncidentOutcome.SUCCEEDED,
            corroborates=("P-02:tool results",),
        )


class AttackThatFailed:
    meta: ClassVar[CheckMeta] = INCIDENT

    def run(self, context: AuditContext) -> Iterator[Detection]:
        yield Detection(
            title="attack",
            location=Location(file="logs/run.jsonl", line=1),
            evidence="it was refused",
            outcome=IncidentOutcome.FAILED,
            corroborates=("P-02",),
        )


def run_audit_with(*checks: type[Check]) -> AuditReport:
    catalog = CheckRegistry()
    for check in checks:
        catalog.register(check)
    scope = AuditScope(
        name="test",
        access=Access.WHITE,
        capability_profile=CapabilityProfile.neutral(),
        root=PROMPTS,
        inputs=ScopeInputs(prompt_dirs=["."]),
    )
    return run_audit(scope, checks=catalog)


def test_findings_are_redacted_scored_deduplicated_and_numbered_by_severity() -> None:
    report = run_audit_with(MildCheck, LeakyCheck)

    assert [(f.id, f.check_id, f.kind, f.severity) for f in report.findings] == [
        ("F-0001", "P-01", FindingKind.WEAKNESS, Severity.HIGH),
        ("F-0002", "P-02", FindingKind.WEAKNESS, Severity.LOW),
        ("F-0003", "P-01", FindingKind.HARDENING, None),
    ]
    first = report.findings[0]
    assert FAKE_KEY not in first.evidence
    assert first.severity_score == 7
    assert first.severity_factors == ["base impact +7"]
    assert first.remediation == "Fix it."


def test_a_broken_check_is_reported_and_the_audit_continues() -> None:
    report = run_audit_with(BrokenCheck, MildCheck)

    assert report.coverage.ran == ("P-02",)
    assert [(f.check_id, f.error) for f in report.coverage.failed] == [
        ("P-03", "RuntimeError: detector bug")
    ]
    assert len(report.findings) == 1


def test_an_unavailable_check_is_skipped_with_its_reason() -> None:
    report = run_audit_with(UnavailableCheck)

    assert [(s.check_id, s.reason) for s in report.coverage.skipped] == [
        ("P-04", "semgrep is not installed")
    ]


def test_report_records_the_run_and_the_inputs() -> None:
    report = run_audit_with(MildCheck)

    assert report.run.scope_name == "test"
    assert report.run.started_at <= report.run.finished_at
    assert [check.id for check in report.checks] == ["P-02"]
    assert report.coverage.inputs[0].kind is InputKind.PROMPT_DIRS


def test_capabilities_missing_from_the_profile_are_noted(tmp_path: Path) -> None:
    tools = '[{"name": "delete_account", "description": "Delete the account."}]'
    (tmp_path / "tools.json").write_text(tools, encoding="utf-8")
    scope = AuditScope(
        name="t",
        access=Access.WHITE,
        capability_profile=CapabilityProfile.neutral(),
        root=tmp_path,
        inputs=ScopeInputs(tool_defs=["tools.json"]),
    )

    report = run_audit(scope, checks=CheckRegistry())

    assert [t.name for t in report.tool_inventory] == ["delete_account"]
    assert any("doesn't list: destructive" in note for note in report.coverage.notes)


def test_an_attack_that_worked_confirms_the_weakness_it_names() -> None:
    report = run_audit_with(WeakSpots, AttackThatWorked)

    by_evidence = {f.evidence: f for f in report.findings}
    confirmed = by_evidence["tool results reach the prompt undelimited"]
    untouched = by_evidence["no length limit on user input"]
    attack = by_evidence["it worked"]
    assert confirmed.kind is FindingKind.VULNERABILITY
    assert confirmed.related == [attack.id]
    assert attack.related == [confirmed.id]
    assert attack.outcome is IncidentOutcome.SUCCEEDED
    # The selector named tool results, so the other weakness is left alone.
    assert untouched.kind is FindingKind.WEAKNESS
    assert untouched.related == []


def test_an_attack_that_failed_confirms_nothing() -> None:
    report = run_audit_with(WeakSpots, AttackThatFailed)

    weaknesses = [f for f in report.findings if f.check_id == "P-02"]
    assert [f.kind for f in weaknesses] == [FindingKind.WEAKNESS] * 2
    assert all(f.related == [] for f in report.findings)
    assert report.incident_summary["P-07"].failed == 1
