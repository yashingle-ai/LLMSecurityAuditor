"""Ground-truth harness: measures the auditor against the demo apps' planted flaws.

Every enabled entry in demo/vulnerable_app/GROUND_TRUTH.yaml must be found in the
vulnerable app, and the hardened app must produce no vulnerability or weakness
findings at all.
"""

import os
from functools import cache
from pathlib import Path

import pytest
import yaml
from pydantic import BaseModel, ConfigDict, Field

import llm_auditor.detectors  # noqa: F401  (registers the built-in checks)
from llm_auditor.audit import run_audit
from llm_auditor.checks import registry
from llm_auditor.models import (
    AuditReport,
    AuditScope,
    CheckId,
    Finding,
    FindingKind,
    Location,
    Oracle,
    Severity,
)

REPO_ROOT = Path(__file__).parents[2]
VULNERABLE_APP = REPO_ROOT / "demo" / "vulnerable_app"
HARDENED_APP = REPO_ROOT / "demo" / "hardened_app"
SCOPES = {
    VULNERABLE_APP: REPO_ROOT / "configs" / "audit_scope.example.yaml",
    HARDENED_APP: REPO_ROOT / "configs" / "audit_scope.hardened.yaml",
}
ATTESTATION = "attestation:"
# CI sets this so a missing tool fails the build instead of silently skipping checks.
REQUIRE_TOOLS = os.environ.get("REQUIRE_SEMGREP") == "1"


class GroundTruthEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^GT-\d{3}$")
    check: CheckId
    stage: int = Field(ge=1, le=14)
    location: str = Field(min_length=1)  # relative to the app directory
    description: str = Field(min_length=1)
    enabled: bool

    @property
    def is_attestation(self) -> bool:
        """Locations like ``attestation:`` name attestation answers, not files."""
        return self.location.startswith(ATTESTATION)

    def is_found_in(self, findings: list[Finding], app_dir: Path) -> bool:
        """A finding matches if it has the same check and a file at or under the location
        (or, for attestation entries, an artifact with the same prefix).

        Relative finding paths are resolved against the repository root.
        """
        expected = (app_dir / self.location).resolve()
        for finding in findings:
            if finding.check_id != self.check:
                continue
            if self.is_attestation:
                if (finding.location.artifact or "").startswith(self.location):
                    return True
                continue
            if finding.location.file is None:
                continue
            found = (REPO_ROOT / finding.location.file).resolve()
            if found == expected or found.is_relative_to(expected):
                return True
        return False


def load_ground_truth() -> list[GroundTruthEntry]:
    raw = yaml.safe_load((VULNERABLE_APP / "GROUND_TRUTH.yaml").read_text(encoding="utf-8"))
    return [GroundTruthEntry.model_validate(item) for item in raw]


@cache
def audit_app(app_dir: Path) -> AuditReport:
    """The auditor's report on one demo app, using that app's scope file."""
    return run_audit(AuditScope.from_yaml(SCOPES[app_dir]))


def enabled_entries() -> list[GroundTruthEntry]:
    return [entry for entry in load_ground_truth() if entry.enabled]


def make_finding(check_id: str, file: str) -> Finding:
    return Finding(
        id="F-0001",
        fingerprint="x",
        check_id=check_id,
        kind=FindingKind.WEAKNESS,
        title="t",
        severity=Severity.HIGH,
        confidence=1.0,
        oracle=Oracle.RULE,
        location=Location(file=file),
        evidence="e",
        remediation="r",
    )


def test_ground_truth_file_is_valid() -> None:
    entries = load_ground_truth()

    ids = [entry.id for entry in entries]
    assert len(ids) == len(set(ids)), "duplicate ground-truth IDs"
    missing = [
        entry.id
        for entry in entries
        if not entry.is_attestation and not (VULNERABLE_APP / entry.location).exists()
    ]
    assert not missing, f"locations that don't exist: {missing}"


def test_enabled_entries_have_a_registered_check() -> None:
    known = {meta.id for meta in registry.list_checks()}

    unknown = [
        entry.id for entry in load_ground_truth() if entry.enabled and entry.check not in known
    ]

    assert not unknown, f"enabled entries whose check has no detector yet: {unknown}"


@pytest.mark.parametrize("entry", enabled_entries(), ids=lambda entry: entry.id)
def test_planted_flaw_is_found(entry: GroundTruthEntry) -> None:
    report = audit_app(VULNERABLE_APP)
    skipped = {s.check_id: s.reason for s in report.coverage.skipped}
    if entry.check in skipped:
        message = f"{entry.check} was skipped: {skipped[entry.check]}"
        if REQUIRE_TOOLS or "not installed" not in skipped[entry.check]:
            pytest.fail(message)
        pytest.skip(message)

    assert entry.is_found_in(list(report.findings), VULNERABLE_APP), (
        f"{entry.id} not found ({entry.check}: {entry.description})"
    )


def test_hardened_app_has_no_vulnerabilities_or_weaknesses() -> None:
    findings = audit_app(HARDENED_APP).findings

    serious = [f"{f.check_id} {f.title} at {f.location}" for f in findings if f.kind.has_severity]

    assert not serious, "findings in the hardened app:\n" + "\n".join(serious)


@pytest.mark.parametrize("app_dir", [VULNERABLE_APP, HARDENED_APP], ids=lambda p: p.name)
def test_no_check_fails_on_the_demo_apps(app_dir: Path) -> None:
    assert audit_app(app_dir).coverage.failed == ()


@pytest.mark.parametrize(
    ("entry_id", "check_id", "file", "expected"),
    [
        ("GT-001", "P-01", "demo/vulnerable_app/prompts/system.txt", True),
        ("GT-001", "P-02", "demo/vulnerable_app/prompts/system.txt", False),  # wrong check
        ("GT-001", "P-01", "demo/hardened_app/prompts/system.txt", False),  # wrong app
        ("GT-002", "A-01", "demo/vulnerable_app/logs/traffic.jsonl", True),  # inside a directory
    ],
)
def test_findings_match_ground_truth_by_check_and_location(
    entry_id: str, check_id: str, file: str, expected: bool
) -> None:
    entry = next(entry for entry in load_ground_truth() if entry.id == entry_id)

    assert entry.is_found_in([make_finding(check_id, file)], VULNERABLE_APP) is expected


@pytest.mark.parametrize("app_dir", [VULNERABLE_APP, HARDENED_APP], ids=lambda p: p.name)
def test_coverage_accounts_for_every_registered_check(app_dir: Path) -> None:
    coverage = audit_app(app_dir).coverage
    accounted = [
        *coverage.ran,
        *(s.check_id for s in coverage.skipped),
        *(f.check_id for f in coverage.failed),
    ]

    assert sorted(accounted) == sorted(meta.id for meta in registry.list_checks())
