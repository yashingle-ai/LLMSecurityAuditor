"""Every check against its fixtures in tests/fixtures/checks/<check>/.

Layout: ``<check>/{positive,negative}/<input kind>/<file>``. Each positive file must
produce at least one finding from its check; each negative file must produce none.
An ``attestations`` file is a YAML mapping used as the scope's attestations.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

import llm_auditor.detectors  # noqa: F401  (registers the built-in checks)
from llm_auditor.audit import run_audit
from llm_auditor.checks import CheckRegistry, registry
from llm_auditor.models import (
    Access,
    AuditScope,
    CapabilityProfile,
    CheckMeta,
    InputKind,
    ScopeInputs,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "checks"
# Semgrep-based checks are tested with `semgrep --test` (tests/semgrep/ and
# tests/semgrep_generated/), not here.
TESTED_ELSEWHERE = ("C-", "A-08", "O-06")


def fixture_files() -> Iterator[tuple[str, str, InputKind, Path]]:
    for check_dir in sorted(FIXTURES.iterdir()):
        for polarity in ("positive", "negative"):
            for kind_dir in sorted((check_dir / polarity).glob("*")):
                # Hidden entries (like T-12's .llmaudit/ lockfile) are setup, not cases.
                for file in sorted(kind_dir.iterdir()):
                    if file.name.startswith("."):
                        continue
                    yield check_dir.name, polarity, InputKind(kind_dir.name), file


@pytest.mark.parametrize(
    ("check_id", "polarity", "kind", "file"),
    [pytest.param(*case, id=f"{case[0]}-{case[1]}-{case[3].name}") for case in fixture_files()],
)
def test_check_on_fixture(check_id: str, polarity: str, kind: InputKind, file: Path) -> None:
    catalog = CheckRegistry()
    catalog.register(registry.get(check_id))
    inputs, attestations = ScopeInputs(), {}
    if kind is InputKind.ATTESTATIONS:  # answers in the scope file, not files to ingest
        attestations = yaml.safe_load(file.read_text(encoding="utf-8"))
    else:
        inputs = ScopeInputs.model_validate({kind.value: [file.name]})
    scope = AuditScope(
        name=file.name,
        access=Access.WHITE,
        capability_profile=CapabilityProfile.neutral(),
        root=file.parent,
        inputs=inputs,
        attestations=attestations,
    )

    report = run_audit(scope, checks=catalog)

    assert report.coverage.ran == (check_id,), report.coverage
    found = [f"{f.title}: {f.evidence}" for f in report.findings]
    if polarity == "positive":
        assert found, f"{check_id} found nothing in {file.name}"
    else:
        assert not found, f"{check_id} false positives in {file.name}: {found}"


@pytest.mark.parametrize("meta", registry.list_checks(), ids=lambda meta: meta.id)
def test_every_check_has_positive_and_negative_fixtures(meta: CheckMeta) -> None:
    if meta.id.startswith(TESTED_ELSEWHERE):
        pytest.skip("tested by semgrep --test")
    counts = {
        polarity: sum(1 for c, p, _, _ in fixture_files() if c == meta.id and p == polarity)
        for polarity in ("positive", "negative")
    }

    assert counts["positive"] >= 2 and counts["negative"] >= 2, counts
