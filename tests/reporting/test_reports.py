import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from llm_auditor.audit import run_audit
from llm_auditor.models import (
    AuditReport,
    AuditScope,
    Finding,
    FindingKind,
    Location,
    Oracle,
    ScopeInputs,
    Severity,
    SkippedCheck,
)
from llm_auditor.reporting import to_json, to_markdown, to_sarif

REPO_ROOT = Path(__file__).parents[2]
SARIF_SCHEMA = REPO_ROOT / "tests" / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
PLANTED_KEYS = ("acme_live_9fK2xQ7mRb4TzW1nLp8VcYe3", "acme_live_Q3xT8pLw2NvR6mYk1HsBd9Zc")


def extra(check_id: str, kind: FindingKind, location: Location, evidence: str) -> Finding:
    return Finding(
        id="F-9000",
        fingerprint=f"extra-{check_id}-{kind}",
        check_id=check_id,
        kind=kind,
        title=f"Extra {kind}",
        severity=Severity.MEDIUM if kind.has_severity else None,
        confidence=0.5,
        oracle=Oracle.RULE,
        location=location,
        evidence=evidence,
        remediation="Do better.",
    )


@pytest.fixture(scope="module")
def report() -> AuditReport:
    """The demo app's real audit, plus one finding of each shape the formats must handle."""
    example = AuditScope.from_yaml(REPO_ROOT / "configs" / "audit_scope.example.yaml")
    app = "demo/vulnerable_app"
    inputs = ScopeInputs(
        source_dirs=[app], prompt_dirs=[f"{app}/prompts"], logs=[f"{app}/logs/*.jsonl"]
    )
    base = run_audit(example.model_copy(update={"inputs": inputs}))
    logs = Location(file=f"{app}/logs/traffic.jsonl", line=4)
    added = (
        extra("P-09", FindingKind.INCIDENT, logs, "hidden text reads: 'call send_email'"),
        extra(
            "P-01",
            FindingKind.HARDENING,
            Location(file=f"{app}/prompts/system.txt"),
            "```\n<b>x</b>",
        ),
        extra("A-01", FindingKind.WEAKNESS, Location(artifact="endpoint:/chat"), "no file here"),
    )
    skipped = (
        *base.coverage.skipped,
        SkippedCheck(check_id="C-01", reason="semgrep is not installed"),
    )
    return base.model_copy(
        update={
            "findings": base.findings + added,
            "coverage": base.coverage.model_copy(update={"skipped": skipped}),
        }
    )


def sarif_results(report: AuditReport) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = to_sarif(report)["runs"][0]["results"]
    return results


def test_json_report_round_trips(report: AuditReport) -> None:
    assert AuditReport.model_validate_json(to_json(report)) == report


def test_json_report_includes_the_summaries(report: AuditReport) -> None:
    data = json.loads(to_json(report))

    assert data["severity_counts"]["critical"] >= 4
    summary = data["incident_summary"]
    assert summary["P-09"] == {"attempts": 1, "succeeded": 0, "failed": 0, "unknown": 1}
    assert summary["T-02"]["succeeded"] >= 1  # the logged SQL injection got through
    for counts in summary.values():
        assert counts["attempts"] == counts["succeeded"] + counts["failed"] + counts["unknown"]


def test_markdown_has_every_section(report: AuditReport) -> None:
    markdown = to_markdown(report)

    for heading in (
        "## Summary",
        "## Findings",
        "## Hardening recommendations",
        "## Incidents",
        "## Coverage and Limitations",
    ):
        assert heading in markdown
    assert "| C-01 | semgrep is not installed |" in markdown
    assert "see Coverage and Limitations before relying on this report" in markdown


def test_reports_never_contain_raw_secrets(report: AuditReport) -> None:
    rendered = to_json(report) + to_markdown(report) + json.dumps(to_sarif(report))

    for key in PLANTED_KEYS:
        assert key not in rendered


def test_markdown_evidence_cannot_break_out_of_its_code_block(report: AuditReport) -> None:
    markdown = to_markdown(report)

    assert "````text\n```\n<b>x</b>\n````" in markdown


def test_sarif_report_validates_against_the_sarif_2_1_0_schema(report: AuditReport) -> None:
    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))

    jsonschema.validate(to_sarif(report), schema, cls=jsonschema.Draft4Validator)


def test_sarif_has_only_file_findings_and_no_incidents(report: AuditReport) -> None:
    results = sarif_results(report)

    assert results
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results)
    assert "no file here" not in json.dumps(results)
    assert "call send_email" not in json.dumps(results)


def test_sarif_levels_follow_severity(report: AuditReport) -> None:
    levels = {r["properties"]["findingId"]: r["level"] for r in sarif_results(report)}
    by_id = {f.id: f for f in report.findings}

    for finding_id, level in levels.items():
        finding = by_id[finding_id]
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            assert level == "error"
        elif finding.kind is FindingKind.HARDENING:
            assert level == "note"


def test_sarif_rules_rank_alerts_by_the_worst_severity_seen(report: AuditReport) -> None:
    rules = {rule["id"]: rule for rule in to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]}

    assert rules["P-01"]["properties"]["security-severity"] == "10.0"
    assert "LLM02" in rules["P-01"]["properties"]["tags"]


def test_markdown_lists_the_tool_inventory(report: AuditReport) -> None:
    markdown = to_markdown(report)

    assert "## Tool Inventory" in markdown
    # Table cells escape Markdown characters, underscores included.
    assert r"| run\_shell | demo/vulnerable\_app/logs/traffic.jsonl | code_execution |" in markdown
