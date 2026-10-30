"""SARIF 2.1.0 report, for GitHub code scanning and other CI tools.

Only findings with a file location are included, since code scanning shows
results against files. Incidents (attack attempts in logs) are left out: they are
not defects in the code.
"""

from typing import Any

from llm_auditor.models import AuditReport, CheckMeta, Finding, FindingKind, Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(report: AuditReport) -> dict[str, Any]:
    results = [
        f
        for f in report.findings
        if f.location.file is not None and f.kind is not FindingKind.INCIDENT
    ]
    reported = sorted({f.check_id for f in results})
    rules = [_rule(meta, results) for check_id in reported if (meta := report.check(check_id))]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.run.tool,
                        "version": report.run.tool_version,
                        "rules": rules,
                    }
                },
                "results": [_result(f, reported.index(f.check_id)) for f in results],
                "properties": {"scope": report.run.scope_name, "access": report.run.access},
            }
        ],
    }


def _rule(meta: CheckMeta, results: list[Finding]) -> dict[str, Any]:
    scores = [f.severity_score for f in results if f.check_id == meta.id and f.severity_score]
    properties: dict[str, Any] = {"tags": ["security", "llm", *meta.maps_to]}
    if scores:
        # GitHub ranks alerts by this; severity here depends on context, so use the worst seen.
        properties["security-severity"] = f"{max(scores):.1f}"
    return {
        "id": meta.id,
        "name": meta.title,
        "shortDescription": {"text": meta.title},
        "help": {"text": meta.remediation},
        "properties": properties,
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    region = {"startLine": finding.location.line} if finding.location.line else None
    physical: dict[str, Any] = {"artifactLocation": {"uri": finding.location.file}}
    if region:
        physical["region"] = region
    return {
        "ruleId": finding.check_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity] if finding.severity else "note",
        "message": {"text": f"{finding.title}. Evidence: {finding.evidence}"},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"llmAuditorFingerprint/v1": finding.fingerprint},
        "properties": {
            "findingId": finding.id,
            "kind": finding.kind,
            "severity": finding.severity,
            "confidence": finding.confidence,
        },
    }
