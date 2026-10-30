"""Run an audit: ingest, plan, run every check that can run, score, and build the report."""

import hashlib
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime

from llm_auditor import __version__
from llm_auditor.checks import CheckRegistry, CheckUnavailable, Detection, registry
from llm_auditor.ingestion import ingest
from llm_auditor.inventory import tool_inventory
from llm_auditor.models import (
    AuditReport,
    AuditScope,
    CheckMeta,
    Coverage,
    FailedCheck,
    Finding,
    FindingKind,
    IncidentOutcome,
    RunInfo,
    SkippedCheck,
    ToolProfile,
)
from llm_auditor.redaction import redact
from llm_auditor.scoring import RUBRIC_VERSION, assess_severity, fingerprint

_KIND_ORDER = [
    FindingKind.VULNERABILITY,
    FindingKind.WEAKNESS,
    FindingKind.HARDENING,
    FindingKind.INCIDENT,
]


def _now() -> datetime:
    return datetime.now(UTC)


def run_audit(
    scope: AuditScope,
    *,
    checks: CheckRegistry | None = None,
    notes: Sequence[str] = (),
    clock: Callable[[], datetime] = _now,
) -> AuditReport:
    """Audit ``scope`` with ``checks`` (the built-in catalog by default)."""
    import llm_auditor.detectors  # noqa: F401  (importing registers the built-in checks)

    catalog = checks or registry
    started = clock()
    context = ingest(scope)
    considered = catalog.list_checks()
    plan = context.plan(considered)
    inventory = [tool.profile for tool in tool_inventory(context)]

    ran: list[str] = []
    skipped = list(plan.skipped)
    failed: list[FailedCheck] = []
    findings: list[Finding] = []
    evidence_for: dict[str, set[str]] = defaultdict(set)  # fingerprint -> check IDs it confirms
    for meta in plan.runnable:
        try:
            detections = list(catalog.get(meta.id)().run(context))
        except CheckUnavailable as reason:
            skipped.append(SkippedCheck(check_id=meta.id, reason=str(reason)))
            continue
        except Exception as error:  # one broken check must not end the whole audit
            failed.append(FailedCheck(check_id=meta.id, error=f"{type(error).__name__}: {error}"))
            continue
        ran.append(meta.id)
        for detection in detections:
            finding = _finding(meta, detection, scope)
            findings.append(finding)
            evidence_for[finding.fingerprint].update(detection.corroborates)

    return AuditReport(
        run=RunInfo(
            tool_version=__version__,
            rubric_version=RUBRIC_VERSION,
            scope_name=scope.name,
            scope_digest=hashlib.sha256(scope.model_dump_json().encode()).hexdigest()[:16],
            access=scope.access,
            started_at=started,
            finished_at=clock(),
        ),
        capability_profile=scope.capability_profile,
        coverage=Coverage(
            ran=tuple(ran),
            skipped=tuple(sorted(skipped, key=lambda s: s.check_id)),
            failed=tuple(failed),
            inputs=tuple(context.inputs),
            ingest_issues=tuple(context.issues),
            notes=(*notes, *_profile_notes(scope, inventory)),
        ),
        checks=tuple(considered),
        findings=tuple(_numbered(*_linked(_deduplicated(findings), evidence_for))),
        tool_inventory=tuple(inventory),
    )


def _profile_notes(scope: AuditScope, inventory: list[ToolProfile]) -> list[str]:
    """A warning when the tools grant capabilities the scope's profile doesn't declare."""
    found = {capability for tool in inventory for capability in tool.capabilities}
    missing = sorted(found - scope.capability_profile.capabilities)
    if not missing:
        return []
    return [
        f"The tools give the agent capabilities the scope's capability_profile doesn't list: "
        f"{', '.join(missing)}. Severity may be understated; if the inventory is right, "
        "add them to capability_profile.capabilities."
    ]


def _finding(meta: CheckMeta, detection: Detection, scope: AuditScope) -> Finding:
    kind = detection.kind or meta.kind
    evidence = redact(detection.evidence)
    assessment = assess_severity(meta, scope.capability_profile) if kind.has_severity else None
    return Finding(
        id="F-0000",  # numbered once all findings are sorted
        fingerprint=fingerprint(meta.id, detection.location, evidence),
        check_id=meta.id,
        kind=kind,
        title=redact(detection.title),
        severity=assessment.severity if assessment else None,
        severity_score=assessment.score if assessment else None,
        severity_factors=[f"{f.name} {f.delta:+d}" for f in assessment.factors]
        if assessment
        else [],
        confidence=detection.confidence,
        oracle=detection.oracle,
        outcome=detection.outcome if kind is FindingKind.INCIDENT else None,
        location=detection.location,
        evidence=evidence,
        remediation=detection.remediation or meta.remediation,
    )


def _deduplicated(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    return list(unique.values())


def _linked(
    findings: list[Finding], evidence_for: Mapping[str, set[str]]
) -> tuple[list[Finding], dict[str, set[str]]]:
    """Apply evidence: a succeeded incident or a vulnerability confirms the findings of the
    checks it corroborates. Confirmed weaknesses become vulnerabilities, and both sides are
    linked. Returns the findings and the links, by fingerprint."""
    links: dict[str, set[str]] = defaultdict(set)
    confirmed: set[str] = set()
    for evidence in findings:
        checks = evidence_for.get(evidence.fingerprint)
        proven = evidence.kind is FindingKind.VULNERABILITY
        if not checks or not (proven or evidence.outcome is IncidentOutcome.SUCCEEDED):
            continue
        for target in findings:
            serious = target.kind in (FindingKind.WEAKNESS, FindingKind.VULNERABILITY)
            other = target.fingerprint != evidence.fingerprint
            if serious and other and _confirms(checks, target):
                links[evidence.fingerprint].add(target.fingerprint)
                links[target.fingerprint].add(evidence.fingerprint)
                confirmed.add(target.fingerprint)
    upgraded = [
        f.model_copy(update={"kind": FindingKind.VULNERABILITY})
        if f.fingerprint in confirmed and f.kind is FindingKind.WEAKNESS
        else f
        for f in findings
    ]
    return upgraded, links


def _confirms(selectors: set[str], finding: Finding) -> bool:
    """Whether a selector ("C-03", or "G-01:tool results") picks out ``finding``."""
    for selector in selectors:
        check_id, _, needle = selector.partition(":")
        text = f"{finding.title}\n{finding.evidence}"
        if finding.check_id == check_id and (not needle or needle in text):
            return True
    return False


def _numbered(findings: list[Finding], links: Mapping[str, set[str]]) -> list[Finding]:
    def order(finding: Finding) -> tuple[int, int, str, str, int]:
        severity = -finding.severity.rank if finding.severity else 1
        location = finding.location
        return (
            _KIND_ORDER.index(finding.kind),
            severity,
            finding.check_id,
            location.file or location.artifact or "",
            location.line or 0,
        )

    ids = {f.fingerprint: f"F-{n:04d}" for n, f in enumerate(sorted(findings, key=order), 1)}
    return [
        finding.model_copy(
            update={
                "id": ids[finding.fingerprint],
                "related": sorted(ids[fp] for fp in links.get(finding.fingerprint, ())),
            }
        )
        for finding in sorted(findings, key=order)
    ]
