"""The audit report: the canonical output every format is rendered from."""

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import computed_field, model_validator

from llm_auditor.models._base import StrictModel
from llm_auditor.models.checks import CheckMeta
from llm_auditor.models.coverage import Coverage
from llm_auditor.models.enums import Access, FindingKind, IncidentOutcome, Severity
from llm_auditor.models.finding import Finding
from llm_auditor.models.inventory import ToolProfile
from llm_auditor.models.scope import CapabilityProfile


class RunInfo(StrictModel):
    tool: str = "llm-auditor"
    tool_version: str
    rubric_version: str
    scope_name: str
    scope_digest: str  # changes whenever the scope file's content does
    access: Access
    started_at: datetime
    finished_at: datetime


class IncidentCounts(StrictModel):
    attempts: int
    succeeded: int
    failed: int
    unknown: int


class AuditReport(StrictModel):
    run: RunInfo
    capability_profile: CapabilityProfile
    coverage: Coverage
    checks: tuple[CheckMeta, ...]  # every check the audit considered
    findings: tuple[Finding, ...]
    tool_inventory: tuple[ToolProfile, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def _drop_computed_fields(cls, data: Any) -> Any:
        """A saved report includes the computed summaries; they're recomputed on load."""
        if isinstance(data, dict):
            return {
                k: v for k, v in data.items() if k not in ("severity_counts", "incident_summary")
            }
        return data

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = Counter(f.severity for f in self.findings if f.severity is not None)
        return {severity: counts[severity] for severity in reversed(Severity)}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def incident_summary(self) -> dict[str, IncidentCounts]:
        """Attack attempts seen in logs, counted per check and by outcome."""
        outcomes: dict[str, Counter[IncidentOutcome | None]] = {}
        for finding in self.findings:
            if finding.kind is FindingKind.INCIDENT:
                outcomes.setdefault(finding.check_id, Counter())[finding.outcome] += 1
        return {
            check_id: IncidentCounts(
                attempts=counts.total(),
                succeeded=counts[IncidentOutcome.SUCCEEDED],
                failed=counts[IncidentOutcome.FAILED],
                unknown=counts[IncidentOutcome.UNKNOWN],
            )
            for check_id, counts in sorted(outcomes.items())
        }

    def check(self, check_id: str) -> CheckMeta | None:
        return next((meta for meta in self.checks if meta.id == check_id), None)
