"""Findings: the issues the auditor reports."""

from datetime import datetime
from typing import Literal, Self

from pydantic import Field, model_validator

from llm_auditor.models._base import StrictModel
from llm_auditor.models.checks import CheckId
from llm_auditor.models.enums import (
    FindingKind,
    FindingStatus,
    IncidentOutcome,
    Oracle,
    Severity,
)


class Location(StrictModel, frozen=True):
    """Where a finding was observed: a file, a logical artifact, or both.

    ``artifact`` is a stable logical name such as ``tool:send_email`` or
    ``endpoint:/chat``. Fingerprints include it, so it must not contain
    run-specific values like timestamps or generated IDs.
    """

    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    artifact: str | None = None

    @model_validator(mode="after")
    def _has_file_or_artifact(self) -> Self:
        if self.file is None and self.artifact is None:
            raise ValueError("a location needs a file or an artifact")
        return self


class AttackSuccessRate(StrictModel, frozen=True):
    successes: int = Field(ge=0)
    trials: int = Field(ge=1)

    @model_validator(mode="after")
    def _successes_within_trials(self) -> Self:
        if self.successes > self.trials:
            raise ValueError("successes cannot exceed trials")
        return self

    @property
    def rate(self) -> float:
        return self.successes / self.trials

    def __str__(self) -> str:
        return f"{self.successes}/{self.trials}"


class Repro(StrictModel):
    """How to reproduce a finding."""

    steps: list[str] = Field(min_length=1)  # human-readable
    replay_file: str | None = None  # machine-replayable request sequence (Stage 10)
    model: str | None = None
    temperature: float | None = None
    recorded_at: datetime | None = None


class Finding(StrictModel):
    """One reported issue. ``evidence`` must already be redacted."""

    id: str = Field(min_length=1)
    fingerprint: str = Field(min_length=1)
    check_id: CheckId
    kind: FindingKind
    title: str = Field(min_length=1)
    severity: Severity | None  # only vulnerabilities and weaknesses have one
    severity_score: int | None = Field(default=None, ge=0, le=10)
    severity_factors: list[str] = Field(default_factory=list)  # e.g. "internet-facing +1"
    confidence: float = Field(ge=0, le=1)  # reported separately; never folded into severity
    oracle: Oracle
    location: Location
    evidence: str
    remediation: str = Field(min_length=1)
    asr: AttackSuccessRate | None = None  # probe findings only
    repro: Repro | None = None
    status: FindingStatus = FindingStatus.OPEN
    outcome: IncidentOutcome | None = None  # incidents only: did the attack work?
    related: list[str] = Field(default_factory=list)  # IDs of chained findings
    source: Literal["baseline", "agent"] = "baseline"

    @model_validator(mode="after")
    def _severity_matches_kind(self) -> Self:
        if self.kind.has_severity and self.severity is None:
            raise ValueError(f"{self.kind} findings need a severity")
        if not self.kind.has_severity and self.severity is not None:
            raise ValueError(f"{self.kind} findings carry no severity")
        return self

    @model_validator(mode="after")
    def _only_incidents_have_an_outcome(self) -> Self:
        if self.kind is FindingKind.INCIDENT and self.outcome is None:
            self.outcome = IncidentOutcome.UNKNOWN
        elif self.kind is not FindingKind.INCIDENT and self.outcome is not None:
            raise ValueError("only incidents have an outcome")
        return self

    @model_validator(mode="after")
    def _vulnerability_was_reproduced(self) -> Self:
        never_succeeded = self.asr is not None and self.asr.successes == 0
        if self.kind is FindingKind.VULNERABILITY and never_succeeded:
            raise ValueError("a vulnerability needs at least one successful trial")
        return self
