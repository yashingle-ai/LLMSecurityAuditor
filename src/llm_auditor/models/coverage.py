"""What an audit could and couldn't cover."""

from pydantic import Field

from llm_auditor.models._base import StrictModel
from llm_auditor.models.checks import CheckId, CheckMeta
from llm_auditor.models.enums import InputKind


class InputSummary(StrictModel, frozen=True):
    """What one scope input entry loaded."""

    kind: InputKind
    entry: str
    files: int = Field(ge=0)
    artifacts: int = Field(ge=0)


class IngestIssue(StrictModel, frozen=True):
    """A problem loading an input. The input (or the bad part of it) was skipped."""

    path: str
    line: int | None = Field(default=None, ge=1)
    message: str


class SkippedCheck(StrictModel, frozen=True):
    check_id: CheckId
    reason: str


class FailedCheck(StrictModel, frozen=True):
    """A check that crashed. Its part of the audit is missing, so reports call it out."""

    check_id: CheckId
    error: str


class Coverage(StrictModel):
    """What the audit covered, and what it didn't."""

    ran: tuple[CheckId, ...] = ()
    skipped: tuple[SkippedCheck, ...] = ()
    failed: tuple[FailedCheck, ...] = ()
    inputs: tuple[InputSummary, ...] = ()
    ingest_issues: tuple[IngestIssue, ...] = ()
    notes: tuple[str, ...] = ()  # caveats, e.g. "no capability profile was given"


class CheckPlan(StrictModel):
    runnable: tuple[CheckMeta, ...] = ()
    skipped: tuple[SkippedCheck, ...] = ()
