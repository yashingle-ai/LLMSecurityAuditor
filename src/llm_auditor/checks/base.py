"""What a check is, and what it reports."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar, Protocol

from llm_auditor.ingestion import AuditContext
from llm_auditor.models import CheckMeta, FindingKind, IncidentOutcome, Location, Oracle


@dataclass(frozen=True)
class Detection:
    """One issue a check found. The runner scores, fingerprints, and numbers it."""

    title: str
    location: Location
    evidence: str  # mask whatever the check itself detected; the runner also redact()s it
    confidence: float = 1.0
    oracle: Oracle = Oracle.RULE
    kind: FindingKind | None = None  # defaults to the check's kind
    remediation: str | None = None  # defaults to the check's remediation
    outcome: IncidentOutcome | None = None  # incidents only: whether the attack worked
    # Findings this is evidence for: "C-03" for any C-03 finding, "G-01:tool results" for
    # those whose title or evidence mentions "tool results". A succeeded incident or a
    # vulnerability confirms them: their weaknesses are reported as vulnerabilities, linked.
    corroborates: tuple[str, ...] = ()


class CheckUnavailable(Exception):
    """Raised by a check that can't run here, e.g. because a tool it needs is missing.

    The audit reports it as skipped, with this exception's message as the reason.
    """


class Check(Protocol):
    meta: ClassVar[CheckMeta]

    def run(self, context: AuditContext) -> Iterable[Detection]: ...
