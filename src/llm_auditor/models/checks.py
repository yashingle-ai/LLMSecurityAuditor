"""Metadata that describes a security check."""

from typing import Annotated

from pydantic import Field

from llm_auditor.models._base import StrictModel
from llm_auditor.models.enums import Access, Boundary, Capability, FindingKind, InputKind, Surface

CheckId = Annotated[str, Field(pattern=r"^(P|O|C|T|A|G|SC)-\d{2}$")]
RiskId = Annotated[str, Field(pattern=r"^(LLM|ASI)\d{2}$")]  # OWASP LLM / Agentic Top 10


class CheckMeta(StrictModel, frozen=True):
    """Static description of a check, used for the catalog, planning, and scoring."""

    id: CheckId
    title: str = Field(min_length=1)
    surface: Surface
    kind: FindingKind  # the kind of finding this check normally produces
    min_access: Access
    inputs: tuple[InputKind, ...] = Field(min_length=1)  # runs when any one is available
    boundaries: tuple[Boundary, ...] = Field(min_length=1)
    maps_to: tuple[RiskId, ...] = ()
    base_impact: int = Field(ge=0, le=10)  # before context modifiers; see SEVERITY.md
    amplified_by: frozenset[Capability] = frozenset()  # target capabilities that make it worse
    remediation: str = Field(min_length=1)
