"""The tool inventory: every tool an audited agent can call, and what it lets the agent do."""

from pydantic import Field

from llm_auditor.models._base import StrictModel
from llm_auditor.models.enums import Capability


class ToolProfile(StrictModel, frozen=True):
    name: str
    source: str  # the file the definition came from
    capabilities: tuple[Capability, ...] = ()
    reasons: dict[Capability, str] = Field(default_factory=dict)  # why each capability was given
    overridden: bool = False  # set by capability_overrides in the scope file
