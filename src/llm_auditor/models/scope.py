"""The audit scope file: what to audit, with what access, and how much is at stake."""

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import AnyHttpUrl, Field, model_validator

from llm_auditor.models._base import StrictModel
from llm_auditor.models.enums import Access, Autonomy, Capability, DataSensitivity, Exposure


class TargetConfig(StrictModel):
    """A live endpoint for active probing. Probes may only reach hosts in ``allow_list``."""

    adapter: Literal["http_chat", "openai_compatible", "scripted"]
    base_url: AnyHttpUrl
    allow_list: tuple[str, ...] = Field(min_length=1)  # "host" or "host:port"

    @model_validator(mode="after")
    def _target_is_allow_listed(self) -> Self:
        host, port = self.base_url.host, self.base_url.port
        if host not in self.allow_list and f"{host}:{port}" not in self.allow_list:
            raise ValueError(f"target {host}:{port} is not in allow_list")
        return self


class LogMapping(StrictModel):
    """Where to find each field in a custom log format, as dotted paths (``output.choices.0``)."""

    user: str
    assistant: str | None = None
    system: str | None = None
    id: str | None = None
    timestamp: str | None = None
    model: str | None = None


class LogInput(StrictModel):
    """A trace log entry with an explicit format. A plain string means ``format: auto``."""

    path: str = Field(min_length=1)
    format: Literal["auto", "openai", "anthropic", "mapped"] = "auto"
    mapping: LogMapping | None = None

    @model_validator(mode="after")
    def _mapping_matches_format(self) -> Self:
        if (self.format == "mapped") != (self.mapping is not None):
            raise ValueError("format 'mapped' needs a mapping, and only mapped logs take one")
        return self


class ScopeInputs(StrictModel):
    """Paths, directories, or glob patterns to audit, one list per input kind."""

    source_dirs: list[str] = Field(default_factory=list)
    prompt_dirs: list[str] = Field(default_factory=list)
    logs: list[str | LogInput] = Field(default_factory=list)
    tool_defs: list[str] = Field(default_factory=list)
    mcp_configs: list[str] = Field(default_factory=list)
    har: list[str] = Field(default_factory=list)
    openapi: list[str] = Field(default_factory=list)
    config_files: list[str] = Field(default_factory=list)
    # Requirements files, lockfiles, package.json.
    dependency_files: list[str] = Field(default_factory=list)
    model_dirs: list[str] = Field(default_factory=list)  # model weights (.pkl, .pt, .safetensors)
    # What the app retrieves or ingests: a RAG corpus, a knowledge base (HTML, PDF, DOCX, text).
    documents: list[str] = Field(default_factory=list)


class InjectionClassifierSettings(StrictModel):
    """Which prompt-injection classifier the injection checks use.

    ``rules`` is built in and deterministic. ``huggingface`` runs a local model
    (needs the ``classifier`` extra); its weights are downloaded once and cached.
    """

    backend: Literal["rules", "huggingface"] = "rules"
    model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    threshold: float = Field(default=0.5, ge=0, le=1)
    # The model's labels that mean "injection"; any other label means benign.
    injection_labels: tuple[str, ...] = ("INJECTION", "LABEL_1", "MALICIOUS", "JAILBREAK")


class CapabilityProfile(StrictModel):
    """What the target can do and how exposed it is.

    Every field is required: these drive severity, and a silent default would
    understate it.
    """

    exposure: Exposure
    autonomy: Autonomy
    data_sensitivity: DataSensitivity
    multi_tenant: bool
    capabilities: frozenset[Capability]

    @classmethod
    def neutral(cls) -> Self:
        """No context modifiers: severity is each check's base impact. Reports must say so."""
        return cls(
            exposure=Exposure.INTERNAL,
            autonomy=Autonomy.HUMAN_IN_LOOP,
            data_sensitivity=DataSensitivity.MEDIUM,
            multi_tenant=False,
            capabilities=frozenset(),
        )


class AuditScope(StrictModel):
    name: str = Field(min_length=1)
    access: Access
    capability_profile: CapabilityProfile
    root: Path = Path()  # base for relative input paths; in a scope file, relative to the file
    target: TargetConfig | None = None  # omitted for static-only audits
    inputs: ScopeInputs = Field(default_factory=ScopeInputs)
    # Replace the inventory's guess for a tool, by name, when the heuristics get it wrong.
    capability_overrides: dict[str, list[Capability]] = Field(default_factory=dict)
    # Approved tool definitions (`llmaudit tools lock`), relative to root. T-12 diffs against it.
    tool_lock: str = ".llmaudit/tools.lock.json"
    # An OSV advisory snapshot from `llmaudit advisories update`; the built-in one if unset.
    advisory_db: str | None = None
    attestations: dict[str, str | int | float | bool] = Field(default_factory=dict)
    # Unique strings planted in the system prompt. One in a response proves the prompt leaked.
    canaries: list[str] = Field(default_factory=list)
    injection_classifier: InjectionClassifierSettings = Field(
        default_factory=InjectionClassifierSettings
    )

    @classmethod
    def from_yaml(cls, path: Path) -> Self:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a mapping at the top level")
        data["root"] = (path.parent / str(data.get("root", "."))).resolve()
        return cls.model_validate(data)
