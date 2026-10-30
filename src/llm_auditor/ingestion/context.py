"""Ingest a scope's inputs into an AuditContext, and plan which checks can run."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from llm_auditor.ingestion.base import Artifact, IngestReport, Loader, read_text
from llm_auditor.ingestion.config_files import ConfigFileLoader
from llm_auditor.ingestion.dependencies import DependencyFileLoader
from llm_auditor.ingestion.discovery import discover, relative_path
from llm_auditor.ingestion.documents import DocumentLoader
from llm_auditor.ingestion.har import HarLoader
from llm_auditor.ingestion.mcp import McpConfigLoader
from llm_auditor.ingestion.model_files import ModelFileLoader
from llm_auditor.ingestion.openapi import OpenApiLoader
from llm_auditor.ingestion.prompts import PromptLoader
from llm_auditor.ingestion.source import SourceLoader
from llm_auditor.ingestion.tools import ToolDefinitionLoader
from llm_auditor.ingestion.traces import TraceLoader
from llm_auditor.models import (
    ApiSpec,
    AuditScope,
    CheckMeta,
    CheckPlan,
    ConfigFile,
    DependencyFile,
    Document,
    HarEntry,
    IngestIssue,
    InputKind,
    InputSummary,
    Interaction,
    LogInput,
    McpServerConfig,
    ModelFile,
    PromptArtifact,
    SkippedCheck,
    SourceFile,
    ToolDefinition,
)

LOADERS: dict[InputKind, Loader] = {
    InputKind.SOURCE_DIRS: SourceLoader(),
    InputKind.PROMPT_DIRS: PromptLoader(),
    InputKind.LOGS: TraceLoader(),
    InputKind.TOOL_DEFS: ToolDefinitionLoader(),
    InputKind.MCP_CONFIGS: McpConfigLoader(),
    InputKind.HAR: HarLoader(),
    InputKind.OPENAPI: OpenApiLoader(),
    InputKind.CONFIG_FILES: ConfigFileLoader(),
    InputKind.DEPENDENCY_FILES: DependencyFileLoader(),
    InputKind.MODEL_DIRS: ModelFileLoader(),
    InputKind.DOCUMENTS: DocumentLoader(),
}


@dataclass
class Artifacts:
    prompts: list[PromptArtifact] = field(default_factory=list)
    interactions: list[Interaction] = field(default_factory=list)
    tool_definitions: list[ToolDefinition] = field(default_factory=list)
    mcp_servers: list[McpServerConfig] = field(default_factory=list)
    source_files: list[SourceFile] = field(default_factory=list)
    har_entries: list[HarEntry] = field(default_factory=list)
    api_specs: list[ApiSpec] = field(default_factory=list)
    config_files: list[ConfigFile] = field(default_factory=list)
    dependency_files: list[DependencyFile] = field(default_factory=list)
    model_files: list[ModelFile] = field(default_factory=list)
    documents: list[Document] = field(default_factory=list)

    def add(self, artifact: Artifact) -> None:
        match artifact:
            case PromptArtifact():
                self.prompts.append(artifact)
            case Interaction():
                self.interactions.append(artifact)
            case ToolDefinition():
                self.tool_definitions.append(artifact)
            case McpServerConfig():
                self.mcp_servers.append(artifact)
            case SourceFile():
                self.source_files.append(artifact)
            case HarEntry():
                self.har_entries.append(artifact)
            case ApiSpec():
                self.api_specs.append(artifact)
            case ConfigFile():
                self.config_files.append(artifact)
            case DependencyFile():
                self.dependency_files.append(artifact)
            case ModelFile():
                self.model_files.append(artifact)
            case Document():
                self.documents.append(artifact)


@dataclass
class AuditContext:
    """Everything loaded for one audit: the scope, its artifacts, and what went wrong."""

    scope: AuditScope
    artifacts: Artifacts
    inputs: list[InputSummary]
    issues: list[IngestIssue]
    cache: dict[str, Any] = field(
        default_factory=dict, repr=False
    )  # shared work, e.g. a Semgrep run

    def read_text(self, rel: str) -> str | None:
        """A loaded file's text (cached), read with the same limits as ingestion."""
        key = f"text:{rel}"
        if key not in self.cache:
            report = IngestReport()
            self.cache[key] = read_text(self.scope.root / rel, rel, report)
            self.issues.extend(report.issues)
        text: str | None = self.cache[key]
        return text

    @property
    def available_inputs(self) -> frozenset[InputKind]:
        """Input kinds that produced at least one artifact, plus the target and attestations."""
        kinds = {summary.kind for summary in self.inputs if summary.artifacts}
        if self.scope.target is not None:
            kinds.add(InputKind.TARGET)
        if self.scope.attestations:
            kinds.add(InputKind.ATTESTATIONS)
        return frozenset(kinds)

    def plan(self, checks: Iterable[CheckMeta]) -> CheckPlan:
        """Split checks into those this audit can run and those it must skip, with why."""
        runnable: list[CheckMeta] = []
        skipped: list[SkippedCheck] = []
        for check in checks:
            reason = self._skip_reason(check)
            if reason is None:
                runnable.append(check)
            else:
                skipped.append(SkippedCheck(check_id=check.id, reason=reason))
        return CheckPlan(runnable=tuple(runnable), skipped=tuple(skipped))

    def _skip_reason(self, check: CheckMeta) -> str | None:
        if not self.scope.access.covers(check.min_access):
            return f"needs {check.min_access} access; this audit has {self.scope.access}"
        # Checks that read attestations always run: when answers are missing they skip
        # themselves and name the questions, which says more than "none were provided".
        if not (self.available_inputs | {InputKind.ATTESTATIONS}) & set(check.inputs):
            wanted = ", ".join(kind.value for kind in check.inputs)
            return f"needs one of: {wanted}; none were provided or loaded"
        return None


def ingest(scope: AuditScope) -> AuditContext:
    """Load every input in ``scope``. Problems are collected as issues, never raised."""
    report = IngestReport()
    artifacts = Artifacts()
    summaries: list[InputSummary] = []
    seen: set[tuple[InputKind, str]] = set()
    for kind, entry, loader in _entries(scope):
        files = discover(scope.root, entry, loader.extensions)
        if not files:
            report.warn(entry, f"no files matched this {kind.value} entry")
        loaded = 0
        for file in files:
            rel = relative_path(file, scope.root)
            if (kind, rel) in seen:
                continue
            seen.add((kind, rel))
            for artifact in loader.load(file, rel, report):
                artifacts.add(artifact)
                loaded += 1
        summaries.append(InputSummary(kind=kind, entry=entry, files=len(files), artifacts=loaded))
    return AuditContext(scope=scope, artifacts=artifacts, inputs=summaries, issues=report.issues)


def _entries(scope: AuditScope) -> Iterator[tuple[InputKind, str, Loader]]:
    for kind, loader in LOADERS.items():
        entries: list[str | LogInput] = getattr(scope.inputs, kind.value)  # names match (tested)
        for entry in entries:
            if isinstance(entry, LogInput):
                yield kind, entry.path, TraceLoader(entry.format, entry.mapping)
            else:
                yield kind, entry, loader
