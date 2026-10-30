"""C-01 to C-06: how application code handles LLM input and output.

Uses Semgrep (an external tool) with the taint rules in ``rules/semgrep/``.
Semgrep's free edition follows data within a function, not across them, so
the rules look for each flaw's source and sink in the same function.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from typing import ClassVar

from llm_auditor.checks import CheckUnavailable, Detection, register
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    IngestIssue,
    InputKind,
    Location,
    Surface,
)
from llm_auditor.rules import SEMGREP_RULES_DIR

SEMGREP_TIMEOUT = 600  # seconds
INSTALL_HINT = "install it with `uv tool install semgrep`, or set LLMAUDIT_SEMGREP to its path"
_INJECTION_AMPLIFIERS = frozenset(
    {
        Capability.EXTERNAL_COMMUNICATION,
        Capability.CODE_EXECUTION,
        Capability.FILE_WRITE,
        Capability.DESTRUCTIVE,
        Capability.FINANCIAL,
    }
)


@dataclass(frozen=True)
class SemgrepMatch:
    check_id: str
    path: str
    start_line: int
    end_line: int


def semgrep_binary() -> str | None:
    return os.environ.get("LLMAUDIT_SEMGREP") or shutil.which("semgrep")


def semgrep_matches(context: AuditContext) -> list[SemgrepMatch]:
    """Semgrep's matches for every C-check, from one run per audit (cached on the context)."""
    cached = context.cache.get("semgrep")
    if cached is None:
        try:
            cached = _run_semgrep(context)
        except CheckUnavailable as unavailable:
            cached = unavailable
        context.cache["semgrep"] = cached
    if isinstance(cached, CheckUnavailable):
        raise cached
    matches: list[SemgrepMatch] = cached
    return matches


def _run_semgrep(context: AuditContext) -> list[SemgrepMatch]:
    binary = semgrep_binary()
    if binary is None:
        raise CheckUnavailable(f"semgrep is not installed; {INSTALL_HINT}")
    targets = [f.path for f in context.artifacts.source_files if f.language == "python"]
    if not targets:
        return []
    command = [
        binary,
        "scan",
        "--config",
        str(SEMGREP_RULES_DIR),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--quiet",
        *targets,
    ]
    try:
        completed = subprocess.run(  # noqa: S603  (fixed arguments plus file paths; no shell)
            command,
            cwd=context.scope.root,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT,
            check=False,
        )
        output = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckUnavailable(f"semgrep could not run: {error}") from error
    except json.JSONDecodeError as error:
        detail = completed.stderr.strip().splitlines()[-1:] or ["no output"]
        raise CheckUnavailable(
            f"semgrep failed (exit {completed.returncode}): {detail[0]}"
        ) from error

    for problem in output.get("errors", []):
        path = str(problem.get("path") or "semgrep")
        message = str(problem.get("message") or problem.get("type") or "unknown error")
        context.issues.append(IngestIssue(path=path, message=f"semgrep: {message.splitlines()[0]}"))
    return [
        SemgrepMatch(
            check_id=str(result["extra"]["metadata"]["check"]),
            path=str(result["path"]),
            start_line=int(result["start"]["line"]),
            end_line=int(result["end"]["line"]),
        )
        for result in output.get("results", [])
        if "check" in result.get("extra", {}).get("metadata", {})
    ]


class _SemgrepCheck:
    meta: ClassVar[CheckMeta]

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for match in semgrep_matches(context):
            if match.check_id == self.meta.id:
                yield Detection(
                    title=self.meta.title,
                    location=Location(file=match.path, line=match.start_line),
                    evidence=_source_lines(context, match),
                    confidence=0.8,
                )


def _source_lines(context: AuditContext, match: SemgrepMatch, limit: int = 4) -> str:
    """The matched code, read from the file (Semgrep's own copy can be withheld)."""
    lines = (context.read_text(match.path) or "").splitlines()
    end = min(match.end_line, match.start_line + limit - 1)
    return "\n".join(line.strip() for line in lines[match.start_line - 1 : end])


def _code_check(
    check_id: str,
    title: str,
    boundary: Boundary,
    maps_to: tuple[str, ...],
    base_impact: int,
    remediation: str,
    amplified_by: frozenset[Capability] = frozenset(),
) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title=title,
        surface=Surface.CODE,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.SOURCE_DIRS,),
        boundaries=(boundary,),
        maps_to=maps_to,
        base_impact=base_impact,
        amplified_by=amplified_by,
        remediation=remediation,
    )


@register
class UserInputInSystemPrompt(_SemgrepCheck):
    meta = _code_check(
        "C-01",
        "User input inserted into the system prompt",
        Boundary.B2,
        ("LLM01",),
        6,
        "Keep the system prompt fixed. Send user-supplied text as a user message, clearly "
        "marked as data, so it never carries the developer's authority.",
        _INJECTION_AMPLIFIERS,
    )


@register
class OutputToCodeExecution(_SemgrepCheck):
    meta = _code_check(
        "C-02",
        "Model output reaches code or shell execution",
        Boundary.B5,
        ("LLM05", "ASI05"),
        9,
        "Never eval, exec, or shell out with model output. Parse it into a narrow, validated "
        "structure (for arithmetic, a whitelist of AST nodes), or run it in an isolated sandbox.",
    )


@register
class OutputToSql(_SemgrepCheck):
    meta = _code_check(
        "C-03",
        "Model output built into a SQL query",
        Boundary.B5,
        ("LLM05",),
        8,
        "Pass model-chosen values as query parameters. If the model must write SQL, run it "
        "read-only with an allow-list of tables and the end user's own permissions.",
        frozenset({Capability.READS_PRIVATE_DATA}),
    )


@register
class OutputToHtml(_SemgrepCheck):
    meta = _code_check(
        "C-04",
        "Model output rendered as raw HTML",
        Boundary.B5,
        ("LLM05",),
        6,
        "Escape model output before putting it in HTML (html.escape), or sanitize it with an "
        "allow-list sanitizer, and block remote images to stop data leaking through image URLs.",
    )


@register
class OutputToPathOrUrl(_SemgrepCheck):
    meta = _code_check(
        "C-05",
        "Model output chooses a file path or a URL to request",
        Boundary.B5,
        ("LLM05", "ASI02"),
        7,
        "Check model-chosen URLs against an allow-list of HTTPS hosts (and block internal "
        "addresses), and resolve paths inside one permitted directory before opening them.",
        frozenset({Capability.READS_PRIVATE_DATA}),
    )


@register
class ToolWithoutAuthorization(_SemgrepCheck):
    meta = _code_check(
        "C-06",
        "Tool handler doesn't check the requesting user's access",
        Boundary.B4,
        ("ASI03",),
        8,
        "Authorize every tool call as the end user: check that the requested resource belongs "
        "to the user the agent is acting for, in code, not in the prompt.",
        frozenset({Capability.READS_PRIVATE_DATA, Capability.DESTRUCTIVE, Capability.FINANCIAL}),
    )


@register
class VectorSearchWithoutTenantFilter(_SemgrepCheck):
    meta = CheckMeta(
        id="A-08",
        title="Vector search without a per-tenant filter",
        surface=Surface.CODE,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.SOURCE_DIRS,),
        boundaries=(Boundary.B3,),
        maps_to=("LLM08", "LLM02"),
        base_impact=7,
        amplified_by=frozenset({Capability.READS_PRIVATE_DATA}),
        remediation=(
            "Filter every retrieval by the requesting user's tenant (a metadata filter, a "
            "namespace, or a separate index per tenant), enforced in code, never left to the "
            "model or the prompt."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        if not context.scope.capability_profile.multi_tenant:
            raise CheckUnavailable("only applies to multi-tenant apps (capability_profile)")
        yield from super().run(context)
