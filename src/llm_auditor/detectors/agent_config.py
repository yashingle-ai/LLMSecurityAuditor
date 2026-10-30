"""Agent configuration checks: T-01 (approvals), T-08 (step limits), T-18 (code sandboxes).

These read the agent's config files. Tool definitions have no standard place for
"needs approval" or "max steps", so agent frameworks keep them in config, and so
do these checks. Anything enforced only in code is out of their sight, which is
why "nothing found" findings have low confidence.

T-01 and T-08 also read logged runs: a destructive tool that ran without approval,
or a runaway loop, is a recorded fact, reported as a vulnerability.
"""

import json
import re
from collections import Counter
from collections.abc import Iterator
from typing import Any, ClassVar

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._text import find_line
from llm_auditor.detectors._trace import log_location, result_of, tool_capabilities
from llm_auditor.ingestion import AuditContext
from llm_auditor.inventory import tool_inventory
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    ConfigFile,
    FindingKind,
    InputKind,
    Location,
    Oracle,
    Surface,
)

APPROVAL_KEYS = re.compile(
    r"(?i)^(requires?_approval|approval_required|requires?_confirmation|confirm_tools"
    r"|tools_requiring_approval|human_approval|interrupt_before)$"
)
STEP_LIMIT_KEYS = re.compile(
    r"(?i)^(max_?steps|max_?iterations|max_iter|max_?turns|recursion_limit|step_limit"
    r"|max_tool_calls|max_rounds)$"
)
AGENT_CONFIG_HINT = re.compile(r"(?i)agent|llm|model|tool")
SANDBOX_NAME = re.compile(r"(?i)sandbox|interpreter|executor|code[-_]?runner|jupyter")
SECRET_NAME = re.compile(r"(?i)key|token|secret|password|credential")
HELD = re.compile(
    r"(?i)approv|confirm|not (been )?run|wasn't run|was not run|denied|rejected|requires|pending"
)
LOOP_REPEATS = 5  # the same call this many times in one run is a loop, not a retry
MAX_CALLS_PER_RUN = 30
SENSITIVE_MOUNTS = ("/", "/home", "/root", "/etc", "~", ".", "/var/run/docker.sock", "/Users")


def walk(data: Any) -> Iterator[tuple[str, Any]]:
    """Every (key, value) pair in nested dicts and lists."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield str(key), value
            yield from walk(value)
    elif isinstance(data, list):
        for item in data:
            yield from walk(item)


def agent_configs(context: AuditContext) -> list[ConfigFile]:
    """Config files that configure an agent or LLM (they mention agent, llm, model, or tool)."""
    return [
        config
        for config in context.artifacts.config_files
        if any(AGENT_CONFIG_HINT.search(key) for key, _ in walk(config.data))
    ]


def find_keys(
    configs: list[ConfigFile], pattern: re.Pattern[str]
) -> list[tuple[ConfigFile, str, Any]]:
    """Every (config, key, value) whose key matches ``pattern``, at any depth."""
    return [(c, key, value) for c in configs for key, value in walk(c.data) if pattern.match(key)]


def config_location(context: AuditContext, config: ConfigFile, needle: str) -> Location:
    return Location(file=config.path, line=find_line(context.read_text(config.path) or "", needle))


def _config_check(
    check_id: str,
    title: str,
    surface: Surface,
    min_access: Access,
    inputs: tuple[InputKind, ...],
    maps_to: tuple[str, ...],
    base_impact: int,
    remediation: str,
) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title=title,
        surface=surface,
        kind=FindingKind.WEAKNESS,
        min_access=min_access,
        inputs=inputs,
        boundaries=(Boundary.B4,),
        maps_to=maps_to,
        base_impact=base_impact,
        remediation=remediation,
    )


@register
class DestructiveToolsWithoutApproval:
    meta: ClassVar[CheckMeta] = _config_check(
        "T-01",
        "Destructive or financial tool runs without human approval",
        Surface.TOOL,
        Access.GRAY,
        (InputKind.TOOL_DEFS, InputKind.LOGS),
        ("LLM06", "ASI02"),
        6,
        "Require the user's explicit confirmation before any tool that deletes, changes "
        "accounts, or moves money runs, and show them the exact action and arguments. "
        "Add the tool to the agent's approval list and enforce it in the agent loop.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        risky = [
            tool
            for tool in tool_inventory(context)
            if {Capability.DESTRUCTIVE, Capability.FINANCIAL} & set(tool.profile.capabilities)
        ]
        if not risky:
            return
        approved, everything, settings = approval_settings(context)
        yield from _ran_without_approval(context, approved, everything)
        for tool in risky:
            if everything or tool.profile.name in approved:
                continue
            reason = "; ".join(tool.profile.reasons.values())
            if settings is not None:
                listed = ", ".join(sorted(approved)) or "no tools"
                yield Detection(
                    title=f"Tool '{tool.profile.name}' runs without approval",
                    location=config_location(context, settings, "approval"),
                    evidence=f"{tool.profile.name} ({reason}); approval is required for: {listed}",
                    confidence=0.85,
                )
            else:
                yield Detection(
                    title=f"Tool '{tool.profile.name}' runs without approval "
                    "(no approval settings found)",
                    location=Location(
                        file=tool.profile.source or None, artifact=f"tool:{tool.profile.name}"
                    ),
                    evidence=f"{tool.profile.name} ({reason}); "
                    "no approval settings in the config files",
                    confidence=0.6,
                )


def approval_settings(context: AuditContext) -> tuple[set[str], bool, ConfigFile | None]:
    """Tools the config requires approval for, whether it requires it for everything, and
    the config file that says so."""
    approved: set[str] = set()
    everything = False
    settings: ConfigFile | None = None
    for config in context.artifacts.config_files:
        for key, value in walk(config.data):
            if not APPROVAL_KEYS.match(key):
                continue
            settings = settings or config
            if value is True:
                everything = True
            elif isinstance(value, list):
                approved |= {str(item) for item in value}
            elif isinstance(value, dict):
                approved |= {str(name) for name, needed in value.items() if needed}
    return approved, everything, settings


def _ran_without_approval(
    context: AuditContext, approved: set[str], everything: bool
) -> Iterator[Detection]:
    """Destructive or financial calls in logged runs whose result shows they ran."""
    capabilities = tool_capabilities(context)
    runs: dict[tuple[str | None, str], tuple[Location, str, set[str]]] = {}
    for interaction in context.artifacts.interactions:
        for call in interaction.tool_calls:
            risky = {Capability.DESTRUCTIVE, Capability.FINANCIAL}
            if not capabilities.get(call.name, frozenset()) & risky:
                continue
            result = result_of(interaction, call)
            if everything or call.name in approved or result is None or HELD.search(result):
                continue
            location = log_location(interaction)
            entry = runs.setdefault(
                (location.file, call.name),
                (location, f"{call.name}({json.dumps(call.arguments)}) -> {result[:200]}", set()),
            )
            entry[2].add(interaction.id)
    for (_, name), (location, evidence, ids) in runs.items():
        yield Detection(
            title=f"Tool '{name}' ran without approval in logged runs ({len(ids)})",
            location=location,
            evidence=evidence,
            confidence=0.9,
            kind=FindingKind.VULNERABILITY,
            oracle=Oracle.DETERMINISTIC,
            corroborates=("T-01",),
        )


@register
class NoStepLimit:
    meta: ClassVar[CheckMeta] = _config_check(
        "T-08",
        "No step or budget limit on the agent loop",
        Surface.CONFIG,
        Access.WHITE,
        (InputKind.CONFIG_FILES, InputKind.LOGS),
        ("LLM10", "ASI08"),
        3,
        "Cap the agent loop (steps, tool calls, and tokens or cost per request) so an "
        "injected instruction or a confused model can't loop forever or run up the bill.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        configs = agent_configs(context)
        limits = find_keys(configs, STEP_LIMIT_KEYS)
        for config, key, value in limits:
            number = _as_int(value)
            if number is None or number <= 0:
                yield Detection(
                    title=f"The agent's step limit is turned off ({key}: {json.dumps(value)})",
                    location=config_location(context, config, key),
                    evidence=f"{key}: {json.dumps(value)}",
                    confidence=0.9,
                )
        if configs and not limits:
            yield Detection(
                title="No step or budget limit found in the agent's configuration",
                location=Location(file=configs[0].path),
                evidence="looked for max_steps, max_iterations, recursion_limit and similar in "
                + ", ".join(c.path for c in configs),
                confidence=0.5,
            )
        yield from _runaway_loops(context)


def _runaway_loops(context: AuditContext) -> Iterator[Detection]:
    """Logged runs that repeated one call, or made too many calls, to be anything but a loop."""
    worst: dict[tuple[str | None, str], tuple[Location, str, int]] = {}
    for interaction in context.artifacts.interactions:
        calls = interaction.tool_calls
        repeats = Counter((c.name, json.dumps(c.arguments, sort_keys=True)) for c in calls)
        location = log_location(interaction)
        for (name, arguments), count in repeats.items():
            key = (location.file, name)
            if count >= LOOP_REPEATS and count > worst.get(key, (location, "", 0))[2]:
                worst[key] = (location, f"{name}({arguments}) called {count} times", count)
        if len(calls) >= MAX_CALLS_PER_RUN:
            key = (location.file, "")
            if len(calls) > worst.get(key, (location, "", 0))[2]:
                worst[key] = (location, f"{len(calls)} tool calls in one run", len(calls))
    for (_, name), (location, evidence, count) in worst.items():
        what = (
            f"Tool '{name}' called {count} times with the same arguments"
            if name
            else (f"{count} tool calls")
        )
        yield Detection(
            title=f"Runaway loop in a logged run: {what}",
            location=location,
            evidence=evidence,
            confidence=0.9,
            kind=FindingKind.VULNERABILITY,
            oracle=Oracle.DETERMINISTIC,
            corroborates=("T-08",),
        )


def _internal_only(service: dict[str, Any], networks: Any) -> bool:
    """Whether every network the service joins is declared ``internal: true`` (no egress)."""
    joined = service.get("networks")
    names = list(joined) if isinstance(joined, dict | list) else []
    defined = networks if isinstance(networks, dict) else {}
    return bool(names) and all(
        isinstance(defined.get(n), dict) and defined[n].get("internal") is True for n in names
    )


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


@register
class CodeSandboxGaps:
    meta: ClassVar[CheckMeta] = _config_check(
        "T-18",
        "Code-execution sandbox has gaps",
        Surface.CONFIG,
        Access.WHITE,
        (InputKind.CONFIG_FILES, InputKind.TOOL_DEFS),
        ("ASI05", "LLM06"),
        8,
        "Run model-written code in a sandbox with no network (network_mode: none), no host "
        "mounts or Docker socket, no secrets in its environment, not privileged, and with "
        "dropped capabilities and resource limits.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        sandboxes = list(sandbox_services(context.artifacts.config_files))
        for config, name, service in sandboxes:
            networks = config.data.get("networks") if isinstance(config.data, dict) else None
            for gap, needle in sandbox_gaps(name, service, networks):
                yield Detection(
                    title=f"Code sandbox '{name}' {gap}",
                    location=config_location(context, config, needle),
                    evidence=f"service {name} in {config.path}: {gap}",
                    confidence=0.85,
                )
        runners = [
            tool.profile.name
            for tool in tool_inventory(context)
            if Capability.CODE_EXECUTION in tool.profile.capabilities
        ]
        if runners and not sandboxes and context.artifacts.config_files:
            yield Detection(
                title="No sandbox configuration found for the code-execution tools",
                location=Location(file=context.artifacts.config_files[0].path),
                evidence=f"code-execution tools: {', '.join(sorted(runners))}; no service "
                "named like a sandbox in the config files",
                confidence=0.5,
            )


def sandbox_services(configs: list[ConfigFile]) -> Iterator[tuple[ConfigFile, str, dict[str, Any]]]:
    """Docker Compose services that look like a code sandbox, by name or image."""
    for config in configs:
        services = config.data.get("services") if isinstance(config.data, dict) else None
        for name, service in (services or {}).items() if isinstance(services, dict) else []:
            if isinstance(service, dict) and (
                SANDBOX_NAME.search(str(name)) or SANDBOX_NAME.search(str(service.get("image", "")))
            ):
                yield config, str(name), service


def sandbox_gaps(
    name: str, service: dict[str, Any], networks: Any = None
) -> Iterator[tuple[str, str]]:
    """(gap, text to find its line by) for each way the sandbox is weaker than it should be."""
    if service.get("network_mode") != "none" and not _internal_only(service, networks):
        yield "has network access (no `network_mode: none` or internal-only network)", f"{name}:"
    if service.get("privileged") is True:
        yield "runs privileged", "privileged"
    for volume in service.get("volumes") or []:
        source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":")[0]
        if source in SENSITIVE_MOUNTS or source.startswith(("/home/", "/Users/", "~/")):
            yield f"mounts the host path {source}", str(source) or "volumes"
    environment = service.get("environment") or {}
    names = (
        environment
        if isinstance(environment, dict)
        else [str(e).split("=")[0] for e in environment]
    )
    for variable in names:
        if SECRET_NAME.search(str(variable)):
            yield f"gets the secret {variable} in its environment", str(variable)
    if service.get("cap_add"):
        yield f"adds Linux capabilities ({', '.join(map(str, service['cap_add']))})", "cap_add"
