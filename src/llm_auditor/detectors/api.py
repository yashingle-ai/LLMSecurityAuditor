"""API and deployment checks: A-02, A-03, A-04, A-05, A-07, A-09.

They read OpenAPI specs, HAR captures, agent config files, and source code. A-02
doesn't send requests to a live target yet; that arrives with the probe engine.
"""

import json
import re
from collections.abc import Iterator
from typing import Any, ClassVar
from urllib.parse import urlsplit

from llm_auditor.checks import Detection, register
from llm_auditor.detectors._text import find_line, split_source
from llm_auditor.detectors.agent_config import agent_configs, config_location, find_keys
from llm_auditor.ingestion import AuditContext
from llm_auditor.inventory import tool_inventory
from llm_auditor.models import (
    Access,
    Boundary,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Surface,
)

LLM_PATH = re.compile(
    r"(?i)chat|complet|generat|prompt|llm|agent|\bask\b|widget|embed|infer|predict|messages"
)
AUTH_HEADERS = ("authorization", "x-api-key", "api-key", "cookie", "proxy-authorization")
TOKEN_LIMIT_KEYS = re.compile(
    r"(?i)^(max_tokens|max_output_tokens|max_completion_tokens|max_new_tokens|num_predict)$"
)
RATE_LIMIT_KEYS = re.compile(
    r"(?i)^(rate_?limits?|requests_per_(second|minute|hour)|rpm|tpm|throttl\w*|quotas?)$"
)
MODEL_KEYS = re.compile(r"(?i)^(model|model_name|model_id|deployment|deployment_name)$")
# Config sections that list the agent's tools, for when there are no tool definitions.
TOOL_SECTIONS = re.compile(r"(?i)^(tools|toolkits?|mcp_?servers|functions)$")
AUDIT_KEYS = re.compile(
    r"(?i)^(audit_?log(ging)?|audit|log_tool_calls|tool_call_logging|tracing|telemetry)$"
)
PLAIN_HTTP = re.compile(r"\bhttp://([^/\s:\"'`<>)]+)")
NON_PUBLIC_HOSTS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|[^.]+|.*\.(local|internal|localhost))$"
)
SCHEMA_HOSTS = ("json-schema.org", "www.w3.org", "schemas.xmlsoap.org", "xmlns.com")
TLS_OFF = re.compile(
    r"verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE"
    r"|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
)
STACK_TRACE = re.compile(
    r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+"
    r"|\bat [\w.$<>]+ \([^)]*:\d+:\d+\)|\b(openai|anthropic)\.\w*Error\b"
)
# A response built on the same line: returned, raised as an HTTP error, or serialized.
RESPONSE = r"(\breturn\b|Response\(|HTTPException\(|jsonify\(|\bdetail\s*=)"
TRACE_IN_RESPONSE = re.compile(RESPONSE + r".*\b(format_exc|format_exception|format_tb)\(")
ERROR_IN_RESPONSE = re.compile(RESPONSE + r".*\b(str|repr)\((e|err|error|exc|exception)\)")
DEBUG_MODE = re.compile(
    r"FastAPI\([^)]*debug\s*=\s*True|\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True"
)
REMOTE_CODE = re.compile(r"trust_remote_code\s*=\s*True")


def _api_check(
    check_id: str,
    title: str,
    min_access: Access,
    inputs: tuple[InputKind, ...],
    boundaries: tuple[Boundary, ...],
    maps_to: tuple[str, ...],
    base_impact: int,
    remediation: str,
) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title=title,
        surface=Surface.API,
        kind=FindingKind.WEAKNESS,
        min_access=min_access,
        inputs=inputs,
        boundaries=boundaries,
        maps_to=maps_to,
        base_impact=base_impact,
        remediation=remediation,
    )


def _not_found(file: str, title: str) -> Detection:
    """A setting the config doesn't show. It may live elsewhere, hence low confidence."""
    return Detection(
        title=title,
        location=Location(file=file),
        evidence=f"{title}; it may be set elsewhere (a gateway, or code)",
        confidence=0.5,
    )


@register
class UnauthenticatedLlmEndpoint:
    meta: ClassVar[CheckMeta] = _api_check(
        "A-02",
        "LLM endpoint reachable without authentication",
        Access.GRAY,
        (InputKind.OPENAPI, InputKind.HAR),
        (Boundary.B1,),
        ("LLM10", "LLM02"),
        7,
        "Require authentication on every endpoint that reaches the model, and tie each "
        "request to a user, so usage can be limited, billed, and audited.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for spec in context.artifacts.api_specs:
            text = context.read_text(spec.path) or ""
            for op in spec.operations:
                if not LLM_PATH.search(f"{op.path} {op.operation_id or ''}"):
                    continue
                security = op.security if op.security is not None else spec.security
                if security and all(requirement for requirement in security):
                    continue  # every alternative requires credentials
                yield Detection(
                    title=f"{op.method} {op.path} needs no authentication",
                    location=Location(file=spec.path, line=find_line(text, f'"{op.path}"')),
                    evidence=f"{op.method} {op.path} ({op.operation_id or 'no operationId'}): "
                    f"security {json.dumps(security)}",
                    confidence=0.85,
                )
        seen: set[tuple[str, str]] = set()
        for entry in context.artifacts.har_entries:
            path = urlsplit(entry.url).path
            authenticated = any(header in entry.request_headers for header in AUTH_HEADERS)
            if not LLM_PATH.search(path) or authenticated or not 200 <= entry.status < 300:
                continue
            file, _ = split_source(entry.source)
            endpoint = f"{entry.method} {path}"
            if (file, endpoint) not in seen:
                seen.add((file, endpoint))
                yield Detection(
                    title=f"{endpoint} answered without credentials",
                    location=Location(file=file, artifact=f"endpoint:{endpoint}"),
                    evidence=f"{entry.method} {entry.url} -> {entry.status}, no credentials sent",
                    confidence=0.8,
                )


@register
class UnboundedConsumption:
    meta: ClassVar[CheckMeta] = _api_check(
        "A-03",
        "No limit on tokens, requests, or cost",
        Access.GRAY,
        (InputKind.CONFIG_FILES, InputKind.HAR, InputKind.LOGS),
        (Boundary.B8,),
        ("LLM10",),
        4,
        "Set max_tokens on every model call, rate-limit requests per user, and set a spend "
        "limit with the provider, so abuse or a runaway agent can't run up unbounded costs.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        configs = agent_configs(context)
        token_limits = find_keys(configs, TOKEN_LIMIT_KEYS)
        for config, key, value in token_limits:
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                yield Detection(
                    title=f"The output token limit is turned off ({key}: {json.dumps(value)})",
                    location=config_location(context, config, key),
                    evidence=f"{key}: {json.dumps(value)}",
                    confidence=0.9,
                )
        if configs and not token_limits:
            yield _not_found(configs[0].path, "No output token limit (max_tokens) in the config")
        if configs and not find_keys(configs, RATE_LIMIT_KEYS):
            yield _not_found(configs[0].path, "No rate limit in the config")

        unbounded: dict[str, int] = {}
        for interaction in context.artifacts.interactions:
            meta = interaction.request_meta
            if meta is None or not (meta.params or meta.endpoint):
                continue  # not a logged model call
            if not any(TOKEN_LIMIT_KEYS.match(key) for key in meta.params):
                file, _ = split_source(interaction.source)
                unbounded[file] = unbounded.get(file, 0) + 1
        for file, count in unbounded.items():
            yield Detection(
                title=f"Model calls sent without max_tokens ({count})",
                location=Location(file=file),
                evidence=f"{count} logged model call(s) set no output token limit",
                confidence=0.8,
            )


@register
class PlainHttpOrWeakTls:
    meta: ClassVar[CheckMeta] = _api_check(
        "A-04",
        "Unencrypted HTTP or TLS verification turned off",
        Access.GRAY,
        (InputKind.CONFIG_FILES, InputKind.HAR, InputKind.SOURCE_DIRS),
        (Boundary.B8,),
        (),
        5,
        "Use HTTPS for every call to a model provider, gateway, or tool, and keep "
        "certificate verification on. Prompts, outputs, and API keys travel in these requests.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        configs = {c.path for c in context.artifacts.config_files}
        for path in [*configs, *(s.path for s in context.artifacts.source_files)]:
            text = context.read_text(path) or ""
            for number, line in enumerate(text.splitlines(), 1):
                if path in configs:  # code is full of example and test URLs; configs aren't
                    for host in PLAIN_HTTP.findall(line):
                        if _public(host):
                            yield _plain_http(path, number, host, line)
                if TLS_OFF.search(line):
                    yield Detection(
                        title="TLS certificate verification is turned off",
                        location=Location(file=path, line=number),
                        evidence=line.strip(),
                        confidence=0.9,
                    )
        for entry in context.artifacts.har_entries:
            host = urlsplit(entry.url).hostname or ""
            if entry.url.startswith("http://") and _public(host):
                file, _ = split_source(entry.source)
                yield _plain_http(file, None, host, f"{entry.method} {entry.url}")


def _public(host: str) -> bool:
    return not NON_PUBLIC_HOSTS.match(host) and host not in SCHEMA_HOSTS


def _plain_http(path: str, line: int | None, host: str, evidence: str) -> Detection:
    return Detection(
        title=f"Unencrypted HTTP to {host}",
        location=Location(file=path, line=line, artifact=f"host:{host}"),
        evidence=evidence.strip(),
        confidence=0.85,
    )


@register
class VerboseErrors:
    meta: ClassVar[CheckMeta] = _api_check(
        "A-05",
        "Errors expose stack traces or provider details",
        Access.GRAY,
        (InputKind.HAR, InputKind.SOURCE_DIRS),
        (Boundary.B1,),
        ("LLM02",),
        4,
        "Log errors server-side and return a generic message. Stack traces and provider "
        "errors reveal code paths, file names, models, and sometimes keys or prompts.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for source in context.artifacts.source_files:
            text = context.read_text(source.path) or ""
            for number, line in enumerate(text.splitlines(), 1):
                if TRACE_IN_RESPONSE.search(line):
                    title, confidence = "A stack trace is sent back in a response", 0.8
                elif DEBUG_MODE.search(line):
                    title, confidence = "Debug mode is on (it shows stack traces to callers)", 0.8
                elif ERROR_IN_RESPONSE.search(line):
                    # Provider errors can carry model names, org IDs, or the prompt itself.
                    title, confidence = "An exception's message is sent back in a response", 0.6
                else:
                    continue
                yield Detection(
                    title=title,
                    location=Location(file=source.path, line=number),
                    evidence=line.strip(),
                    confidence=confidence,
                )
        reported: set[str] = set()
        for entry in context.artifacts.har_entries:
            file, _ = split_source(entry.source)
            trace = STACK_TRACE.search(entry.response_body or "")
            if entry.status < 400 or trace is None or file in reported:
                continue
            reported.add(file)
            endpoint = f"{entry.method} {urlsplit(entry.url).path}"
            yield Detection(
                title=f"An error response includes a stack trace ({endpoint})",
                location=Location(file=file, artifact=f"endpoint:{endpoint}"),
                evidence=f"{entry.status} response: {trace[0]}",
                confidence=0.85,
            )


@register
class UnpinnedModel:
    meta: ClassVar[CheckMeta] = _api_check(
        "A-07",
        "Model version not pinned, or model code trusted blindly",
        Access.WHITE,
        (InputKind.CONFIG_FILES, InputKind.SOURCE_DIRS),
        (Boundary.B8,),
        ("LLM03",),
        5,
        "Pin an exact, dated model version (and a revision for downloaded models), so a "
        "provider-side change can't silently change behavior, and never set "
        "trust_remote_code=True for models you haven't reviewed.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for config, key, value in find_keys(agent_configs(context), MODEL_KEYS):
            if isinstance(value, str) and re.search(r"(?i)(^|[-:_ ])latest$", value.strip()):
                yield Detection(
                    title=f"The model isn't pinned to a version ({key}: {value})",
                    location=config_location(context, config, value),
                    evidence=f"{key}: {value}",
                    confidence=0.85,
                )
        for source in context.artifacts.source_files:
            text = context.read_text(source.path) or ""
            for number, line in enumerate(text.splitlines(), 1):
                if REMOTE_CODE.search(line):
                    yield Detection(
                        title="Model code is downloaded and run (trust_remote_code=True)",
                        location=Location(file=source.path, line=number),
                        evidence=line.strip(),
                        confidence=0.9,
                    )


@register
class NoAuditTrail:
    meta: ClassVar[CheckMeta] = _api_check(
        "A-09",
        "No audit trail of tool calls and approvals",
        Access.WHITE,
        (InputKind.CONFIG_FILES,),
        (Boundary.B4,),
        ("ASI08",),
        3,
        "Record every tool call (who asked, which tool, which arguments, whether it was "
        "approved) in an append-only log kept apart from the app, so incidents can be "
        "investigated and agent actions attributed.",
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        configs = agent_configs(context)
        if not tool_inventory(context) and not find_keys(configs, TOOL_SECTIONS):
            return  # no tools, no tool calls to audit
        settings = find_keys(configs, AUDIT_KEYS)
        for config, key, value in settings:
            if not _enabled(value):
                yield Detection(
                    title=f"Audit logging of tool calls is turned off ({key})",
                    location=config_location(context, config, key),
                    evidence=f"{key}: {json.dumps(value)}",
                    confidence=0.9,
                )
        if configs and not settings:
            yield _not_found(configs[0].path, "No audit log of tool calls in the config")


def _enabled(value: Any) -> bool:
    """A setting is on if it is truthy, or a section without ``enabled: false``."""
    if isinstance(value, dict):
        return value.get("enabled", True) is not False
    return bool(value)
