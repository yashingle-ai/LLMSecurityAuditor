"""The tool inventory: which tools an agent can call, and what each one lets it do.

Capabilities are inferred mostly from a tool's name and parameter schema, which
are more reliable than its free-text description. Each capability records why
it was given. ``capability_overrides`` in the scope file replaces the guess for
any tool.
"""

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from llm_auditor.ingestion import AuditContext
from llm_auditor.ingestion.base import split_source
from llm_auditor.models import Capability, Interaction, ToolDefinition, ToolProfile

SHELL_WORDS = frozenset({"shell", "bash", "terminal", "subprocess", "powershell", "zsh"})
COMMAND_PARAMS = frozenset({"command", "cmd", "shell_command"})
EXEC_VERBS = frozenset({"run", "exec", "execute", "eval", "evaluate", "interpret"})
CODE_NOUNS = frozenset({"code", "python", "script", "javascript", "notebook"})
CODE_PARAMS = frozenset({"code", "script", "python_code", "source_code"})
URL_PARAMS = frozenset({"url", "uri", "endpoint", "webhook", "webhook_url", "link", "href"})
DESTINATION_PARAMS = URL_PARAMS | frozenset(
    {"to", "recipient", "recipients", "email", "address", "channel", "host", "cc", "bcc", "phone"}
)
SEND_WORDS = frozenset(
    {"send", "post", "email", "mail", "notify", "message", "sms", "tweet", "publish", "upload"}
    | {"share", "forward", "webhook"}
)
UNTRUSTED_WORDS = frozenset(
    {"fetch", "browse", "browser", "scrape", "crawl", "web", "webpage", "website", "page", "url"}
    | {"inbox", "rss", "feed", "download", "internet"}
)
PRIVATE_NOUNS = frozenset(
    {"invoice", "invoices", "account", "accounts", "customer", "customers", "user", "users"}
    | {"profile", "inbox", "email", "emails", "message", "messages", "order", "orders"}
    | {"record", "records", "file", "files", "document", "documents", "database", "db", "crm"}
    | {"ticket", "tickets", "payment", "payments", "contact", "contacts", "transaction"}
    | {"transactions", "balance", "history", "note", "notes"}
)
READ_VERBS = frozenset(
    {"get", "read", "list", "lookup", "look", "search", "find", "query", "show", "view"}
    | {"report", "fetch", "load", "retrieve", "export"}
)
DELETE_VERBS = frozenset(
    {"delete", "remove", "drop", "destroy", "cancel", "revoke", "purge", "truncate", "wipe"}
    | {"terminate", "deactivate", "erase"}
)
MONEY_VERBS = frozenset(
    {"pay", "payment", "refund", "charge", "transfer", "purchase", "buy", "withdraw", "payout"}
    | {"wire", "checkout"}
)
WRITE_VERBS = frozenset({"write", "save", "create", "upload", "append", "put", "store"})
PATH_PARAMS = frozenset({"path", "file", "filename", "file_path", "filepath", "destination"})
MEMORY_WORDS = frozenset({"remember", "memorize", "memorise", "memory", "memories"})
MEMORY_VERBS = WRITE_VERBS | frozenset({"remember", "memorize", "memorise", "add", "update"})

_WORD = re.compile(r"[^\W\d_]+")


@dataclass(frozen=True)
class InventoryTool:
    definition: ToolDefinition
    profile: ToolProfile


def tool_inventory(context: AuditContext) -> list[InventoryTool]:
    """The audited agent's tools, deduplicated and classified (cached on the context)."""
    cached = context.cache.get("inventory")
    if cached is None:
        definitions = unique_definitions(
            context.artifacts.tool_definitions, context.artifacts.interactions
        )
        overrides = context.scope.capability_overrides
        cached = [InventoryTool(d, profile(d, overrides)) for d in definitions]
        context.cache["inventory"] = cached
    inventory: list[InventoryTool] = cached
    return inventory


def unique_definitions(
    tool_definitions: Iterable[ToolDefinition], interactions: Iterable[Interaction]
) -> list[ToolDefinition]:
    """Definitions from tool files, plus any that only appear in logs (sourced to the log)."""
    unique: dict[tuple[str, str, str], ToolDefinition] = {}
    for tool in tool_definitions:
        unique.setdefault((tool.source or "", tool.name, canonical(tool)), tool)
    known = {(name, body) for _, name, body in unique}
    for interaction in interactions:
        log, _ = split_source(interaction.source)
        for tool in interaction.tool_definitions:
            if (tool.name, canonical(tool)) not in known:
                known.add((tool.name, canonical(tool)))
                unique[(log, tool.name, canonical(tool))] = tool.model_copy(update={"source": log})
    return list(unique.values())


def canonical(tool: ToolDefinition) -> str:
    """A stable text form of what a tool tells the model: its description and schema."""
    body = {"description": tool.description, "parameters": tool.parameters}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def profile(tool: ToolDefinition, overrides: Mapping[str, list[Capability]]) -> ToolProfile:
    if tool.name in overrides:
        reasons = {capability: "set in the scope file" for capability in overrides[tool.name]}
    else:
        reasons = classify(tool)
    return ToolProfile(
        name=tool.name,
        source=tool.source or "",
        capabilities=tuple(c for c in Capability if c in reasons),
        reasons=reasons,
        overridden=tool.name in overrides,
    )


def classify(tool: ToolDefinition) -> dict[Capability, str]:
    """Each capability the tool appears to give, with the reason."""
    name, description = words(tool.name), words(tool.description)
    text = name | description
    parameters = properties(tool.parameters)
    free = {p.lower() for p, schema in parameters.items() if is_free_text(schema)}
    constrained_urls = {p.lower() for p in parameters} & URL_PARAMS - free
    found: dict[Capability, str] = {}

    shell = (text & SHELL_WORDS) | (free & COMMAND_PARAMS)
    code = ((name & EXEC_VERBS) and (text & CODE_NOUNS)) | (free & CODE_PARAMS)
    if shell:
        found[Capability.CODE_EXECUTION] = f"runs shell commands ({_listed(shell)})"
    elif code:
        found[Capability.CODE_EXECUTION] = f"runs code ({_listed(code)})"

    urls = free & URL_PARAMS
    destinations = free & DESTINATION_PARAMS
    if urls or (destinations and text & SEND_WORDS):
        found[Capability.EXTERNAL_COMMUNICATION] = (
            f"the model chooses where it goes ({_listed(urls or destinations)})"
        )

    untrusted = text & UNTRUSTED_WORDS
    if untrusted and not (constrained_urls and not urls):
        found[Capability.INGESTS_UNTRUSTED_CONTENT] = (
            f"returns outside content ({_listed(untrusted)})"
        )

    nouns = name & PRIVATE_NOUNS
    if nouns and (name & READ_VERBS or not name & (DELETE_VERBS | WRITE_VERBS | SEND_WORDS)):
        found[Capability.READS_PRIVATE_DATA] = f"reads {_listed(nouns)}"
    if name & DELETE_VERBS:
        found[Capability.DESTRUCTIVE] = f"its name says {_listed(name & DELETE_VERBS)}"
    if name & MONEY_VERBS:
        found[Capability.FINANCIAL] = f"its name says {_listed(name & MONEY_VERBS)}"
    if name & MEMORY_WORDS and (name & MEMORY_VERBS or "remember" in name):
        found[Capability.WRITES_MEMORY] = (
            f"saves to memory read in later conversations ({_listed(name & MEMORY_WORDS)})"
        )
    if name & WRITE_VERBS and free & PATH_PARAMS:
        found[Capability.FILE_WRITE] = (
            f"writes to a path the model chooses ({_listed(free & PATH_PARAMS)})"
        )
    return found


def words(text: str) -> set[str]:
    """Lower-case words, splitting snake_case and camelCase."""
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    return {word.lower() for word in _WORD.findall(spaced)}


def properties(schema: Mapping[str, Any]) -> dict[str, Any]:
    found = schema.get("properties")
    return found if isinstance(found, dict) else {}


def is_free_text(schema: Any) -> bool:
    """A string (or list of strings) the model can set to anything: no enum, const, or pattern."""
    if not isinstance(schema, dict):
        return False
    kind = schema.get("type", "string")
    kinds = kind if isinstance(kind, list) else [kind]
    if "array" in kinds:
        return is_free_text(schema.get("items", {}))
    return "string" in kinds and not any(key in schema for key in ("enum", "const", "pattern"))


def _listed(values: Iterable[str]) -> str:
    return ", ".join(sorted(values))
