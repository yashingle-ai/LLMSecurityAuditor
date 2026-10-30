"""Built-in checks. Importing this package registers every one of them."""

from llm_auditor.detectors import (
    agent_config,
    api,
    code,
    generated_code,
    guardrails,
    injection,
    obfuscation,
    outputs,
    pii,
    provider,
    runtime,
    secrets,
    supply_chain,
    templates,
    tools,
)

__all__ = [
    "agent_config",
    "api",
    "code",
    "generated_code",
    "guardrails",
    "injection",
    "obfuscation",
    "outputs",
    "pii",
    "provider",
    "runtime",
    "secrets",
    "supply_chain",
    "templates",
    "tools",
]
