"""Shared vocabulary for findings, checks, and audit scopes."""

from enum import StrEnum


class Severity(StrEnum):
    """Qualitative severity, lowest first. Score ranges are in documentation/SEVERITY.md."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class FindingKind(StrEnum):
    VULNERABILITY = "vulnerability"  # confirmed exploitable
    WEAKNESS = "weakness"  # design or configuration flaw, not yet exploited
    HARDENING = "hardening"  # best-practice advice; no severity
    INCIDENT = "incident"  # attack seen in logs; aggregated, no severity

    @property
    def has_severity(self) -> bool:
        return self in (FindingKind.VULNERABILITY, FindingKind.WEAKNESS)


class IncidentOutcome(StrEnum):
    """Whether an attack attempt seen in logs worked."""

    SUCCEEDED = "succeeded"  # the model or a tool did what the attack asked
    FAILED = "failed"  # refused, blocked by a guardrail, or rejected by the tool
    UNKNOWN = "unknown"  # nothing in the log shows either way


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class Access(StrEnum):
    """How much of the target the auditor can see, least first."""

    BLACK = "black"  # endpoint only
    GRAY = "gray"  # logs, configs, can plant canaries or content
    WHITE = "white"  # source code, system prompts, tool code

    def covers(self, required: "Access") -> bool:
        """Whether an audit with this access can run a check that needs ``required``."""
        order = list(Access)
        return order.index(self) >= order.index(required)


class Oracle(StrEnum):
    """What established a finding."""

    DETERMINISTIC = "deterministic"  # canary token, callback hit, recorded tool call
    RULE = "rule"
    CLASSIFIER = "classifier"
    LLM_JUDGE = "llm_judge"
    ATTESTATION = "attestation"  # a human's answer in the scope file


class Surface(StrEnum):
    PROMPT = "prompt"
    OUTPUT = "output"
    API = "api"
    TOOL = "tool"
    CODE = "code"
    CONFIG = "config"
    SUPPLY_CHAIN = "supply_chain"


class Boundary(StrEnum):
    """Trust boundaries from documentation/THREAT_MODEL.md."""

    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B4 = "B4"
    B5 = "B5"
    B6 = "B6"
    B7 = "B7"
    B8 = "B8"

    @property
    def description(self) -> str:
        return _BOUNDARY_DESCRIPTIONS[self]


_BOUNDARY_DESCRIPTIONS: dict[Boundary, str] = {
    Boundary.B1: "User → App",
    Boundary.B2: "App → LLM (prompt construction)",
    Boundary.B3: "External content → Context (RAG documents, tool results, web pages)",
    Boundary.B4: "LLM → Tools (tool calls)",
    Boundary.B5: "LLM output → Downstream sinks (UI, code, DB, shell)",
    Boundary.B6: "Agent ↔ Persistent memory",
    Boundary.B7: "Agent ↔ MCP servers and other agents",
    Boundary.B8: "App ↔ LLM provider and infrastructure (keys, limits, logs)",
}


class Capability(StrEnum):
    """What an agent's tools let it do. Drives severity and tool analysis.

    - reads_private_data: returns data about users, accounts, or the business
    - ingests_untrusted_content: returns content third parties control (web pages, emails)
    - external_communication: sends data to a destination chosen at call time (a URL or
      recipient the model picks), so injected instructions can send data to an attacker
    - code_execution: runs code or shell commands
    - file_write: writes files at a path chosen at call time
    - destructive: deletes or irreversibly changes things
    - financial: moves money
    - writes_memory: saves text the agent reads again in later conversations
    """

    READS_PRIVATE_DATA = "reads_private_data"
    INGESTS_UNTRUSTED_CONTENT = "ingests_untrusted_content"
    EXTERNAL_COMMUNICATION = "external_communication"
    CODE_EXECUTION = "code_execution"
    FILE_WRITE = "file_write"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    WRITES_MEMORY = "writes_memory"


class InputKind(StrEnum):
    """Inputs a check can use: the fields of ``AuditScope.inputs``, plus two that aren't
    files: a live target and the scope's attestations."""

    SOURCE_DIRS = "source_dirs"
    PROMPT_DIRS = "prompt_dirs"
    LOGS = "logs"
    TOOL_DEFS = "tool_defs"
    MCP_CONFIGS = "mcp_configs"
    HAR = "har"
    OPENAPI = "openapi"
    CONFIG_FILES = "config_files"
    DEPENDENCY_FILES = "dependency_files"
    MODEL_DIRS = "model_dirs"
    DOCUMENTS = "documents"
    TARGET = "target"
    ATTESTATIONS = "attestations"


class Exposure(StrEnum):
    INTERNET = "internet"
    INTERNAL = "internal"


class Autonomy(StrEnum):
    HUMAN_IN_LOOP = "human_in_loop"
    AUTONOMOUS = "autonomous"


class DataSensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
