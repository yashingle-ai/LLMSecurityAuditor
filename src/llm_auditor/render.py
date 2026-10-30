"""Terminal rendering. Audited content is always redacted and sanitized before display."""

import re
from collections.abc import Iterable, Sequence

from rich.console import RenderableType
from rich.table import Table
from rich.text import Text

from llm_auditor.ingestion import Artifacts, AuditContext
from llm_auditor.models import AuditReport, FindingKind, IngestIssue, Role, Severity, ToolProfile
from llm_auditor.redaction import redact
from llm_auditor.reporting.markdown import tool_name

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def safe(value: object, limit: int = 60) -> Text:
    """Audited content made safe to print: redacted, on one line, no markup or control codes."""
    text = _CONTROL.sub(" ", redact(str(value)))
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return Text(text)


def inputs_table(context: AuditContext) -> Table:
    table = _table(
        Text("Inputs for ") + safe(context.scope.name),
        ("Input", "Entry", "Files", "Artifacts"),
        [(s.kind.value, safe(s.entry), str(s.files), str(s.artifacts)) for s in context.inputs],
    )
    if not context.inputs:
        table.caption = "The scope lists no inputs."
    return table


def artifact_tables(artifacts: Artifacts) -> list[Table]:
    """One table per artifact type that has any artifacts."""
    candidates = [
        _table(
            "Prompts",
            ("Path", "Format", "Variables", "Lines"),
            [
                (
                    safe(p.path),
                    p.format,
                    safe(", ".join(p.variables) or "-"),
                    str(len(p.text.splitlines())),
                )
                for p in artifacts.prompts
            ],
        ),
        _table(
            "Source files",
            ("Path", "Language", "Bytes"),
            [(safe(f.path), f.language, str(f.size_bytes)) for f in artifacts.source_files],
        ),
        _table(
            "Interactions",
            ("Source", "User", "Messages", "Tool calls", "First user message"),
            [
                (
                    safe(i.source),
                    safe(i.user or "-"),
                    str(len(i.messages)),
                    str(len(i.tool_calls)),
                    safe(next((m.content for m in i.messages if m.role is Role.USER), "-"), 50),
                )
                for i in artifacts.interactions
            ],
        ),
        _table(
            "Tool definitions",
            ("Name", "Source", "Parameters"),
            [
                (
                    safe(t.name),
                    safe(t.source or "-"),
                    safe(", ".join(_properties(t.parameters)) or "-"),
                )
                for t in artifacts.tool_definitions
            ],
        ),
        _table(
            "MCP servers",
            ("Name", "Transport", "Command or URL", "Source"),
            [
                (
                    safe(s.name),
                    s.transport,
                    safe(s.url or " ".join([s.command or "", *s.args])),
                    safe(s.source),
                )
                for s in artifacts.mcp_servers
            ],
        ),
        _table(
            "HAR entries",
            ("Source", "Method", "URL", "Status"),
            [
                (safe(e.source), safe(e.method), safe(e.url), str(e.status))
                for e in artifacts.har_entries
            ],
        ),
        _table(
            "API specs",
            ("Path", "Title", "Operations", "Security schemes"),
            [
                (
                    safe(a.path),
                    safe(a.title or "-"),
                    str(len(a.operations)),
                    safe(", ".join(a.security_schemes) or "-"),
                )
                for a in artifacts.api_specs
            ],
        ),
        _table(
            "Config files",
            ("Path", "Format", "Top-level keys"),
            [
                (
                    safe(c.path),
                    c.format,
                    safe(
                        ", ".join(map(str, c.data))
                        if isinstance(c.data, dict)
                        else type(c.data).__name__
                    ),
                )
                for c in artifacts.config_files
            ],
        ),
    ]
    return [table for table in candidates if table.row_count]


def issue_lines(issues: Sequence[IngestIssue]) -> list[Text]:
    lines = []
    for issue in issues:
        where = f"{issue.path}:{issue.line}" if issue.line else issue.path
        lines.append(Text("  ") + safe(f"{where}: {issue.message}", limit=200))
    return lines


def _table(
    title: str | Text, columns: Iterable[str], rows: Iterable[Iterable[RenderableType]]
) -> Table:
    table = Table(title=title, title_justify="left")
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*row)
    if isinstance(title, str):
        table.title = f"{title} ({table.row_count})"
    return table


def _properties(schema: dict[str, object]) -> list[str]:
    properties = schema.get("properties")
    return [str(name) for name in properties] if isinstance(properties, dict) else []


_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def findings_table(report: AuditReport) -> Table:
    """Vulnerabilities, weaknesses, and hardening advice; incidents are only counted."""
    shown = [f for f in report.findings if f.kind is not FindingKind.INCIDENT]
    table = _table(
        Text("Findings for ") + safe(report.run.scope_name),
        ("ID", "Severity", "Check", "Title", "Location"),
        [
            (
                f.id,
                Text(
                    f.severity or f.kind,
                    style=_SEVERITY_STYLES.get(f.severity, "") if f.severity else "dim",
                ),
                f.check_id,
                safe(f.title, limit=70),
                safe(
                    f"{f.location.file or f.location.artifact}"
                    + (f":{f.location.line}" if f.location.line else "")
                ),
            )
            for f in shown
        ],
    )
    if not shown:
        table.caption = "No vulnerabilities, weaknesses, or hardening advice."
    return table


def coverage_line(report: AuditReport) -> Text:
    coverage = report.coverage
    counts = report.severity_counts
    worst = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no findings"
    summary = report.incident_summary.values()
    incidents = sum(counts.attempts for counts in summary)
    succeeded = sum(counts.succeeded for counts in summary)
    line = Text(
        f"{worst}; {incidents} incident(s), {succeeded} succeeded. "
        f"Ran {len(coverage.ran)} check(s), "
        f"skipped {len(coverage.skipped)}, failed {len(coverage.failed)}."
    )
    if coverage.failed:
        line.stylize("yellow")
    return line


def inventory_table(tools: Sequence[ToolProfile]) -> Table:
    table = _table(
        "Tool inventory",
        ("Tool", "Source", "Capabilities", "Why"),
        [
            (
                safe(tool_name(t.name)),
                safe(t.source),
                ", ".join(t.capabilities) or "-",
                safe("; ".join(t.reasons.values()) or "-", limit=90),
            )
            for t in tools
        ],
    )
    if not tools:
        table.caption = "No tool definitions were loaded."
    return table
