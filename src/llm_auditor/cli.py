"""Command-line entry point: ``llmaudit``."""

from pathlib import Path
from typing import Annotated

import httpx
import typer
import yaml
from rich.console import Console
from rich.table import Table
from rich.text import Text

import llm_auditor.detectors  # noqa: F401  (registers the built-in checks)
from llm_auditor import __version__
from llm_auditor.advisories import fetch_db, write_db
from llm_auditor.audit import run_audit
from llm_auditor.checks import registry
from llm_auditor.ingestion import ingest
from llm_auditor.inventory import tool_inventory
from llm_auditor.models import Access, AuditScope, CapabilityProfile, ScopeInputs, Severity
from llm_auditor.render import (
    artifact_tables,
    coverage_line,
    findings_table,
    inputs_table,
    inventory_table,
    issue_lines,
)
from llm_auditor.reporting import FORMATS, write_reports
from llm_auditor.tool_lock import lock_tools, write_lock

app = typer.Typer(
    name="llmaudit",
    help="Audit LLM applications for security vulnerabilities.",
    no_args_is_help=True,
)
checks_app = typer.Typer(help="Inspect the catalog of security checks.", no_args_is_help=True)
app.add_typer(checks_app, name="checks")
scan_app = typer.Typer(
    help="Run an audit and write reports. Use --scope, or a quick-scan subcommand.",
    invoke_without_command=True,
)
app.add_typer(scan_app, name="scan")
tools_app = typer.Typer(
    help="Inspect and approve the tools an agent can call.", no_args_is_help=True
)
app.add_typer(tools_app, name="tools")
advisories_app = typer.Typer(
    help="Manage the known-vulnerability snapshot that check SC-02 uses.", no_args_is_help=True
)
app.add_typer(advisories_app, name="advisories")
console = Console()
err_console = Console(stderr=True)


@app.callback()
def main() -> None:
    """Audit prompts, outputs, tool calls, and API interactions of LLM applications."""


@app.command()
def version() -> None:
    """Print the installed version."""
    console.print(f"llmaudit {__version__}")


@checks_app.command("list")
def list_checks() -> None:
    """List every registered check."""
    table = Table(title="Registered checks")
    for column in ("ID", "Title", "Surface", "Kind", "Access", "Boundaries", "Maps to"):
        table.add_column(column)
    checks = registry.list_checks()
    for meta in checks:
        table.add_row(
            meta.id,
            meta.title,
            meta.surface,
            meta.kind,
            meta.min_access,
            ", ".join(meta.boundaries),
            ", ".join(meta.maps_to) or "-",
        )
    if not checks:
        table.caption = "No checks registered yet."
    console.print(table)


@app.command("ingest")
def ingest_command(
    scope: Annotated[
        Path,
        typer.Option(help="Audit scope file (YAML).", exists=True, dir_okay=False, readable=True),
    ],
    dump: Annotated[bool, typer.Option("--dump", help="List every loaded artifact.")] = False,
) -> None:
    """Load a scope's inputs and summarize what was found."""
    context = ingest(_load_scope(scope))
    console.print(inputs_table(context))
    if dump:
        for table in artifact_tables(context.artifacts):
            console.print(table)
    if context.issues:
        console.print(Text(f"{len(context.issues)} issue(s) while loading:", style="yellow"))
        for line in issue_lines(context.issues):
            console.print(line)


def _load_scope(path: Path) -> AuditScope:
    try:
        return AuditScope.from_yaml(path)
    except (ValueError, yaml.YAMLError) as error:  # pydantic's ValidationError is a ValueError
        err_console.print(Text(f"Invalid scope file {path}:", style="red"))
        err_console.print(Text(str(error)))
        raise typer.Exit(code=1) from error


FormatsOption = Annotated[
    str, typer.Option("--format", help="Comma-separated report formats: json, md, sarif.")
]
OutOption = Annotated[Path, typer.Option("--out", help="Directory to write reports to.")]
FailOnOption = Annotated[
    Severity | None,
    typer.Option("--fail-on", help="Exit with status 1 if a finding is at least this severe."),
]
QUICK_SCAN_NOTE = (
    "Quick scan without a scope file: no capability profile was given, so each severity is "
    "the check's base impact only. Use `llmaudit scan --scope` for context-aware severity."
)


@scan_app.callback()
def scan(
    context: typer.Context,
    scope: Annotated[
        Path | None,
        typer.Option(help="Audit scope file (YAML).", exists=True, dir_okay=False, readable=True),
    ] = None,
    formats: FormatsOption = "json,md,sarif",
    out: OutOption = Path("reports"),
    fail_on: FailOnOption = None,
) -> None:
    """Audit everything a scope file lists."""
    if context.invoked_subcommand is not None:
        return
    if scope is None:
        raise typer.BadParameter(
            "give a scope file, or use a quick scan such as `llmaudit scan prompts DIR`",
            param_hint="--scope",
        )
    _scan(_load_scope(scope), formats, out, fail_on)


@scan_app.command("prompts")
def scan_prompts(
    path: Annotated[
        Path, typer.Argument(help="A prompt file or a directory of them.", exists=True)
    ],
    formats: FormatsOption = "json,md,sarif",
    out: OutOption = Path("reports"),
    fail_on: FailOnOption = None,
) -> None:
    """Quick scan of prompt files, without a scope file."""
    scope = AuditScope(
        name=f"prompts in {path}",
        access=Access.WHITE,
        capability_profile=CapabilityProfile.neutral(),
        root=Path.cwd(),
        inputs=ScopeInputs(prompt_dirs=[str(path)]),
    )
    _scan(scope, formats, out, fail_on, notes=(QUICK_SCAN_NOTE,))


def _scan(
    scope: AuditScope,
    formats: str,
    out: Path,
    fail_on: Severity | None,
    notes: tuple[str, ...] = (),
) -> None:
    chosen = _formats(formats)
    report = run_audit(scope, notes=notes)
    console.print(findings_table(report))
    console.print(coverage_line(report))
    for path in write_reports(report, out, chosen):
        console.print(Text(f"Wrote {path}"))
    if fail_on is not None and any(
        f.severity is not None and f.severity.rank >= fail_on.rank for f in report.findings
    ):
        raise typer.Exit(code=1)


def _formats(value: str) -> list[str]:
    chosen = [part.strip() for part in value.split(",") if part.strip()]
    unknown = [name for name in chosen if name not in FORMATS]
    if unknown or not chosen:
        raise typer.BadParameter(
            f"unknown format {', '.join(unknown) or '(none)'}; choose from {', '.join(FORMATS)}",
            param_hint="--format",
        )
    return chosen


ScopeOption = Annotated[
    Path,
    typer.Option(
        "--scope", help="Audit scope file (YAML).", exists=True, dir_okay=False, readable=True
    ),
]


@tools_app.command("inventory")
def tools_inventory_command(scope: ScopeOption) -> None:
    """Show every tool the agent can call, and what each one lets it do."""
    context = ingest(_load_scope(scope))
    console.print(inventory_table([tool.profile for tool in tool_inventory(context)]))


@tools_app.command("lock")
def tools_lock_command(scope: ScopeOption) -> None:
    """Approve the current tool definitions. Later scans report any change (check T-12)."""
    audit_scope = _load_scope(scope)
    lock = lock_tools(ingest(audit_scope).artifacts.tool_definitions)
    path = audit_scope.root / audit_scope.tool_lock
    write_lock(lock, path)
    console.print(Text(f"Approved {len(lock.tools)} tool definition(s): wrote {path}"))


def _osv_client() -> httpx.Client:
    return httpx.Client(timeout=30.0)


@advisories_app.command("update")
def advisories_update_command(
    out: Annotated[
        Path, typer.Option("--out", help="Where to write it. Point a scope's advisory_db here.")
    ] = Path(".llmaudit/advisories.json"),
) -> None:
    """Fetch current advisories for the watched LLM frameworks from OSV (needs network)."""
    try:
        with _osv_client() as client:
            db = fetch_db(client)
    except httpx.HTTPError as error:
        err_console.print(Text(f"Could not fetch advisories from OSV: {error}"))
        raise typer.Exit(1) from error
    write_db(db, out)
    count, packages = len(db.advisories), sum(len(names) for names in db.watched.values())
    noun = "advisory" if count == 1 else "advisories"
    console.print(Text(f"Wrote {count} {noun} for {packages} packages to {out}"))
