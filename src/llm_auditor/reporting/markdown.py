"""Markdown report: for people. Summary first, then findings, then what wasn't covered."""

import re

from llm_auditor.models import AuditReport, Finding, FindingKind, IncidentOutcome, Severity

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def to_markdown(report: AuditReport) -> str:
    sections = [
        _header(report),
        _summary(report),
        _findings(report, (FindingKind.VULNERABILITY, FindingKind.WEAKNESS), "Findings"),
        _findings(report, (FindingKind.HARDENING,), "Hardening recommendations"),
        _incidents(report),
        _inventory(report),
        _coverage(report),
    ]
    return "\n\n".join(section for section in sections if section) + "\n"


def _header(report: AuditReport) -> str:
    run = report.run
    profile = report.capability_profile
    capabilities = ", ".join(sorted(profile.capabilities)) or "none"
    return "\n".join(
        [
            f"# LLM Security Audit: {_inline(run.scope_name)}",
            "",
            f"- **Date:** {run.finished_at:%Y-%m-%d %H:%M} UTC",
            f"- **Access:** {run.access}-box",
            f"- **Target profile:** {profile.exposure}, {profile.autonomy.replace('_', ' ')}, "
            f"{profile.data_sensitivity}-sensitivity data, "
            f"{'multi' if profile.multi_tenant else 'single'}-tenant; capabilities: {capabilities}",
            f"- **Tool:** {run.tool} {run.tool_version}, severity rubric v{run.rubric_version}",
        ]
    )


def _summary(report: AuditReport) -> str:
    counts = report.severity_counts
    total = sum(counts.values())
    rows = [f"| {severity.title()} | {counts[severity]} |" for severity in reversed(Severity)]
    lines = ["## Summary", ""]
    if total:
        worst = next(s for s in reversed(Severity) if counts[s])
        lines.append(f"**{total} finding{'s' if total != 1 else ''}**, the most severe {worst}.")
    else:
        lines.append("**No vulnerabilities or weaknesses found** by the checks that ran.")
    incidents = sum(counts.attempts for counts in report.incident_summary.values())
    succeeded = sum(counts.succeeded for counts in report.incident_summary.values())
    hardening = sum(f.kind is FindingKind.HARDENING for f in report.findings)
    if hardening:
        lines.append(f"{hardening} hardening recommendation(s).")
    if incidents:
        lines.append(
            f"{incidents} attack attempt(s) seen in logs, {succeeded} of them successful "
            "(see Incidents)."
        )
    if report.coverage.skipped or report.coverage.failed:
        lines.append(
            f"{len(report.coverage.skipped)} check(s) skipped and {len(report.coverage.failed)} "
            "failed: see Coverage and Limitations before relying on this report."
        )
    return "\n".join([*lines, "", "| Severity | Findings |", "|---|---|", *rows])


def _findings(report: AuditReport, kinds: tuple[FindingKind, ...], title: str) -> str:
    findings = [f for f in report.findings if f.kind in kinds]
    if not findings:
        return ""
    return "\n\n".join([f"## {title}", *(_finding(report, f) for f in findings)])


def _finding(report: AuditReport, finding: Finding) -> str:
    meta = report.check(finding.check_id)
    label = finding.severity.title() if finding.severity else finding.kind.title()
    lines = [
        f"### {finding.id} · {label} · {_inline(finding.title)}",
        "",
        f"- **Check:** {finding.check_id} {_inline(meta.title) if meta else ''}",
        f"- **Where:** {_location(finding)}",
        f"- **Kind:** {finding.kind} · **Confidence:** {finding.confidence:.0%} "
        f"· **Established by:** {finding.oracle.replace('_', ' ')}",
    ]
    if finding.severity_score is not None:
        factors = ", ".join(finding.severity_factors)
        lines.append(f"- **Severity:** {finding.severity_score}/10 ({factors})")
    if meta and meta.maps_to:
        lines.append(f"- **Maps to:** {', '.join(meta.maps_to)}")
    if finding.related:
        lines.append(f"- **Related:** {', '.join(finding.related)}")
    return "\n".join(
        [
            *lines,
            "",
            "**Evidence**",
            "",
            _fenced(finding.evidence),
            "",
            f"**Fix:** {finding.remediation}",
        ]
    )


def _incidents(report: AuditReport) -> str:
    if not report.incident_summary:
        return ""
    rows = []
    for check_id, counts in report.incident_summary.items():
        meta = report.check(check_id)
        rows.append(
            f"| {check_id} | {_inline(meta.title) if meta else ''} | {counts.attempts} "
            f"| {counts.succeeded} | {counts.failed} | {counts.unknown} |"
        )
    succeeded = [
        f"- {f.id} ({f.check_id}) {_inline(f.title)}, at {_location(f)}"
        + (f"; evidence for {', '.join(f.related)}" if f.related else "")
        for f in report.findings
        if f.kind is FindingKind.INCIDENT and f.outcome is IncidentOutcome.SUCCEEDED
    ]
    return "\n".join(
        [
            "## Incidents",
            "",
            "Attack attempts seen in logs. They are not findings on their own: a successful one "
            "is evidence for the finding it exploited, which is then reported as a vulnerability.",
            "",
            "| Check | Title | Attempts | Succeeded | Failed | Unknown |",
            "|---|---|---|---|---|---|",
            *rows,
            *(["", "**Attacks that succeeded:**", "", *succeeded] if succeeded else []),
        ]
    )


def _inventory(report: AuditReport) -> str:
    if not report.tool_inventory:
        return ""
    rows = []
    for tool in report.tool_inventory:
        capabilities = ", ".join(tool.capabilities) or "-"
        reasons = _inline("; ".join(tool.reasons.values())) or "-"
        name, source = _inline(tool_name(tool.name)), _inline(tool.source)
        rows.append(f"| {name} | {source} | {capabilities} | {reasons} |")
    return "\n".join(
        [
            "## Tool Inventory",
            "",
            "Every tool the agent can call, and what the auditor inferred it lets the agent do. "
            "Correct a tool with `capability_overrides` in the scope file.",
            "",
            "| Tool | Source | Capabilities | Why |",
            "|---|---|---|---|",
            *rows,
        ]
    )


def tool_name(name: str) -> str:
    """A tool name, with an ASCII-escaped copy when it contains other characters."""
    escaped = name.encode("ascii", "backslashreplace").decode()
    return name if escaped == name else f"{name} ({escaped})"


def _coverage(report: AuditReport) -> str:
    coverage = report.coverage
    lines = ["## Coverage and Limitations", ""]
    lines += [f"> **Note:** {_inline(note)}" for note in coverage.notes]
    if coverage.notes:
        lines.append("")
    lines.append(f"**Checks run ({len(coverage.ran)}):** {', '.join(coverage.ran) or 'none'}")
    if coverage.skipped:
        lines += ["", "**Checks skipped**", "", "| Check | Reason |", "|---|---|"]
        lines += [f"| {s.check_id} | {_inline(s.reason)} |" for s in coverage.skipped]
    if coverage.failed:
        lines += ["", "**Checks that failed** (their part of the audit is missing)", ""]
        lines += [f"- {f.check_id}: {_inline(f.error)}" for f in coverage.failed]
    lines += ["", "**Inputs**", "", "| Input | Entry | Files | Artifacts |", "|---|---|---|---|"]
    lines += [
        f"| {i.kind} | {_inline(i.entry)} | {i.files} | {i.artifacts} |" for i in coverage.inputs
    ]
    if coverage.ingest_issues:
        lines += ["", "**Input problems** (these parts were skipped)", ""]
        lines += [
            f"- {_inline(i.path)}{f':{i.line}' if i.line else ''}: {_inline(i.message)}"
            for i in coverage.ingest_issues
        ]
    return "\n".join(lines)


def _location(finding: Finding) -> str:
    location = finding.location
    where = location.file or location.artifact or "?"
    return _code(f"{where}:{location.line}" if location.line else where)


def _inline(text: str) -> str:
    """Audited text on one line, with Markdown table and emphasis characters neutralized."""
    cleaned = _CONTROL.sub(" ", text).replace("\n", " ")
    return re.sub(r"([\\`*_|<>\[\]])", r"\\\1", cleaned)


def _code(text: str) -> str:
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{_CONTROL.sub(' ', text)}{pad}{fence}"


def _fenced(text: str) -> str:
    """A code block that the evidence can't break out of, however many backticks it holds."""
    fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return f"{fence}text\n{_CONTROL.sub(' ', text)}\n{fence}"
