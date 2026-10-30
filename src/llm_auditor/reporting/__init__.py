"""Report formats. JSON is canonical; the others are rendered from the same AuditReport."""

import json
from collections.abc import Callable, Iterable
from pathlib import Path

from llm_auditor.models import AuditReport
from llm_auditor.reporting.markdown import to_markdown
from llm_auditor.reporting.sarif import to_sarif


def to_json(report: AuditReport) -> str:
    return report.model_dump_json(indent=2) + "\n"


def to_sarif_json(report: AuditReport) -> str:
    return json.dumps(to_sarif(report), indent=2) + "\n"


FORMATS: dict[str, tuple[str, Callable[[AuditReport], str]]] = {
    "json": ("report.json", to_json),
    "md": ("report.md", to_markdown),
    "sarif": ("report.sarif", to_sarif_json),
}


def write_reports(report: AuditReport, out_dir: Path, formats: Iterable[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name in formats:
        filename, render = FORMATS[name]
        path = out_dir / filename
        path.write_text(render(report), encoding="utf-8")
        written.append(path)
    return written


__all__ = ["FORMATS", "to_json", "to_markdown", "to_sarif", "write_reports"]
