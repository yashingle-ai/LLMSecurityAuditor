"""The demo site: audit the two demo apps from a browser and explore the results.

    uv run python -m demo.showcase      # then open http://127.0.0.1:8000

It audits only the demo apps' own scope files, so a request can't point it at other
paths. It answers only to localhost host names, which stops DNS rebinding. The page
never renders report text as HTML, because evidence quotes attack payloads on purpose.
"""

import json
import threading
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

import llm_auditor.detectors  # noqa: F401  (registers the built-in checks)
from llm_auditor.audit import run_audit
from llm_auditor.checks import registry
from llm_auditor.classifiers import Channel, build_classifier
from llm_auditor.detectors._text import line_at
from llm_auditor.detectors.pii import personal_data
from llm_auditor.detectors.secrets import secret_hits
from llm_auditor.extractors import extract_text
from llm_auditor.models import AuditReport, AuditScope, Finding, InjectionClassifierSettings
from llm_auditor.redaction import redact
from llm_auditor.reporting import FORMATS

REPO_ROOT = Path(__file__).parents[2]
STATIC = Path(__file__).parent / "static"
LOCAL_HOSTS = ("127.0.0.1", "localhost")
MAX_TEXT = 20_000  # characters a visitor can paste into the detector panel
EXCERPT = 600
# Locked down: no inline script, nothing from other origins. Images can't load either,
# so a link in a finding's evidence can't send data anywhere.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
DOWNLOADS = {
    "report.json": ("json", "application/json"),
    "report.md": ("md", "text/markdown; charset=utf-8"),
    "report.sarif": ("sarif", "application/sarif+json"),
}


class DemoApp(StrEnum):
    VULNERABLE = "vulnerable"
    HARDENED = "hardened"


@dataclass(frozen=True)
class AppInfo:
    name: str
    summary: str
    directory: Path
    scope: Path


APPS = {
    DemoApp.VULNERABLE: AppInfo(
        "Vulnerable app",
        "Acme's support agent with flaws planted on purpose, each one listed in its ground "
        "truth. The auditor should find every one.",
        REPO_ROOT / "demo" / "vulnerable_app",
        REPO_ROOT / "configs" / "audit_scope.example.yaml",
    ),
    DemoApp.HARDENED: AppInfo(
        "Hardened app",
        "The same agent with every planted flaw fixed. The auditor should report no "
        "vulnerabilities or weaknesses at all.",
        REPO_ROOT / "demo" / "hardened_app",
        REPO_ROOT / "configs" / "audit_scope.hardened.yaml",
    ),
}


class InspectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    channel: Channel = "content"
    format: Literal["text", "markdown"] = "text"


class Audits:
    """The latest report for each demo app. One audit of an app runs at a time."""

    def __init__(self) -> None:
        self._locks = {app: threading.Lock() for app in DemoApp}
        self._reports: dict[DemoApp, AuditReport] = {}

    def run(self, app: DemoApp) -> AuditReport:
        with self._locks[app]:
            report = run_audit(AuditScope.from_yaml(APPS[app].scope))
            self._reports[app] = report
            return report

    def latest(self, app: DemoApp) -> AuditReport | None:
        return self._reports.get(app)


def create_app(allowed_hosts: Sequence[str] = LOCAL_HOSTS) -> FastAPI:
    app = FastAPI(title="LLM Security Auditor demo", docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))
    audits = Audits()

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/apps")
    def apps() -> list[dict[str, str]]:
        return [
            {
                "id": app_id.value,
                "name": info.name,
                "summary": info.summary,
                "scope": info.scope.relative_to(REPO_ROOT).as_posix(),
            }
            for app_id, info in APPS.items()
        ]

    @app.post("/api/audit/{app_id}")
    def audit(app_id: DemoApp) -> dict[str, Any]:
        started = time.monotonic()
        report = audits.run(app_id)
        return {
            "app": app_id.value,
            "seconds": round(time.monotonic() - started, 1),
            "report": json.loads(FORMATS["json"][1](report)),
            "ground_truth": ground_truth(report, APPS[app_id].directory),
        }

    @app.get("/api/audit/{app_id}/{filename}")
    def download(app_id: DemoApp, filename: str) -> Response:
        if filename not in DOWNLOADS:
            raise HTTPException(404, "Downloads are report.json, report.md and report.sarif.")
        report = audits.latest(app_id)
        if report is None:
            raise HTTPException(404, "Run the audit first.")
        report_format, media_type = DOWNLOADS[filename]
        return Response(
            FORMATS[report_format][1](report),
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{app_id}-{filename}"'},
        )

    @app.get("/api/checks")
    def checks() -> list[dict[str, Any]]:
        return [meta.model_dump(mode="json") for meta in registry.list_checks()]

    @app.post("/api/inspect")
    def inspect(request: InspectRequest) -> dict[str, Any]:
        return inspect_text(request.text, request.channel, request.format)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def ground_truth(report: AuditReport, app_dir: Path) -> list[dict[str, Any]]:
    """Each enabled planted flaw, and the findings that match it (same check and location),
    as the ground-truth harness in tests/groundtruth/ matches them."""
    path = app_dir / "GROUND_TRUTH.yaml"
    if not path.exists():
        return []
    entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [
        {
            "id": entry["id"],
            "check": entry["check"],
            "description": " ".join(str(entry["description"]).split()),
            "findings": [f.id for f in report.findings if _matches(entry, f, app_dir)],
        }
        for entry in entries
        if entry.get("enabled")
    ]


def _matches(entry: dict[str, Any], finding: Finding, app_dir: Path) -> bool:
    location = str(entry["location"])
    if finding.check_id != entry["check"]:
        return False
    if location.startswith("attestation:"):
        return (finding.location.artifact or "").startswith(location)
    if finding.location.file is None:
        return False
    found = (REPO_ROOT / finding.location.file).resolve()
    expected = (app_dir / location).resolve()
    return found == expected or found.is_relative_to(expected)


def inspect_text(text: str, channel: Channel, text_format: str) -> dict[str, Any]:
    """What the detectors make of one piece of text: injection, hidden content, and
    sensitive data. Hidden parts are always third-party content: nobody types them."""
    classifier = build_classifier(InjectionClassifierSettings())
    extraction = extract_text(text, "markdown" if text_format == "markdown" else "text")
    visible = extraction.text.strip() or text
    parts: list[tuple[str, Channel, str]] = [("Visible text", channel, visible)]
    parts += [(f"Hidden: {hidden.how}", "content", hidden.text) for hidden in extraction.hidden]
    scored: list[dict[str, Any]] = []
    for label, part_channel, part in parts:
        verdict = classifier.classify(part, part_channel)
        scored.append(
            {
                "part": label,
                "channel": part_channel,
                "text": _excerpt(redact(part)),  # scored as pasted, shown redacted
                "score": verdict.score,
                "signals": list(verdict.signals),
                "flagged": verdict.score >= classifier.threshold,
            }
        )
    sensitive = [
        {"type": match.title, "line": _excerpt(redact(line_at(text, match.start).strip()))}
        for match in personal_data(text)
    ]
    sensitive += [{"type": hit.title, "line": _excerpt(hit.evidence)} for hit in secret_hits(text)]
    return {
        "classifier": classifier.name,
        "threshold": classifier.threshold,
        "parts": scored,
        "worst": max(scored, key=lambda part: part["score"]),
        "sensitive": sensitive,
    }


def _excerpt(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= EXCERPT else flat[: EXCERPT - 1] + "…"
