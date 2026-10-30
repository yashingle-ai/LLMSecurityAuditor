"""O-06: insecure code in the model's responses.

Fenced code blocks in assistant replies are written to a temporary directory and
scanned with the Semgrep rules in ``rules/semgrep_generated/``, in one run per audit.
"""

import json
import re
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from llm_auditor.checks import CheckUnavailable, Detection, register
from llm_auditor.detectors._trace import log_location
from llm_auditor.detectors.code import INSTALL_HINT, SEMGREP_TIMEOUT, semgrep_binary
from llm_auditor.detectors.outputs import replies
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    CheckMeta,
    FindingKind,
    InputKind,
    Location,
    Surface,
)
from llm_auditor.rules import GENERATED_CODE_RULES_DIR

FENCE = re.compile(r"```[ \t]*([\w+#.-]*)[^\n]*\n(.*?)```", re.DOTALL)
EXTENSIONS = {
    "python": ".py",
    "py": ".py",
    "python3": ".py",
    "javascript": ".js",
    "js": ".js",
    "node": ".js",
    "jsx": ".js",
    "typescript": ".ts",
    "ts": ".ts",
}


def code_blocks(text: str) -> list[tuple[str, str]]:
    """(file extension, code) for each fenced block in a language the rules cover."""
    return [
        (EXTENSIONS[language.lower()], code)
        for language, code in FENCE.findall(text)
        if language.lower() in EXTENSIONS
    ]


@dataclass
class _Sighting:
    location: Location
    title: str
    evidence: str
    runs: set[str] = field(default_factory=set)


@register
class InsecureGeneratedCode:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="O-06",
        title="Insecure code in model responses",
        surface=Surface.OUTPUT,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.LOGS,),
        boundaries=(Boundary.B5,),
        maps_to=("LLM05", "LLM09"),
        base_impact=4,
        remediation=(
            "Review model-written code before running it, and steer the model with secure "
            "defaults in the system prompt (parameterized SQL, no shell=True, safe loaders). "
            "Never run generated code automatically outside a sandbox."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        blocks = [
            (interaction, extension, code)
            for interaction in context.artifacts.interactions
            for reply in replies(interaction)
            for extension, code in code_blocks(reply)
        ]
        if not blocks:
            return
        binary = semgrep_binary()
        if binary is None:
            raise CheckUnavailable(f"semgrep is not installed; {INSTALL_HINT}")
        sightings: dict[tuple[str | None, str], _Sighting] = {}
        with tempfile.TemporaryDirectory(prefix="llmaudit-o06-") as directory:
            names = []
            for number, (_, extension, code) in enumerate(blocks):
                name = f"block_{number:05d}{extension}"
                (Path(directory) / name).write_text(code, encoding="utf-8")
                names.append(name)
            for name, rule_title, line in _scan(binary, Path(directory), names):
                interaction, _, code = blocks[names.index(name)]
                location = log_location(interaction)
                sighting = sightings.setdefault(
                    (location.file, rule_title),
                    _Sighting(location, rule_title, code.splitlines()[line - 1].strip()[:300]),
                )
                sighting.runs.add(interaction.id)
        for sighting in sightings.values():
            count = len(sighting.runs)
            yield Detection(
                title=f"{sighting.title}, in code the model wrote ({count} "
                f"run{'s' if count != 1 else ''})",
                location=sighting.location,
                evidence=sighting.evidence,
                confidence=0.75,
            )


def _scan(binary: str, directory: Path, names: list[str]) -> Iterator[tuple[str, str, int]]:
    """(file name, rule title, line) for each Semgrep match."""
    command = [
        binary,
        "scan",
        "--config",
        str(GENERATED_CODE_RULES_DIR),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--quiet",
        *names,
    ]
    try:
        completed = subprocess.run(  # noqa: S603  (fixed arguments plus our own file names)
            command,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT,
            check=False,
        )
        output = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise CheckUnavailable(f"semgrep could not scan the generated code: {error}") from error
    for result in output.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})
        title = str(metadata.get("title") or result.get("check_id", "insecure code"))
        yield Path(str(result["path"])).name, title, int(result["start"]["line"])
