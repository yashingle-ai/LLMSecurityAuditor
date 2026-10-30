"""Prompt files and templates."""

import re
from pathlib import Path
from typing import Literal

from llm_auditor.ingestion.base import Artifact, IngestReport, read_text
from llm_auditor.models import PromptArtifact

PromptFormat = Literal["text", "markdown", "jinja"]

_FORMATS: dict[str, PromptFormat] = {
    ".txt": "text",
    ".prompt": "text",
    ".md": "markdown",
    ".jinja": "jinja",
    ".jinja2": "jinja",
    ".j2": "jinja",
}
_JINJA_VARIABLE = re.compile(r"\{\{\s*([A-Za-z_]\w*)")  # {{ name }} and {{ name.attr }}
_FORMAT_VARIABLE = re.compile(r"(?<!\{)\{([A-Za-z_]\w*)(?:![rsa])?(?::[^{}]*)?\}(?!\})")  # {name}


class PromptLoader:
    extensions = frozenset(_FORMATS)

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        text = read_text(file, rel, report)
        if text is None:
            return []
        variables = set(_JINJA_VARIABLE.findall(text)) | set(_FORMAT_VARIABLE.findall(text))
        return [
            PromptArtifact(
                path=rel,
                format=_FORMATS.get(file.suffix.lower(), "text"),
                text=text,
                variables=tuple(sorted(variables)),
            )
        ]
