"""Application source files. Only discovered here; Stage 5 scans their contents."""

from pathlib import Path

from llm_auditor.ingestion.base import Artifact, IngestReport
from llm_auditor.models import SourceFile

LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
}


class SourceLoader:
    extensions = frozenset(LANGUAGES)

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        language = LANGUAGES.get(file.suffix.lower())
        if language is None:
            report.warn(rel, "skipped: not a recognized source file")
            return []
        try:
            size = file.stat().st_size
        except OSError as error:
            report.warn(rel, f"skipped: {error.strerror or error}")
            return []
        return [SourceFile(path=rel, language=language, size_bytes=size)]
