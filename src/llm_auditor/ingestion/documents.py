"""Documents an LLM app retrieves or ingests: what a reader sees, and what's hidden."""

import zipfile
from pathlib import Path

from pypdf.errors import PdfReadError

from llm_auditor.extractors import extract
from llm_auditor.ingestion.base import MAX_FILE_BYTES, Artifact, IngestReport
from llm_auditor.models import Document, DocumentFormat

FORMATS: dict[str, DocumentFormat] = {
    ".html": "html",
    ".htm": "html",
    ".md": "markdown",
    ".markdown": "markdown",
    ".txt": "text",
    ".pdf": "pdf",
    ".docx": "docx",
}


class DocumentLoader:
    extensions = frozenset(FORMATS)

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        document_format = FORMATS.get(file.suffix.lower())
        if document_format is None:
            report.warn(rel, "skipped: not a supported document (HTML, Markdown, text, PDF, DOCX)")
            return []
        try:
            if file.stat().st_size > MAX_FILE_BYTES:
                report.warn(rel, f"skipped: larger than {MAX_FILE_BYTES // 2**20} MiB")
                return []
            extraction = extract(file.read_bytes(), document_format)
        except OSError as error:
            report.warn(rel, f"skipped: {error.strerror or error}")
            return []
        except (ValueError, PdfReadError, zipfile.BadZipFile) as error:
            report.warn(rel, f"skipped: could not read the {document_format}: {error}")
            return []
        return [
            Document(
                path=rel,
                format=document_format,
                text=extraction.text,
                hidden=tuple(extraction.hidden),
            )
        ]
