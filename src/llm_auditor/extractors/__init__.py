"""Extract what a reader sees, and what's hidden from them, from documents an LLM reads.

Hidden text is the delivery mechanism for indirect prompt injection: an instruction
a person reviewing the page never sees, but a model reading it does.
"""

from llm_auditor.extractors.docx import extract_docx
from llm_auditor.extractors.html import Extraction, extract_html, extract_markdown, looks_like_html
from llm_auditor.extractors.pdf import extract_pdf
from llm_auditor.models import DocumentFormat, HiddenText

_TAGS = range(0xE0000, 0xE0080)

__all__ = ["Extraction", "extract", "extract_text", "looks_like_html", "smuggled"]


def extract(data: bytes, document_format: DocumentFormat) -> Extraction:
    if document_format == "pdf":
        return extract_pdf(data)
    if document_format == "docx":
        return extract_docx(data)
    return extract_text(data.decode("utf-8", errors="replace"), document_format)


def extract_text(text: str, document_format: DocumentFormat = "text") -> Extraction:
    """Text formats, and text that may be HTML (a fetched page in a tool result)."""
    if document_format == "html" or (document_format == "text" and looks_like_html(text)):
        extraction = extract_html(text)
    elif document_format == "markdown":
        extraction = extract_markdown(text)
    else:
        extraction = Extraction(text=text)
    hidden_unicode = smuggled(text)
    if hidden_unicode:
        extraction.hidden.append(HiddenText(how="Unicode tag characters", text=hidden_unicode))
    return extraction


def smuggled(text: str) -> str:
    """Text written in invisible Unicode tag characters ("ASCII smuggling"), decoded."""
    decoded = "".join(chr(ord(c) - 0xE0000) for c in text if ord(c) in _TAGS)
    return "".join(c for c in decoded if c.isprintable())
