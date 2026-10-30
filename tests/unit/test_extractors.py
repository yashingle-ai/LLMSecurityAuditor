import io
import zipfile

import pytest

from llm_auditor.extractors import Extraction, extract, extract_text, looks_like_html, smuggled
from llm_auditor.extractors.html import extract_html, extract_markdown, hiding_style

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def hidden(extraction: Extraction) -> dict[str, str]:
    return {h.how: h.text for h in extraction.hidden}


# HTML


def test_html_separates_visible_and_hidden_text() -> None:
    page = extract_html(
        "<html><head><title>Sale</title><style>.promo { font-size: 0 }</style>"
        '<meta name="description" content="Spring sale page"></head><body>'
        "<h1>Spring sale</h1><p>Everything is 20% off.</p>"
        '<div style="display: none">hidden by style</div>'
        '<p class="promo">hidden by class rule</p>'
        '<span class="sr-only">screen reader only</span>'
        "<p hidden>hidden attribute</p>"
        "<!-- a comment -->"
        '<img src="x.png" alt="alt text here">'
        '<input type="hidden" name="t" value="hidden input value">'
        "<script>var notText = 1;</script>"
        "</body></html>"
    )

    assert page.text == "Spring sale\nEverything is 20% off."
    assert hidden(page) == {
        "meta tag": "Spring sale page",
        "display:none": "hidden by style",
        "zero or tiny font size (class .promo)": "hidden by class rule",
        "screen-reader-only text": "screen reader only",
        "hidden attribute": "hidden attribute",
        "HTML comment": "a comment",
        "alt text": "alt text here",
        "hidden input": "hidden input value",
    }


@pytest.mark.parametrize(
    ("style", "how"),
    [
        ("visibility: hidden", "visibility:hidden"),
        ("opacity:0", "opacity:0"),
        ("font-size: 1px", "zero or tiny font size"),
        ("color: rgba(0, 0, 0, 0)", "transparent text"),
        ("color: #ffffff", "white text"),
        ("color: white; background-color: #fff", "white text"),
        ("position: absolute; left: -9999px", "positioned off-screen"),
        ("text-indent: -9999px", "indented off-screen"),
        ("height: 0; overflow: hidden", "zero-size box"),
        ("transform: scale(0)", "clipped to nothing"),
        ("display: none !important", "display:none"),
    ],
)
def test_hiding_styles(style: str, how: str) -> None:
    assert hiding_style(style) == how


@pytest.mark.parametrize(
    "style",
    ["color: #333", "color: white; background: #000", "font-size: 14px", "opacity: 0.8", ""],
)
def test_visible_styles(style: str) -> None:
    assert hiding_style(style) is None


def test_conditional_comments_are_not_reported() -> None:
    page = extract_html("<p>Hi</p><!--[if IE]><p>Old browser</p><![endif]-->")

    assert page.hidden == []


def test_markdown_comments_and_inline_html() -> None:
    page = extract_markdown(
        "# Returns\n\nReturn items within 30 days.\n\n"
        "[//]: # (markdown comment text)\n"
        "<!-- html comment text -->\n"
        '<span style="display:none">inline hidden text</span>\n'
    )

    assert "Return items within 30 days." in page.text
    assert "markdown comment text" not in page.text
    assert hidden(page) == {
        "Markdown comment": "markdown comment text",
        "HTML comment": "html comment text",
        "display:none": "inline hidden text",
    }


def test_text_that_looks_like_html_is_parsed_as_html() -> None:
    page = extract_text('<p>Status: OK</p><p style="display:none">note</p>')

    assert page.text == "Status: OK"
    assert hidden(page) == {"display:none": "note"}


def test_plain_text_with_a_comparison_is_not_html() -> None:
    assert not looks_like_html("Use a < b when sorting, and c > d otherwise.")


def test_unicode_tag_characters_are_decoded() -> None:
    tags = "".join(chr(0xE0000 + ord(c)) for c in "tagged note")

    page = extract_text(f"Visible text.{tags}")

    assert smuggled(f"x{tags}y") == "tagged note"
    assert hidden(page) == {"Unicode tag characters": "tagged note"}


# DOCX


def docx(body: str, comments: str | None = None, title: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        document = f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'
        archive.writestr("word/document.xml", document)
        if comments is not None:
            archive.writestr(
                "word/comments.xml",
                f'<w:comments xmlns:w="{W}"><w:comment w:id="0"><w:p><w:r><w:t>{comments}'
                "</w:t></w:r></w:p></w:comment></w:comments>",
            )
        if title is not None:
            archive.writestr(
                "docProps/core.xml",
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
                f"<dc:title>{title}</dc:title></cp:coreProperties>",
            )
    return buffer.getvalue()


def run(text: str, properties: str = "") -> str:
    return f"<w:r><w:rPr>{properties}</w:rPr><w:t>{text}</w:t></w:r>"


def paragraph(*runs: str) -> str:
    return "<w:p>" + "".join(runs) + "</w:p>"


WHITE = '<w:color w:val="FFFFFF"/>'


def test_docx_hidden_runs_comments_and_properties() -> None:
    body = (
        paragraph(run("Shipping takes three days."), run(" vanished run", "<w:vanish/>"))
        + paragraph(run("white run", WHITE))
        + paragraph(run("tiny run", '<w:sz w:val="2"/>'))
        + paragraph(run("white on black", WHITE + '<w:shd w:fill="000000"/>'))
        + paragraph("<w:del><w:r><w:delText>deleted text</w:delText></w:r></w:del>")
    )

    page = extract(docx(body, comments="a reviewer comment", title="Doc title"), "docx")

    assert page.text == "Shipping takes three days.\nwhite on black"
    assert hidden(page) == {
        "hidden text": "vanished run",
        "white text": "white run",
        "tiny text": "tiny run",
        "tracked deletion": "deleted text",
        "comment": "a reviewer comment",
        "document properties": "Doc title",
    }


def test_docx_vanish_turned_off_is_visible() -> None:
    page = extract(docx(paragraph(run("shown", '<w:vanish w:val="false"/>'))), "docx")

    assert page.text == "shown"
    assert page.hidden == []


def test_docx_parts_over_the_size_limit_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("llm_auditor.extractors.docx.MAX_PART_BYTES", 10)

    with pytest.raises(ValueError, match="too large"):
        extract(docx(paragraph(run("some text"))), "docx")


def test_a_zip_without_a_document_is_not_a_docx() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "hello")

    with pytest.raises(ValueError, match="not a Word document"):
        extract(buffer.getvalue(), "docx")


# PDF


def pdf(content: str, title: str | None = None) -> bytes:
    """A one-page PDF with ``content`` as its content stream."""
    stream = content.encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    if title is not None:
        objects.append(b"<< /Title (%s) >>" % title.encode("latin-1"))
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    info = b" /Info %d 0 R" % len(objects) if title is not None else b""
    out += b"trailer\n<< /Size %d /Root 1 0 R%s >>\n" % (len(objects) + 1, info)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def test_pdf_hidden_text_and_metadata() -> None:
    content = "\n".join(
        [
            "BT /F1 12 Tf 72 720 Td (Shipping takes three days.) Tj ET",
            "1 1 1 rg BT /F1 12 Tf 72 700 Td (white text here) Tj ET",
            "0 g BT 3 Tr /F1 12 Tf 72 680 Td (invisible text here) Tj 0 Tr ET",
            "BT /F1 0.5 Tf 72 660 Td (tiny text here) Tj ET",
            "BT /F1 12 Tf 72 -400 Td (off page text) Tj ET",
            "0 0 0 rg 50 400 400 50 re f",
            "1 1 1 rg BT /F1 12 Tf 72 420 Td (White on black.) Tj ET",
        ]
    )

    page = extract(pdf(content, title="PDF title"), "pdf")

    assert page.text == "Shipping takes three days. White on black."
    assert hidden(page) == {
        "white text": "white text here",
        "invisible text (render mode 3)": "invisible text here",
        "tiny text": "tiny text here",
        "text placed off the page": "off page text",
        "metadata Title": "PDF title",
    }
    assert {h.page for h in page.hidden if not h.how.startswith("metadata")} == {1}


def test_pdf_with_only_visible_text_has_nothing_hidden() -> None:
    page = extract(pdf("BT /F1 12 Tf 72 720 Td (Just a normal page.) Tj ET"), "pdf")

    assert page.text == "Just a normal page."
    assert page.hidden == []
