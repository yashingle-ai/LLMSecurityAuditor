"""Hidden content in Word documents (.docx): hidden or white runs, tiny text, tracked
deletions, comments, and document properties. XML is parsed with defusedxml."""

import io
import zipfile
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from llm_auditor.extractors.html import Extraction
from llm_auditor.models import HiddenText

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
PROPERTIES = (
    "{http://purl.org/dc/elements/1.1/}title",
    "{http://purl.org/dc/elements/1.1/}subject",
    "{http://purl.org/dc/elements/1.1/}description",
    "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}keywords",
)
MAX_PART_BYTES = 50 * 1024 * 1024  # refuse zip bombs
WHITE = ("FFFFFF", "white")


def extract_docx(data: bytes) -> Extraction:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        document = _part(archive, "word/document.xml")
        if document is None:
            raise ValueError("not a Word document (no word/document.xml)")
        visible: list[str] = []
        hidden: list[HiddenText] = []
        for paragraph in document.iter(f"{W}p"):
            shown: list[str] = []
            concealed: dict[str, list[str]] = {}
            for how, text in _runs(paragraph):
                if how is None:
                    shown.append(text)
                else:
                    concealed.setdefault(how, []).append(text)
            if "".join(shown).strip():
                visible.append("".join(shown).strip())
            hidden += [HiddenText(how=how, text="".join(texts)) for how, texts in concealed.items()]
        comments = _part(archive, "word/comments.xml")
        for comment in comments.iter(f"{W}comment") if comments is not None else ():
            hidden.append(HiddenText(how="comment", text=_text(comment)))
        core = _part(archive, "docProps/core.xml")
        for tag in PROPERTIES if core is not None else ():
            element = core.find(tag) if core is not None else None
            if element is not None and (element.text or "").strip():
                hidden.append(HiddenText(how="document properties", text=element.text or ""))
    cleaned = [HiddenText(how=h.how, text=" ".join(h.text.split())) for h in hidden]
    return Extraction(text="\n".join(visible), hidden=[h for h in cleaned if h.text])


def _runs(paragraph: Element) -> list[tuple[str | None, str]]:
    """(how it's hidden, or None if visible; text) for each run in a paragraph."""
    found: list[tuple[str | None, str]] = []
    deleted = {id(run) for d in paragraph.iter(f"{W}del") for run in d.iter(f"{W}r")}
    for run in paragraph.iter(f"{W}r"):
        if id(run) in deleted:
            text = "".join(t.text or "" for t in run.iter(f"{W}delText"))
            found.append(("tracked deletion", text))
            continue
        text = "".join(t.text or "" for t in run.iter(f"{W}t"))
        if text:
            found.append((_hiding(run.find(f"{W}rPr")), text))
    return found


def _hiding(properties: Element | None) -> str | None:
    if properties is None:
        return None
    if _on(properties.find(f"{W}vanish")) or _on(properties.find(f"{W}webHidden")):
        return "hidden text"
    color = properties.find(f"{W}color")
    shading = properties.find(f"{W}shd")
    background = shading.get(f"{W}fill", "") if shading is not None else ""
    if (
        color is not None
        and color.get(f"{W}val", "") in WHITE
        and background in ("", "auto", *WHITE)
    ):
        return "white text"
    size = properties.find(f"{W}sz")
    if size is not None and size.get(f"{W}val", "").isdigit() and int(size.get(f"{W}val", "")) <= 2:
        return "tiny text"  # sizes are in half-points: 2 is 1pt
    return None


def _on(toggle: Element | None) -> bool:
    return toggle is not None and toggle.get(f"{W}val", "true") not in ("false", "0", "off")


def _part(archive: zipfile.ZipFile, name: str) -> Element | None:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_PART_BYTES:
        raise ValueError(f"{name} is too large ({info.file_size} bytes uncompressed)")
    root: Element = ElementTree.fromstring(archive.read(info))
    return root


def _text(element: Element) -> str:
    return " ".join(t.text or "" for t in element.iter(f"{W}t"))
