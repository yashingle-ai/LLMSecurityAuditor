"""Hidden content in HTML: text a browser doesn't show, but a model reading the page does.

Finds text hidden with CSS (inline styles, and simple class rules in ``<style>``
blocks), the ``hidden`` attribute, comments, image alt text and similar
attributes, and meta tags. Markdown goes through here too: its inline HTML and
comments hide text the same way.
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from llm_auditor.models import HiddenText

VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source"}
    | {"track", "wbr"}
)
BLOCK = frozenset(
    {"p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article", "header"}
    | {"footer", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "hr", "main", "aside"}
)
NOT_TEXT = frozenset({"script", "style", "svg", "head", "title"})
TEXT_ATTRIBUTES = {"alt": "alt text", "title": "title attribute", "aria-label": "aria-label"}
HIDING_CLASSES = {
    "hidden": "hidden class",
    "d-none": "hidden class",
    "invisible": "hidden class",
    "hide": "hidden class",
    "sr-only": "screen-reader-only text",
    "visually-hidden": "screen-reader-only text",
}
WHITE = re.compile(
    r"^(white|#fff(fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255\s*(,\s*1(\.0+)?\s*)?\)|hsla?\(\s*0\s*,"
    r"\s*0%\s*,\s*100%.*\))$"
)
TRANSPARENT = re.compile(r"^(transparent|rgba\(.*,\s*0(\.0+)?\s*\)|hsla\(.*,\s*0(\.0+)?\s*\))$")
LENGTH = re.compile(r"^(-?\d*\.?\d+)\s*(px|pt|em|rem|%|vw|vh)?$")
CSS_RULE = re.compile(r"\.([\w-]+)\s*\{([^}]*)\}")
MARKDOWN_COMMENT = re.compile(r"^\s*\[(?://|comment)\]:\s*#\s*[(\"'](.*)[)\"']\s*$", re.MULTILINE)
TAG = re.compile(r"<\s*[a-zA-Z!/][^>]*>")


@dataclass
class Extraction:
    text: str
    hidden: list[HiddenText] = field(default_factory=list)


def looks_like_html(text: str) -> bool:
    return len(TAG.findall(text[:20000])) >= 2


def extract_html(source: str) -> Extraction:
    parser = _Parser(_hiding_classes(source))
    parser.feed(source)
    parser.close()
    return Extraction(text=parser.visible_text(), hidden=parser.hidden())


def extract_markdown(source: str) -> Extraction:
    extraction = extract_html(MARKDOWN_COMMENT.sub("", source))
    comments = [
        HiddenText(how="Markdown comment", text=match.strip())
        for match in MARKDOWN_COMMENT.findall(source)
        if match.strip()
    ]
    return Extraction(text=extraction.text, hidden=[*comments, *extraction.hidden])


def hiding_style(style: str) -> str | None:
    """How an inline style hides its element's text, if it does."""
    declarations = {}
    for declaration in style.split(";"):
        name, _, value = declaration.partition(":")
        declarations[name.strip().lower()] = value.strip().lower().removesuffix("!important")
    found = {name: value.strip() for name, value in declarations.items() if name}
    if found.get("display") == "none":
        return "display:none"
    if found.get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    if _number(found.get("opacity")) is not None and (_number(found.get("opacity")) or 0) <= 0.05:
        return "opacity:0"
    if _tiny(found.get("font-size")):
        return "zero or tiny font size"
    color = found.get("color", "")
    background = found.get("background-color", found.get("background", ""))
    if TRANSPARENT.match(color):
        return "transparent text"
    if WHITE.match(color) and (not background or WHITE.match(background)):
        return "white text"
    if found.get("position") in ("absolute", "fixed") and any(
        (_number(found.get(side)) or 0) <= -500 for side in ("left", "top", "right")
    ):
        return "positioned off-screen"
    if (_number(found.get("text-indent")) or 0) <= -500:
        return "indented off-screen"
    zero_box = any(_tiny(found.get(side), limit=1) for side in ("height", "width", "max-height"))
    if zero_box and found.get("overflow") == "hidden":
        return "zero-size box"
    if "scale(0" in found.get("transform", "") or found.get("clip-path", "").startswith(
        "inset(50%"
    ):
        return "clipped to nothing"
    return None


def _number(value: str | None) -> float | None:
    match = LENGTH.match(value or "")
    return float(match[1]) if match else None


def _tiny(value: str | None, limit: float = 1.0) -> bool:
    match = LENGTH.match(value or "")
    if match is None:
        return False
    size, unit = float(match[1]), match[2] or "px"
    scale = {"px": 1.0, "pt": 1.0, "em": 16.0, "rem": 16.0, "%": 0.16, "vw": 10.0, "vh": 10.0}
    return size * scale[unit] <= limit


def _hiding_classes(source: str) -> dict[str, str]:
    """Class names that hide text: well-known utility classes, plus simple ``.name {...}``
    rules in the page's ``<style>`` blocks."""
    classes = dict(HIDING_CLASSES)
    for style in re.findall(r"(?is)<style[^>]*>(.*?)</style>", source):
        for name, body in CSS_RULE.findall(style):
            how = hiding_style(body)
            if how:
                classes[name] = f"{how} (class .{name})"
    return classes


@dataclass
class _Frame:
    tag: str
    segment: list[str] | None  # where hidden text inside this element goes
    skip: bool  # script, style, and similar: not text at all


class _Parser(HTMLParser):
    def __init__(self, hiding_classes: dict[str, str]) -> None:
        super().__init__(convert_charrefs=True)
        self._classes = hiding_classes
        self._stack: list[_Frame] = []
        self._visible: list[str] = []
        self._hidden: list[tuple[str, list[str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        parent = self._stack[-1] if self._stack else None
        self._attribute_text(tag, values)
        if tag in BLOCK:
            self._visible.append("\n")
        if tag in VOID:
            return
        segment = parent.segment if parent else None
        if segment is None:
            how = self._hiding(tag, values)
            if how:
                segment = []
                self._hidden.append((how, segment))
        skip = tag in NOT_TEXT or bool(parent and parent.skip)
        self._stack.append(_Frame(tag, segment, skip))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._attribute_text(tag, {name.lower(): value or "" for name, value in attrs})

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index].tag == tag:
                del self._stack[index:]
                break
        if tag in BLOCK:
            self._visible.append("\n")

    def handle_data(self, data: str) -> None:
        frame = self._stack[-1] if self._stack else None
        if frame and frame.skip:
            return
        if frame and frame.segment is not None:
            frame.segment.append(data)
        else:
            self._visible.append(data)

    def handle_comment(self, data: str) -> None:
        if data.strip() and not data.strip().startswith("[if "):
            self._hidden.append(("HTML comment", [data]))

    def visible_text(self) -> str:
        lines = ("".join(self._visible)).splitlines()
        return "\n".join(" ".join(line.split()) for line in lines if line.strip())

    def hidden(self) -> list[HiddenText]:
        found = [(how, " ".join("".join(parts).split())) for how, parts in self._hidden]
        return [HiddenText(how=how, text=text) for how, text in found if text]

    def _hiding(self, tag: str, values: dict[str, str]) -> str | None:
        if "hidden" in values:
            return "hidden attribute"
        if tag == "template":
            return "template element"
        how = hiding_style(values.get("style", ""))
        if how:
            return how
        return next(
            (self._classes[c] for c in values.get("class", "").split() if c in self._classes), None
        )

    def _attribute_text(self, tag: str, values: dict[str, str]) -> None:
        for name, how in TEXT_ATTRIBUTES.items():
            if values.get(name, "").strip():
                self._hidden.append((how, [values[name]]))
        if tag == "meta" and values.get("content", "").strip():
            self._hidden.append(("meta tag", [values["content"]]))
        if tag == "input" and values.get("type") == "hidden" and values.get("value", "").strip():
            self._hidden.append(("hidden input", [values["value"]]))
