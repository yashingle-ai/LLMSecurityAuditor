"""Hidden content in PDFs: white or invisible text, text too small to read, text placed off
the page, and document metadata.

pypdf extracts the text. It reports text only when a text block ends, so this tracks
the graphics state at each text-showing operator itself (fill colour, render mode,
font size, position), then splits pypdf's text between those operators. White text
drawn over a dark filled rectangle is visible, so it isn't reported.
"""

import io
import math
from dataclasses import dataclass, field, replace
from typing import Any

from pypdf import PdfReader

from llm_auditor.extractors.html import Extraction
from llm_auditor.models import HiddenText

SHOW_TEXT = (b"Tj", b"TJ", b"'", b'"')
FILL = (b"f", b"F", b"f*", b"B", b"B*", b"b", b"b*")
METADATA = ("/Title", "/Subject", "/Keywords", "/Author")
MIN_SIZE = 1.5  # points; smaller text can't be read
INVISIBLE_MODES = (3, 7)  # text render modes that paint nothing

Matrix = tuple[float, float, float, float, float, float]
Box = tuple[float, float, float, float]  # x0, y0, x1, y1


@dataclass(frozen=True)
class _State:
    fill: tuple[float, ...] = (0.0,)  # gray, RGB, or CMYK
    render_mode: int = 0
    font_size: float = 12.0


@dataclass
class _Show:
    how: str | None
    text: str | None  # decoded directly, when the bytes are plain text


@dataclass
class _Page:
    box: Box
    stack: list[_State] = field(default_factory=list)
    state: _State = field(default_factory=_State)
    pending_rects: list[Box] = field(default_factory=list)
    dark_areas: list[Box] = field(default_factory=list)
    shows: list[_Show] = field(default_factory=list)
    hidden: list[tuple[str, str]] = field(default_factory=list)
    visible: list[str] = field(default_factory=list)

    def operator(self, op: bytes, args: list[Any], cm: list[float], tm: list[float]) -> None:
        state = self.state
        if op == b"q":
            self.stack.append(state)
        elif op == b"Q" and self.stack:
            self.state = self.stack.pop()
        elif op in (b"g", b"rg", b"k") or (op in (b"sc", b"scn") and _numbers(args)):
            self.state = replace(state, fill=tuple(_numbers(args)))
        elif op == b"Tr" and _numbers(args):
            self.state = replace(state, render_mode=int(_numbers(args)[0]))
        elif op == b"Tf" and len(args) == 2 and _numbers(args[1:]):
            self.state = replace(state, font_size=_numbers(args[1:])[0])
        elif op == b"re" and len(_numbers(args)) == 4:
            x, y, w, h = _numbers(args)
            self.pending_rects.append(_box(_matrix(cm), x, y, w, h))
        elif op in FILL:
            if not _is_white(state.fill):
                self.dark_areas += self.pending_rects
            self.pending_rects = []
        elif op in (b"n", b"S", b"s"):
            self.pending_rects = []
        elif op in SHOW_TEXT:
            self.shows.append(_Show(self._hiding(_matrix(cm), _matrix(tm)), _decoded(args)))

    def text(self, text: str, *_: Any) -> None:
        if not text.strip():
            return
        shows, self.shows = self.shows, []
        if all(show.how is None for show in shows):
            self.visible.append(text)
            return
        decoded = [show.text for show in shows]
        joined = "".join(d or "" for d in decoded)
        if all(d is not None for d in decoded) and joined.split() == text.split():
            for show in shows:
                self._add(show.how, show.text or "")
            return
        how = next(show.how for show in shows if show.how)
        self._add(f"{how} (mixed with visible text)" if len(shows) > 1 else how, text)

    def _add(self, how: str | None, text: str) -> None:
        if how is None:
            self.visible.append(text)
        elif self.hidden and self.hidden[-1][0] == how:
            self.hidden[-1] = (how, self.hidden[-1][1] + text)
        else:
            self.hidden.append((how, text))

    def _hiding(self, cm: Matrix, tm: Matrix) -> str | None:
        state = self.state
        if state.render_mode in INVISIBLE_MODES:
            return f"invisible text (render mode {state.render_mode})"
        x, y = _apply(cm, tm[4], tm[5])
        x0, y0, x1, y1 = self.box
        if not (x0 - 5 <= x <= x1 + 5 and y0 - 5 <= y <= y1 + 5):
            return "text placed off the page"
        scale = math.hypot(tm[1], tm[3]) * math.hypot(cm[1], cm[3])
        if 0 < state.font_size * scale < MIN_SIZE:
            return "tiny text"
        on_dark = any(a[0] <= x <= a[2] and a[1] <= y <= a[3] for a in self.dark_areas)
        if _is_white(state.fill) and not on_dark:
            return "white text"
        return None


def extract_pdf(data: bytes) -> Extraction:
    reader = PdfReader(io.BytesIO(data))
    pages: list[str] = []
    hidden: list[HiddenText] = []
    for number, page in enumerate(reader.pages, 1):
        box = page.mediabox
        state = _Page(box=(float(box.left), float(box.bottom), float(box.right), float(box.top)))
        page.extract_text(visitor_operand_before=state.operator, visitor_text=state.text)
        pages.append(" ".join(" ".join(state.visible).split()))
        for how, text in state.hidden:
            if text.strip():
                hidden.append(HiddenText(how=how, text=" ".join(text.split()), page=number))
    metadata = reader.metadata
    for key in METADATA if metadata is not None else ():
        value = metadata.get(key) if metadata is not None else None
        if isinstance(value, str) and value.strip():
            hidden.append(HiddenText(how=f"metadata {key.lstrip('/')}", text=value.strip()))
    return Extraction(text="\n".join(p for p in pages if p), hidden=hidden)


def _numbers(args: list[Any]) -> list[float]:
    values = [a for a in args if isinstance(a, int | float) and not isinstance(a, bool)]
    return [float(v) for v in values] if len(values) == len(args) else []


def _is_white(fill: tuple[float, ...]) -> bool:
    if len(fill) == 4:  # CMYK
        return all(c <= 0.05 for c in fill)
    return bool(fill) and all(c >= 0.95 for c in fill)


def _decoded(args: list[Any]) -> str | None:
    """The shown text, when its bytes are plain printable text (simple fonts)."""
    parts = [a for a in (args[-1] if args and isinstance(args[-1], list) else args[-1:])]
    raw = b"".join(p for p in parts if isinstance(p, bytes))
    if not raw:
        text = "".join(p for p in parts if isinstance(p, str))
        return text or None
    decoded = raw.decode("latin-1")
    return decoded if decoded.isprintable() else None


def _matrix(values: list[float]) -> Matrix:
    a, b, c, d, e, f = (float(v) for v in values[:6])
    return (a, b, c, d, e, f)


def _apply(m: Matrix, x: float, y: float) -> tuple[float, float]:
    return m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]


def _box(m: Matrix, x: float, y: float, w: float, h: float) -> Box:
    (ax, ay), (bx, by) = _apply(m, x, y), _apply(m, x + w, y + h)
    return min(ax, bx), min(ay, by), max(ax, bx), max(ay, by)
