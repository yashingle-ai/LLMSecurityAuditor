"""Helpers shared by detectors that scan text."""

import json
from collections.abc import Iterator

from llm_auditor.ingestion.base import split_source
from llm_auditor.models import HarEntry, Interaction

__all__ = ["find_line", "har_texts", "interaction_texts", "line_at", "line_number", "split_source"]


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_line(text: str, needle: str) -> int | None:
    """The number of the first line containing ``needle``."""
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def line_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start : end if end != -1 else len(text)]


def interaction_texts(interaction: Interaction) -> Iterator[str]:
    """Every piece of text a logged interaction carries."""
    if interaction.system_prompt:
        yield interaction.system_prompt
    for message in interaction.messages:
        if message.content:
            yield message.content
        for call in message.tool_calls:
            yield json.dumps(call.arguments)
        if message.tool_result is not None:
            yield message.tool_result.content
    if interaction.request_meta is not None:
        yield from (f"{name}: {value}" for name, value in interaction.request_meta.headers.items())


def har_texts(entry: HarEntry) -> Iterator[str]:
    yield entry.url
    for headers in (entry.request_headers, entry.response_headers):
        yield from (f"{name}: {value}" for name, value in headers.items())
    for body in (entry.request_body, entry.response_body):
        if body:
            yield body
