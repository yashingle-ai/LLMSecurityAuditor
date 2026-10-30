"""HAR exports from browsers and proxies. Calls to LLM APIs also become Interactions."""

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from llm_auditor.ingestion.base import (
    Artifact,
    FormatError,
    IngestReport,
    describe,
    expect_dict,
    parse_timestamp,
    read_structured,
)
from llm_auditor.ingestion.traces import normalize_trace
from llm_auditor.models import HarEntry, Interaction, RequestMeta


class HarLoader:
    extensions = frozenset({".har"})

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        data = read_structured(file, rel, report)
        if data is None:
            return []
        log = data.get("log") if isinstance(data, dict) else None
        entries = log.get("entries") if isinstance(log, dict) else None
        if not isinstance(entries, list):
            report.warn(rel, "skipped: not a HAR file (no log.entries)")
            return []
        artifacts: list[Artifact] = []
        for number, raw in enumerate(entries, 1):
            try:
                entry = _entry(raw, f"{rel}#{number}")
            except (FormatError, ValidationError) as error:
                report.warn(rel, f"entry {number} skipped: {describe(error)}")
                continue
            artifacts.append(entry)
            interaction = _llm_call(entry, rel, report)
            if interaction is not None:
                artifacts.append(interaction)
        return artifacts


def _entry(raw: Any, source: str) -> HarEntry:
    entry = expect_dict(raw, "entry")
    request = expect_dict(entry.get("request"), "request")
    response = expect_dict(entry.get("response") or {}, "response")
    status = response.get("status")
    return HarEntry(
        source=source,
        started=parse_timestamp(entry.get("startedDateTime")),
        method=str(request.get("method", "")).upper(),
        url=str(request.get("url", "")),
        status=status if isinstance(status, int) else 0,
        request_headers=_headers(request.get("headers")),
        response_headers=_headers(response.get("headers")),
        request_body=_string(expect_dict(request.get("postData") or {}, "postData").get("text")),
        response_body=_content(response.get("content")),
    )


def _llm_call(entry: HarEntry, rel: str, report: IngestReport) -> Interaction | None:
    """An Interaction if the request body looks like a chat API call."""
    body = _json_object(entry.request_body)
    if body is None or not isinstance(body.get("messages"), list):
        return None
    record = {"request": body, "response": _json_object(entry.response_body)}
    try:
        interaction = normalize_trace(record, entry.source)
    except (FormatError, ValidationError) as error:
        report.warn(rel, f"{entry.source}: LLM call not parsed: {describe(error)}")
        return None
    params = interaction.request_meta.params if interaction.request_meta else {}
    meta = RequestMeta(
        endpoint=entry.url, method=entry.method, headers=entry.request_headers, params=params
    )
    return interaction.model_copy(update={"timestamp": entry.started, "request_meta": meta})


def _headers(raw: Any) -> dict[str, str]:
    """HAR's header list as a dict with lower-case names; repeated headers are joined."""
    headers: dict[str, str] = {}
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            name, value = item["name"].lower(), str(item.get("value", ""))
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return headers


def _content(raw: Any) -> str | None:
    if not isinstance(raw, dict):
        return None
    text = _string(raw.get("text"))
    if text is not None and raw.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return None
    return text


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _json_object(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
