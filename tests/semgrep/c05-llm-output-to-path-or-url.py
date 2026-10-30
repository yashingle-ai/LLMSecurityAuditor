from typing import Any
from urllib.parse import urlsplit

import httpx
import requests

ALLOWED = {"docs.acme.example"}


def fetch_url(user: str, arguments: dict[str, Any]) -> str:
    # ruleid: llmaudit-c05-llm-output-to-path-or-url
    return httpx.get(str(arguments.get("url", "")), timeout=10).text


def read_file(user: str, arguments: dict[str, Any]) -> str:
    # ruleid: llmaudit-c05-llm-output-to-path-or-url
    with open(arguments["path"]) as handle:
        return handle.read()


def follow_link(client):
    link = client.chat.completions.create(model="m", messages=[]).choices[0].message.content
    # ruleid: llmaudit-c05-llm-output-to-path-or-url
    return requests.get(link, timeout=10).text


def allowed_url(url: str) -> str | None:
    return url if urlsplit(url).hostname in ALLOWED else None


def safe_fetch(user: str, arguments: dict[str, Any]) -> str:
    url = allowed_url(str(arguments.get("url", "")))
    if url is None:
        return "not allowed"
    # ok: llmaudit-c05-llm-output-to-path-or-url
    return httpx.get(url, timeout=10).text


def fixed_fetch():
    # ok: llmaudit-c05-llm-output-to-path-or-url
    return httpx.get("https://docs.acme.example/faq", timeout=10).text
