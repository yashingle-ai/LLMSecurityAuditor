import json
from typing import Any

import httpx
import pytest

from demo.common.backends import backend_from_env
from demo.common.llm import ChatMessage, ToolCall, ToolSpec
from demo.common.openai_compatible import OpenAICompatibleLLM
from demo.common.scripted import ScriptedLLM

TOOLS = (ToolSpec("get_invoice", "Look up an invoice.", {"type": "object"}),)


def fake_llm(reply: dict[str, Any], seen: list[httpx.Request]) -> OpenAICompatibleLLM:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": reply}]})

    client = httpx.Client(
        base_url="http://llm.test/v1",
        headers={"Authorization": "Bearer test-key"},
        transport=httpx.MockTransport(handle),
    )
    return OpenAICompatibleLLM("test-model", client)


def test_sends_an_openai_chat_completions_request() -> None:
    seen: list[httpx.Request] = []
    llm = fake_llm({"role": "assistant", "content": "hi"}, seen)

    llm.complete([ChatMessage("system", "Be brief."), ChatMessage("user", "hello")], TOOLS)

    request = seen[0]
    body = json.loads(request.content)
    assert str(request.url) == "http://llm.test/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer test-key"
    assert body["model"] == "test-model"
    assert body["temperature"] == 0
    assert body["messages"] == [
        {"role": "system", "content": "Be brief."},
        {"role": "user", "content": "hello"},
    ]
    assert body["tools"][0]["function"]["name"] == "get_invoice"


@pytest.mark.parametrize("max_tokens", [None, 256])
def test_sends_max_tokens_only_when_set(max_tokens: int | None) -> None:
    seen: list[httpx.Request] = []
    llm = fake_llm({"role": "assistant", "content": "hi"}, seen)

    llm.complete([ChatMessage("user", "hello")], (), max_tokens=max_tokens)

    body = json.loads(seen[0].content)
    assert body.get("max_tokens") == max_tokens
    assert "tools" not in body


def test_parses_text_replies() -> None:
    llm = fake_llm({"role": "assistant", "content": "Hello!"}, [])

    reply = llm.complete([ChatMessage("user", "hi")], TOOLS)

    assert reply.content == "Hello!"
    assert not reply.tool_calls


def test_parses_tool_calls() -> None:
    call = {
        "id": "call_a",
        "type": "function",
        "function": {"name": "get_invoice", "arguments": '{"invoice_id": "INV-1001"}'},
    }
    llm = fake_llm({"role": "assistant", "content": None, "tool_calls": [call]}, [])

    reply = llm.complete([ChatMessage("user", "INV-1001?")], TOOLS)

    assert reply.content == ""
    assert reply.tool_calls == (ToolCall("call_a", "get_invoice", {"invoice_id": "INV-1001"}),)


def test_keeps_malformed_tool_arguments_instead_of_crashing() -> None:
    call = {
        "id": "c",
        "type": "function",
        "function": {"name": "get_invoice", "arguments": "{oops"},
    }
    llm = fake_llm({"role": "assistant", "content": None, "tool_calls": [call]}, [])

    reply = llm.complete([ChatMessage("user", "x")], TOOLS)

    assert reply.tool_calls[0].arguments == {"_raw": "{oops"}


def test_backend_defaults_to_scripted() -> None:
    assert isinstance(backend_from_env({}), ScriptedLLM)


def test_real_backend_is_configured_from_the_environment() -> None:
    llm = backend_from_env(
        {"LLM_BACKEND": "real", "LLM_BASE_URL": "http://localhost:11434/v1", "LLM_MODEL": "llama3"}
    )

    assert llm.name == "llama3"


def test_real_backend_falls_back_to_the_apps_llm_config() -> None:
    llm = backend_from_env(
        {"LLM_BACKEND": "real", "LLM_MODEL": "override"},
        defaults={"base_url": "https://llm-gateway.example/v1", "model": "acme-2026-09-15"},
    )

    assert llm.name == "override"


@pytest.mark.parametrize(
    ("environ", "message"),
    [
        ({"LLM_BACKEND": "real"}, "needs LLM_BASE_URL and LLM_MODEL"),
        ({"LLM_BACKEND": "gpt"}, "unknown LLM_BACKEND"),
    ],
)
def test_bad_backend_settings_fail_clearly(environ: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        backend_from_env(environ)
