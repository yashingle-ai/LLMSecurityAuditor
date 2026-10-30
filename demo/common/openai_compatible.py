"""A real model, through any OpenAI-compatible chat-completions API.

Works with OpenAI, Ollama (``http://localhost:11434/v1``), vLLM, LM Studio, and
gateways such as LiteLLM that front other providers.
"""

from collections.abc import Sequence
from typing import Any, Self

import httpx

from demo.common.llm import ChatMessage, LLMReply, ToolSpec
from demo.common.openai_format import message_to_openai, reply_from_openai, tool_to_openai


class OpenAICompatibleLLM:
    def __init__(self, model: str, client: httpx.Client) -> None:
        self._model = model
        self._client = client

    @classmethod
    def connect(
        cls, base_url: str, model: str, api_key: str | None = None, timeout: float = 60.0
    ) -> Self:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        return cls(model, httpx.Client(base_url=base_url, headers=headers, timeout=timeout))

    @property
    def name(self) -> str:
        return self._model

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSpec],
        max_tokens: int | None = None,
    ) -> LLMReply:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [message_to_openai(message) for message in messages],
            "temperature": 0,
        }
        if tools:
            payload["tools"] = [tool_to_openai(tool) for tool in tools]
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        response = self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        return reply_from_openai(response.json()["choices"][0]["message"])
