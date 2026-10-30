"""Pick the LLM backend from the environment."""

import os
from collections.abc import Mapping
from typing import Any

from demo.common.llm import LLMBackend
from demo.common.openai_compatible import OpenAICompatibleLLM
from demo.common.scripted import ScriptedLLM


def backend_from_env(
    environ: Mapping[str, str] | None = None, defaults: Mapping[str, Any] | None = None
) -> LLMBackend:
    """``LLM_BACKEND=scripted`` (default) or ``real``.

    A real backend needs a base URL and a model: ``LLM_BASE_URL`` and ``LLM_MODEL``, or
    ``base_url`` and ``model`` in ``defaults`` (the app's ``llm`` config).
    """
    env = os.environ if environ is None else environ
    settings = defaults or {}
    kind = env.get("LLM_BACKEND", "scripted")
    if kind == "scripted":
        return ScriptedLLM()
    if kind == "real":
        base_url = env.get("LLM_BASE_URL") or settings.get("base_url")
        model = env.get("LLM_MODEL") or settings.get("model")
        if not base_url or not model:
            raise ValueError("LLM_BACKEND=real needs LLM_BASE_URL and LLM_MODEL")
        return OpenAICompatibleLLM.connect(
            str(base_url), str(model), api_key=env.get("LLM_API_KEY")
        )
    raise ValueError(f"unknown LLM_BACKEND {kind!r}; use 'scripted' or 'real'")
