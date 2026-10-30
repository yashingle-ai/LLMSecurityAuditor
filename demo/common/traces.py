"""JSONL trace log: one line per agent run, in OpenAI chat format."""

import json
import threading
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from demo.common.llm import ChatMessage, ToolSpec
from demo.common.openai_format import message_to_openai, tool_to_openai


def _now() -> datetime:
    return datetime.now(UTC)


def _random_id() -> str:
    return f"run_{uuid.uuid4().hex[:12]}"


class TraceLog:
    def __init__(
        self,
        path: Path,
        clock: Callable[[], datetime] = _now,
        new_id: Callable[[], str] = _random_id,
    ) -> None:
        self.path = path
        self._clock = clock
        self._new_id = new_id
        self._lock = threading.Lock()

    def record(
        self,
        *,
        user: str,
        conversation_id: str,
        model: str,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSpec],
    ) -> None:
        with self._lock:
            entry = {
                "id": self._new_id(),
                "timestamp": self._clock().isoformat(),
                "user": user,
                "conversation_id": conversation_id,
                "model": model,
                "messages": [message_to_openai(message) for message in messages],
                "tools": [tool_to_openai(tool) for tool in tools],
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(entry, ensure_ascii=False) + "\n")
