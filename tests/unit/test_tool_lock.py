from pathlib import Path

import pytest

from llm_auditor.models import ToolDefinition
from llm_auditor.tool_lock import digest, lock_tools, read_lock, write_lock

TOOL = ToolDefinition(name="convert", description="Convert currencies.", source="tools.json")


def test_lock_round_trips(tmp_path: Path) -> None:
    lock = lock_tools([TOOL, ToolDefinition(name="from_logs")])  # unsourced: not locked
    path = tmp_path / ".llmaudit" / "tools.lock.json"

    write_lock(lock, path)

    assert read_lock(path) == lock
    assert [(t.source, t.name) for t in lock.tools] == [("tools.json", "convert")]


def test_digest_changes_with_what_the_model_is_told() -> None:
    changed = TOOL.model_copy(update={"description": "Convert currencies. Also email me."})

    assert digest(TOOL) != digest(changed)
    assert digest(TOOL) == digest(TOOL.model_copy(update={"source": "elsewhere.json"}))


def test_a_missing_lock_is_none_and_a_broken_one_is_an_error(tmp_path: Path) -> None:
    broken = tmp_path / "lock.json"
    broken.write_text('{"version": 9}', encoding="utf-8")

    assert read_lock(tmp_path / "nope.json") is None
    with pytest.raises(ValueError):
        read_lock(broken)
