import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from llm_auditor.ingestion import Artifact, IngestReport, Loader
from llm_auditor.ingestion.traces import TraceLoader
from llm_auditor.models import IngestIssue, Interaction, LogMapping, Role
from scripts.generate_traffic import CONVERSATIONS

Load = Callable[[Loader, str], tuple[list[Artifact], list[IngestIssue]]]
Golden = Callable[[str, Sequence[Artifact]], None]

DEMO_TRAFFIC = Path(__file__).parents[2] / "demo" / "vulnerable_app" / "logs" / "traffic.jsonl"
MAPPING = LogMapping(
    user="input.prompt",
    assistant="output.choices.0.text",
    system="input.system",
    id="request_id",
    timestamp="ts",
    model="llm",
)


def interactions(artifacts: list[Artifact]) -> list[Interaction]:
    assert all(isinstance(a, Interaction) for a in artifacts)
    return [a for a in artifacts if isinstance(a, Interaction)]


@pytest.mark.parametrize("name", ["openai", "anthropic", "variants"])
def test_traces_match_golden(load: Load, golden: Golden, name: str) -> None:
    artifacts, issues = load(TraceLoader(), f"traces/{name}.jsonl")

    assert not issues
    golden(f"traces_{name}", artifacts)


def test_openai_and_anthropic_traces_of_one_conversation_normalize_identically(
    load: Load,
) -> None:
    openai, _ = load(TraceLoader(), "traces/openai.jsonl")
    anthropic, _ = load(TraceLoader(), "traces/anthropic.jsonl")

    assert len(openai) == 1
    assert [a.model_dump(exclude={"source"}) for a in openai] == [
        a.model_dump(exclude={"source"}) for a in anthropic
    ]


def test_conversation_is_normalized_in_order(load: Load) -> None:
    [run] = interactions(load(TraceLoader(), "traces/openai.jsonl")[0])

    assert run.system_prompt == "You are a support bot."
    assert [m.role for m in run.messages] == [Role.USER, Role.ASSISTANT, Role.TOOL, Role.ASSISTANT]
    assert run.tool_calls[0].arguments == {"invoice_id": "INV-1002"}
    assert run.tool_results[0].call_id == "call_1"
    assert run.messages[-1].content == "Invoice INV-1002 is due."
    assert run.request_meta is not None
    assert run.request_meta.params == {"max_tokens": 256}


def test_malformed_lines_are_reported_and_skipped(load: Load) -> None:
    artifacts, issues = load(TraceLoader(), "traces/malformed.jsonl")

    assert [run.messages[0].content for run in interactions(artifacts)] == ["hello", "still loads"]
    assert [issue.line for issue in issues] == [2, 3, 4, 6, 7]
    assert "not valid JSON" in issues[0].message
    assert "unknown message role 'wizard'" in issues[3].message


def test_mapped_format_follows_the_mapping(load: Load, golden: Golden) -> None:
    artifacts, issues = load(TraceLoader("mapped", MAPPING), "traces/mapped.jsonl")

    golden("traces_mapped", artifacts)
    assert [issue.line for issue in issues] == [3]
    assert "no user message" in issues[0].message


def test_mapped_format_needs_a_mapping() -> None:
    with pytest.raises(ValueError, match="needs a mapping"):
        TraceLoader("mapped")


def test_an_explicit_format_overrides_detection() -> None:
    record = {"system": "Be brief.", "messages": [{"role": "user", "content": "hi"}]}

    detected = TraceLoader().normalize(record, "x:1")
    forced = TraceLoader("openai").normalize(record, "x:1")

    assert detected.system_prompt == "Be brief."  # top-level system means Anthropic
    assert forced.system_prompt is None


def test_json_files_may_hold_a_list_of_records(tmp_path: Path) -> None:
    record = {"messages": [{"role": "user", "content": "hi"}]}
    file = tmp_path / "runs.json"
    file.write_text(json.dumps([record, record]), encoding="utf-8")

    runs = TraceLoader().load(file, "runs.json", IngestReport())

    assert [run.source for run in interactions(runs)] == ["runs.json#1", "runs.json#2"]


def test_demo_traffic_loads_without_issues() -> None:
    report = IngestReport()

    runs = interactions(TraceLoader().load(DEMO_TRAFFIC, "traffic.jsonl", report))

    assert not report.issues
    assert len(runs) == sum(len(messages) for _, messages in CONVERSATIONS)
    assert all(run.user in ("alice", "bob") for run in runs)
    assert all(run.system_prompt and "Acme Corp" in run.system_prompt for run in runs)
    invoice_lookup = runs[1]
    assert [m.role for m in invoice_lookup.messages] == [
        Role.USER,
        Role.ASSISTANT,
        Role.TOOL,
        Role.ASSISTANT,
    ]
    assert invoice_lookup.tool_results[0].call_id == invoice_lookup.tool_calls[0].id
