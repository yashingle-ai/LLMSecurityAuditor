from pathlib import Path
from typing import Any

import pytest

from llm_auditor.ingestion import LOADERS, Artifacts, AuditContext, InputSummary, ingest
from llm_auditor.models import (
    Access,
    AuditScope,
    Boundary,
    CheckMeta,
    FindingKind,
    InputKind,
    Surface,
)
from scripts.generate_traffic import APPS, CONVERSATIONS

REPO_ROOT = Path(__file__).parents[2]
TRAFFIC_RUNS = sum(len(messages) for _, messages in CONVERSATIONS)
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "ingestion"
PROFILE: dict[str, Any] = {
    "exposure": "internal",
    "autonomy": "human_in_loop",
    "data_sensitivity": "medium",
    "multi_tenant": False,
    "capabilities": [],
}


def scope(**fields: Any) -> AuditScope:
    return AuditScope.model_validate(
        {"name": "test", "access": "gray", "capability_profile": PROFILE, **fields}
    )


def check(check_id: str, inputs: tuple[InputKind, ...], access: Access = Access.GRAY) -> CheckMeta:
    return CheckMeta(
        id=check_id,
        title="t",
        surface=Surface.PROMPT,
        kind=FindingKind.WEAKNESS,
        min_access=access,
        inputs=inputs,
        boundaries=(Boundary.B1,),
        base_impact=5,
        remediation="r",
    )


def context_with(*kinds: InputKind, **scope_fields: Any) -> AuditContext:
    summaries = [InputSummary(kind=k, entry="x", files=1, artifacts=1) for k in kinds]
    return AuditContext(
        scope=scope(**scope_fields), artifacts=Artifacts(), inputs=summaries, issues=[]
    )


def test_every_file_input_kind_has_a_loader() -> None:
    assert set(LOADERS) == set(InputKind) - {InputKind.TARGET, InputKind.ATTESTATIONS}


def test_ingests_the_example_scope() -> None:
    example = AuditScope.from_yaml(REPO_ROOT / "configs" / "audit_scope.example.yaml")

    context = ingest(example)

    assert example.root == REPO_ROOT
    loaded = context.artifacts
    assert [p.path for p in loaded.prompts] == [
        "demo/vulnerable_app/prompts/faq.md",
        "demo/vulnerable_app/prompts/handoff.jinja",
        "demo/vulnerable_app/prompts/system.txt",
    ]
    assert len(loaded.interactions) == TRAFFIC_RUNS
    app = APPS["vulnerable_app"]
    assert [t.name for t in loaded.tool_definitions] == [
        *(spec.name for spec in app.tool_specs),
        *(tool["name"] for tool in app.mcp_tools),
    ]
    assert len(loaded.source_files) == 5  # four Python modules and the chat widget's JS
    assert [server.name for server in loaded.mcp_servers] == ["currency-tools", "uploads"]
    assert [d.path for d in loaded.dependency_files] == ["demo/vulnerable_app/requirements.txt"]
    assert [m.format for m in loaded.model_files] == ["pickle"]
    assert [s.path for s in loaded.api_specs] == ["demo/vulnerable_app/openapi.json"]
    assert [config.path.split("/")[-1] for config in loaded.config_files] == [
        "agent.yaml",
        "docker-compose.yaml",
    ]
    assert context.issues == []


def test_plan_runs_only_checks_the_audit_can_support() -> None:
    context = context_with(InputKind.LOGS)
    checks = [
        check("P-01", (InputKind.PROMPT_DIRS,), Access.WHITE),
        check("P-02", (InputKind.SOURCE_DIRS,)),
        check("P-03", (InputKind.LOGS,)),
        check("P-04", (InputKind.TARGET,)),
        check("P-05", (InputKind.SOURCE_DIRS, InputKind.LOGS)),
    ]

    plan = context.plan(checks)

    assert [c.id for c in plan.runnable] == ["P-03", "P-05"]
    assert {s.check_id: s.reason for s in plan.skipped} == {
        "P-01": "needs white access; this audit has gray",
        "P-02": "needs one of: source_dirs; none were provided or loaded",
        "P-04": "needs one of: target; none were provided or loaded",
    }


def test_inputs_that_load_nothing_are_not_available() -> None:
    context = context_with()
    context.inputs.append(InputSummary(kind=InputKind.LOGS, entry="x", files=1, artifacts=0))

    assert InputKind.LOGS not in context.available_inputs


def test_a_configured_target_is_an_available_input() -> None:
    target = {
        "adapter": "http_chat",
        "base_url": "http://localhost:8001",
        "allow_list": ["localhost"],
    }

    assert InputKind.TARGET in context_with(target=target).available_inputs


def test_the_same_file_is_loaded_once_per_input_kind() -> None:
    context = ingest(
        scope(root=FIXTURES, inputs={"prompt_dirs": ["prompts", "prompts/system.txt"]})
    )

    assert sorted(p.path for p in context.artifacts.prompts) == [
        "prompts/answer.md",
        "prompts/support.jinja",
        "prompts/system.txt",
    ]


def test_log_entries_can_set_a_format_and_mapping() -> None:
    entry = {
        "path": "traces/mapped.jsonl",
        "format": "mapped",
        "mapping": {"user": "input.prompt", "assistant": "output.choices.0.text"},
    }

    context = ingest(scope(root=FIXTURES, inputs={"logs": [entry]}))

    assert [i.messages[0].content for i in context.artifacts.interactions] == [
        "What is my balance?",
        "Thanks!",
    ]


def test_a_mapped_log_entry_needs_a_mapping() -> None:
    with pytest.raises(ValueError, match="needs a mapping"):
        scope(inputs={"logs": [{"path": "x.jsonl", "format": "mapped"}]})


def test_scope_root_is_relative_to_the_scope_file(tmp_path: Path) -> None:
    (tmp_path / "configs").mkdir()
    scope_file = tmp_path / "configs" / "scope.yaml"
    scope_file.write_text(
        "name: x\naccess: white\nroot: ..\ncapability_profile:\n"
        "  exposure: internal\n  autonomy: human_in_loop\n  data_sensitivity: low\n"
        "  multi_tenant: false\n  capabilities: []\n",
        encoding="utf-8",
    )

    assert AuditScope.from_yaml(scope_file).root == tmp_path.resolve()
