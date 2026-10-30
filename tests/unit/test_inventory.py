from typing import Any

import pytest

from demo.malicious_mcp_server.server import SEND_EMAIL_LOOKALIKE
from llm_auditor.ingestion.tools import parse_tool_definition
from llm_auditor.inventory import classify, is_free_text, profile, unique_definitions
from llm_auditor.models import Capability, Interaction, ToolDefinition
from scripts.generate_traffic import APPS

C = Capability
EXPECTED = {
    "vulnerable_app": {
        "get_invoice": {C.READS_PRIVATE_DATA},
        "get_billing_status": set(),
        "calculate": set(),  # it eval()s, but nothing in its schema says so; C-02 covers the code
        "invoice_report": {C.READS_PRIVATE_DATA},
        "fetch_url": {C.INGESTS_UNTRUSTED_CONTENT, C.EXTERNAL_COMMUNICATION},
        "read_inbox": {C.READS_PRIVATE_DATA, C.INGESTS_UNTRUSTED_CONTENT},
        "search_notes": {C.READS_PRIVATE_DATA},
        "save_memory": {C.WRITES_MEMORY},
        "send_email": {C.EXTERNAL_COMMUNICATION},
        "run_shell": {C.CODE_EXECUTION},
        "run_python": {C.CODE_EXECUTION},
        "delete_account": {C.DESTRUCTIVE},
        "currency_convert": set(),
        SEND_EMAIL_LOOKALIKE: {C.EXTERNAL_COMMUNICATION},
    },
    "hardened_app": {
        "get_invoice": {C.READS_PRIVATE_DATA},
        "get_billing_status": set(),
        "calculate": set(),
        "invoice_report": {C.READS_PRIVATE_DATA},
        "fetch_url": set(),  # allow-listed in its schema: no model-chosen destination
        "read_inbox": {C.READS_PRIVATE_DATA, C.INGESTS_UNTRUSTED_CONTENT},
        "search_notes": {C.READS_PRIVATE_DATA},
        "save_memory": {C.WRITES_MEMORY},
        "send_email": set(),  # always the customer's own address
        "run_python": {C.CODE_EXECUTION},
        "delete_account": {C.DESTRUCTIVE},
    },
}


def demo_definitions(app_name: str) -> list[ToolDefinition]:
    app = APPS[app_name]
    tools = [
        parse_tool_definition({"function": spec.__dict__}, "tools.json") for spec in app.tool_specs
    ]
    return tools + [parse_tool_definition(tool, "mcp_tools.json") for tool in app.mcp_tools]


@pytest.mark.parametrize("app_name", sorted(EXPECTED))
def test_inventory_gives_every_demo_tool_the_right_capabilities(app_name: str) -> None:
    found = {tool.name: set(classify(tool)) for tool in demo_definitions(app_name)}

    assert found == EXPECTED[app_name]


def test_every_capability_comes_with_a_reason() -> None:
    for tool in demo_definitions("vulnerable_app"):
        assert all(reason for reason in classify(tool).values())


def test_scope_overrides_replace_the_guess() -> None:
    calculate = next(t for t in demo_definitions("vulnerable_app") if t.name == "calculate")

    overridden = profile(calculate, {"calculate": [C.CODE_EXECUTION]})

    assert overridden.capabilities == (C.CODE_EXECUTION,)
    assert overridden.overridden
    assert overridden.reasons == {C.CODE_EXECUTION: "set in the scope file"}


@pytest.mark.parametrize(
    ("schema", "free"),
    [
        ({"type": "string"}, True),
        ({}, True),  # no type: anything goes
        ({"type": ["string", "null"]}, True),
        ({"type": "array", "items": {"type": "string"}}, True),
        ({"type": "string", "enum": ["a", "b"]}, False),
        ({"type": "string", "pattern": "^https://x/"}, False),
        ({"type": "string", "const": "x"}, False),
        ({"type": "integer"}, False),
    ],
)
def test_free_text_parameters(schema: dict[str, Any], free: bool) -> None:
    assert is_free_text(schema) is free


def test_tools_seen_only_in_logs_join_the_inventory_once() -> None:
    known = ToolDefinition(name="get_invoice", source="tools.json")
    runtime_only = ToolDefinition(name="debug_dump")
    runs = [
        Interaction(id=f"r{i}", source=f"logs/a.jsonl:{i}", tool_definitions=[known, runtime_only])
        for i in (1, 2)
    ]

    unique = unique_definitions([known], runs)

    assert [(t.name, t.source) for t in unique] == [
        ("get_invoice", "tools.json"),
        ("debug_dump", "logs/a.jsonl"),
    ]
