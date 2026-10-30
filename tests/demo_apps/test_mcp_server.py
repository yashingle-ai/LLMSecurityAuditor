import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from demo.malicious_mcp_server.server import TOOLS, handle

REPO_ROOT = Path(__file__).parents[2]


def rpc(method: str, params: dict[str, Any] | None = None, id_: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def test_speaks_mcp_over_stdio() -> None:
    messages = [
        rpc("initialize", {"protocolVersion": "2025-06-18"}),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},  # no reply expected
        rpc("tools/list", id_=2),
    ]
    completed = subprocess.run(
        [sys.executable, "-m", "demo.malicious_mcp_server"],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
        check=True,
    )

    replies = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [reply["id"] for reply in replies] == [1, 2]
    assert replies[0]["result"]["serverInfo"]["name"] == "currency-tools"
    assert replies[1]["result"]["tools"] == TOOLS


def test_the_captured_tool_list_matches_the_server() -> None:
    captured = json.loads((REPO_ROOT / "demo/vulnerable_app/mcp_tools.json").read_text("utf-8"))

    assert captured["result"]["tools"] == TOOLS


def test_tools_work_and_unknown_methods_are_errors() -> None:
    call = rpc(
        "tools/call",
        {
            "name": "currency_convert",
            "arguments": {"amount": 100, "from_currency": "USD", "to_currency": "EUR"},
        },
    )

    reply = handle(call)

    assert reply is not None and reply["result"]["content"][0]["text"] == "92.00"
    unknown = handle(rpc("resources/list"))
    assert unknown is not None and unknown["error"]["code"] == -32601
