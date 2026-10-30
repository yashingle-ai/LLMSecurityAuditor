"""Tools the support agent can call."""

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from demo.common.data import INVOICES, MEMORY, SUPPORT_INBOX, invoice_database
from demo.common.llm import ToolCall, ToolSpec
from demo.common.vectors import SUPPORT_NOTES

Handler = Callable[[str, dict[str, Any]], str]  # (user, arguments) -> result shown to the model
SANDBOX_URL = "http://python-sandbox:8080/run"  # the code sandbox in sandbox/docker-compose.yaml


@dataclass(frozen=True)
class Tool:
    spec: ToolSpec
    handler: Handler


def get_invoice(user: str, arguments: dict[str, Any]) -> str:
    invoice = INVOICES.get(str(arguments.get("invoice_id", "")))
    if invoice is None:
        return "No invoice with that ID."
    return f"Invoice {invoice.id}: {invoice.amount} {invoice.currency}, {invoice.status}."


def get_billing_status(user: str, arguments: dict[str, Any]) -> str:
    return "The billing service is operational."


def calculate(user: str, arguments: dict[str, Any]) -> str:
    return str(eval(str(arguments.get("expression", ""))))


def invoice_report(user: str, arguments: dict[str, Any]) -> str:
    status = arguments.get("status", "due")
    rows = (
        invoice_database()
        .execute(
            "SELECT id, amount, currency FROM invoices "
            f"WHERE owner = '{user}' AND status = '{status}'"
        )
        .fetchall()
    )
    return "\n".join(f"{id_}: {amount} {currency}" for id_, amount, currency in rows) or (
        "No matching invoices."
    )


def fetch_url(user: str, arguments: dict[str, Any]) -> str:
    response = httpx.get(str(arguments.get("url", "")), timeout=10, follow_redirects=True)
    return response.text[:2000]


def send_email(user: str, arguments: dict[str, Any]) -> str:
    return f"Email '{arguments.get('subject', '')}' sent to {arguments.get('to', '')}."


def run_shell(user: str, arguments: dict[str, Any]) -> str:
    command = str(arguments.get("command", ""))
    completed = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
    return (completed.stdout + completed.stderr)[:2000]


def read_inbox(user: str, arguments: dict[str, Any]) -> str:
    return "\n\n".join(
        f"From: {message.sender}\nSubject: {message.subject}\n{message.body}"
        for message in SUPPORT_INBOX
    )


def search_notes(user: str, arguments: dict[str, Any]) -> str:
    notes = SUPPORT_NOTES.similarity_search(str(arguments.get("query", "")), k=3)
    return "\n".join(note.text for note in notes) or "No matching notes."


def save_memory(user: str, arguments: dict[str, Any]) -> str:
    MEMORY.setdefault(user, []).append(str(arguments.get("note", "")))
    return "Saved."


def run_python(user: str, arguments: dict[str, Any]) -> str:
    try:
        response = httpx.post(
            SANDBOX_URL, json={"code": str(arguments.get("code", ""))}, timeout=30
        )
    except httpx.HTTPError:
        return "The code sandbox isn't available."
    return response.text[:2000]


def delete_account(user: str, arguments: dict[str, Any]) -> str:
    return f"The account for {user} is scheduled for deletion."


TOOLS = {
    tool.spec.name: tool
    for tool in (
        Tool(
            ToolSpec(
                name="get_invoice",
                description="Look up one of the customer's invoices by its ID.",
                parameters={
                    "type": "object",
                    "properties": {
                        "invoice_id": {"type": "string", "description": "e.g. INV-1001"},
                    },
                    "required": ["invoice_id"],
                },
            ),
            get_invoice,
        ),
        Tool(
            ToolSpec(
                name="get_billing_status",
                description="Check whether the billing service is operational.",
                parameters={"type": "object", "properties": {}},
            ),
            get_billing_status,
        ),
        Tool(
            ToolSpec(
                name="calculate",
                description="Work out an amount, e.g. a balance after a refund.",
                parameters={
                    "type": "object",
                    "properties": {
                        "expression": {"type": "string", "description": "e.g. 120 - 35.5"},
                    },
                    "required": ["expression"],
                },
            ),
            calculate,
        ),
        Tool(
            ToolSpec(
                name="invoice_report",
                description="List the customer's invoices with a given status.",
                parameters={
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["paid", "due", "overdue"]},
                    },
                    "required": ["status"],
                },
            ),
            invoice_report,
        ),
        Tool(
            ToolSpec(
                name="fetch_url",
                description="Fetch a web page the customer mentions, e.g. a status page.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                    },
                    "required": ["url"],
                },
            ),
            fetch_url,
        ),
        Tool(
            ToolSpec(
                name="read_inbox",
                description="Read the latest messages in the support inbox.",
                parameters={"type": "object", "properties": {}},
            ),
            read_inbox,
        ),
        Tool(
            ToolSpec(
                name="search_notes",
                description="Search the support team's notes about the customer.",
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            ),
            search_notes,
        ),
        Tool(
            ToolSpec(
                name="save_memory",
                description="Save a note about the customer to memory, for future conversations.",
                parameters={
                    "type": "object",
                    "properties": {"note": {"type": "string"}},
                    "required": ["note"],
                },
            ),
            save_memory,
        ),
        Tool(
            ToolSpec(
                name="send_email",
                description="Send an email.",
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["to", "subject", "body"],
                },
            ),
            send_email,
        ),
        Tool(
            ToolSpec(
                name="run_shell",
                description="Run a shell command on the support server, for diagnostics.",
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                    },
                    "required": ["command"],
                },
            ),
            run_shell,
        ),
        Tool(
            ToolSpec(
                name="run_python",
                description="Run Python code in the code sandbox and return its output.",
                parameters={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                    },
                    "required": ["code"],
                },
            ),
            run_python,
        ),
        Tool(
            ToolSpec(
                name="delete_account",
                description="Close and delete the customer's account.",
                parameters={"type": "object", "properties": {}},
            ),
            delete_account,
        ),
    )
}
TOOL_SPECS = tuple(tool.spec for tool in TOOLS.values())


def execute(call: ToolCall, user: str) -> str:
    tool = TOOLS.get(call.name)
    if tool is None:
        return f"Unknown tool: {call.name}"
    return tool.handler(user, call.arguments)
