"""Tools the support agent can call."""

import ast
import operator
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from demo.common.data import CUSTOMER_EMAILS, INVOICES, MEMORY, SUPPORT_INBOX, invoice_database
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
    if invoice is None or invoice.owner != user:
        return "No invoice with that ID on your account."
    return f"Invoice {invoice.id}: {invoice.amount} {invoice.currency}, {invoice.status}."


def get_billing_status(user: str, arguments: dict[str, Any]) -> str:
    return "The billing service is operational."


_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


def calculate(user: str, arguments: dict[str, Any]) -> str:
    try:
        tree = ast.parse(str(arguments.get("expression", "")), mode="eval")
        return str(_arithmetic(tree.body))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return "I can only work out simple arithmetic."


def _arithmetic(node: ast.expr) -> float:
    """Evaluate numbers and + - * / only; anything else is rejected."""
    value = node.value if isinstance(node, ast.Constant) else None
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
        return float(_OPERATORS[type(node.op)](_arithmetic(node.left), _arithmetic(node.right)))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_arithmetic(node.operand)
    raise ValueError("not simple arithmetic")


INVOICE_STATUSES = ("paid", "due", "overdue")


def invoice_report(user: str, arguments: dict[str, Any]) -> str:
    status = arguments.get("status", "due")
    if status not in INVOICE_STATUSES:
        return f"The status must be one of: {', '.join(INVOICE_STATUSES)}."
    rows = (
        invoice_database()
        .execute(
            "SELECT id, amount, currency FROM invoices WHERE owner = ? AND status = ?",
            (user, status),
        )
        .fetchall()
    )
    return "\n".join(f"{id_}: {amount} {currency}" for id_, amount, currency in rows) or (
        "No matching invoices."
    )


ALLOWED_HOSTS = frozenset({"status.acme-payments.example", "docs.acme.example"})
# The same allow-list, stated in the tool's schema so the model and validators see it too.
ALLOWED_URL_PATTERN = "^https://(" + "|".join(re.escape(h) for h in sorted(ALLOWED_HOSTS)) + ")/"


def allowed_url(url: str) -> str | None:
    """The URL if it is HTTPS on an approved host, otherwise None."""
    parts = urlsplit(url)
    return url if parts.scheme == "https" and parts.hostname in ALLOWED_HOSTS else None


def fetch_url(user: str, arguments: dict[str, Any]) -> str:
    url = allowed_url(str(arguments.get("url", "")))
    if url is None:
        return "I can only open pages on approved Acme sites."
    response = httpx.get(url, timeout=10, follow_redirects=False)
    return response.text[:2000]


def send_email(user: str, arguments: dict[str, Any]) -> str:
    """Always to the customer's own address: the model can't choose where data goes."""
    return f"Email '{arguments.get('subject', '')}' sent to {CUSTOMER_EMAILS[user]}."


def read_inbox(user: str, arguments: dict[str, Any]) -> str:
    return "\n\n".join(
        f"From: {message.sender}\nSubject: {message.subject}\n{message.body}"
        for message in SUPPORT_INBOX
    )


def search_notes(user: str, arguments: dict[str, Any]) -> str:
    query = str(arguments.get("query", ""))
    notes = SUPPORT_NOTES.similarity_search(query, k=3, filter={"customer": user})
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
                        "status": {"type": "string", "enum": list(INVOICE_STATUSES)},
                    },
                    "required": ["status"],
                },
            ),
            invoice_report,
        ),
        Tool(
            ToolSpec(
                name="fetch_url",
                description="Fetch a page from an approved Acme site, e.g. a status page.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "pattern": ALLOWED_URL_PATTERN},
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
                description="Email the customer at the address on file.",
                parameters={
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["subject", "body"],
                },
            ),
            send_email,
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
