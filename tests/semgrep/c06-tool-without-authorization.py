from typing import Any

INVOICES: dict[str, Any] = {}
ORDERS: dict[str, Any] = {}
STATUS: dict[str, str] = {}


def get_invoice(user: str, arguments: dict[str, Any]) -> Any:
    # ruleid: llmaudit-c06-tool-without-authorization
    invoice = INVOICES.get(str(arguments.get("invoice_id", "")))
    return invoice


def delete_order(user_id, tool_args):
    # ruleid: llmaudit-c06-tool-without-authorization
    order = ORDERS[tool_args["order_id"]]
    order.delete()


def get_invoice_checked(user: str, arguments: dict[str, Any]) -> Any:
    # ok: llmaudit-c06-tool-without-authorization
    invoice = INVOICES.get(str(arguments.get("invoice_id", "")))
    if invoice is None or invoice.owner != user:
        return "not found"
    return invoice


def region_status(user: str, arguments: dict[str, Any]) -> str:
    # ok: llmaudit-c06-tool-without-authorization
    return STATUS.get(str(arguments.get("region", "eu")), "unknown")
