import sqlite3
from typing import Any


def invoice_report(user: str, arguments: dict[str, Any]) -> list[Any]:
    db = sqlite3.connect(":memory:")
    status = arguments.get("status")
    # ruleid: llmaudit-c03-llm-output-to-sql
    rows = db.execute(f"SELECT * FROM invoices WHERE status = '{status}'").fetchall()
    # ok: llmaudit-c03-llm-output-to-sql
    rows += db.execute("SELECT * FROM invoices WHERE status = ?", (status,)).fetchall()
    return rows


def text_to_sql(llm, db, question):
    sql = llm.invoke(f"Write SQL for: {question}")
    # ruleid: llmaudit-c03-llm-output-to-sql
    return db.execute(sql.content)


def by_customer(db, customer_id):
    # ok: llmaudit-c03-llm-output-to-sql
    return db.execute("SELECT * FROM invoices WHERE owner = ?", (customer_id,))


from tools import execute  # an agent's tool dispatcher, not a database cursor


def run_tools(llm, messages, user):
    reply = llm.complete(messages)
    for call in reply.tool_calls:
        # ok: llmaudit-c03-llm-output-to-sql
        execute(call, user)
