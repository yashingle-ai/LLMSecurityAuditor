import html

import markdown
from fastapi.responses import HTMLResponse


def widget(llm, request, user):
    messages = run_agent(llm, "prompt", [], request.message, user)
    # ruleid: llmaudit-c04-llm-output-to-html
    return HTMLResponse(f"<div>{messages[-1].content}</div>")


def render(client):
    reply = client.messages.create(model="m", max_tokens=100, messages=[])
    # ruleid: llmaudit-c04-llm-output-to-html
    return markdown.markdown(reply.content[0].text)


def safe_widget(llm, request, user):
    messages = run_agent(llm, "prompt", [], request.message, user)
    # ok: llmaudit-c04-llm-output-to-html
    return HTMLResponse(f"<div>{html.escape(messages[-1].content)}</div>")


def static_page():
    # ok: llmaudit-c04-llm-output-to-html
    return HTMLResponse("<h1>Support</h1>")
