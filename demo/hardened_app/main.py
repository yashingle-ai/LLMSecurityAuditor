"""Acme support agent: a demo target for the LLM Security Auditor. See demo/README.md."""

import html
import itertools
import logging
import os
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from demo.common.backends import backend_from_env
from demo.common.data import USERS_BY_TOKEN
from demo.common.llm import ChatMessage, LLMBackend
from demo.common.ratelimit import RateLimiter
from demo.common.traces import TraceLog

from . import VARIANT
from .agent import MAX_TOKENS, SETTINGS, run_agent
from .tools import TOOL_SPECS

APP_DIR = Path(__file__).parent
PROMPTS_DIR = APP_DIR / "prompts"
SYSTEM_PROMPT = (
    (PROMPTS_DIR / "system.txt").read_text(encoding="utf-8")
    + "\nReference FAQ:\n"
    + (PROMPTS_DIR / "faq.md").read_text(encoding="utf-8")
)
BEARER = HTTPBearer(auto_error=False)
LOG = logging.getLogger("acme.app")


class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None
    customer_note: str | None = None  # optional context, e.g. "prefers Spanish"


class ChatResponse(BaseModel):
    conversation_id: str
    reply: str


class CompletionRequest(BaseModel):
    prompt: str


def create_app(llm: LLMBackend, trace_log: TraceLog) -> FastAPI:
    app = FastAPI(title=f"Acme support agent ({VARIANT})")
    conversations: dict[tuple[str, str], list[ChatMessage]] = {}
    conversation_numbers = itertools.count(1)
    limiter = RateLimiter((SETTINGS.get("rate_limit") or {}).get("requests_per_minute"))

    def current_user(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(BEARER)],
    ) -> str:
        user = USERS_BY_TOKEN.get(credentials.credentials) if credentials else None
        if user is None:
            raise HTTPException(status_code=401, detail="Unknown or missing bearer token.")
        if not limiter.allow(user):
            raise HTTPException(status_code=429, detail="Too many requests; try again shortly.")
        return user

    @app.exception_handler(Exception)
    async def hide_errors(request: Request, error: Exception) -> PlainTextResponse:
        LOG.error("unhandled error on %s", request.url.path, exc_info=error)
        return PlainTextResponse("Something went wrong.", status_code=500)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "variant": VARIANT}

    @app.post("/chat")
    def chat(request: ChatRequest, user: Annotated[str, Depends(current_user)]) -> ChatResponse:
        conversation_id = request.conversation_id or f"conv_{next(conversation_numbers):04d}"
        history = conversations.get((user, conversation_id), [])
        message = request.message
        if request.customer_note:  # the customer's words stay in the user turn, marked as theirs
            message = f"{message}\n\n(Customer preferences, as given by the customer: "
            message += f"{request.customer_note})"
        messages = run_agent(llm, SYSTEM_PROMPT, history, message, user)
        conversations[(user, conversation_id)] = messages[1:]  # all but the system prompt
        trace_log.record(
            user=user,
            conversation_id=conversation_id,
            model=llm.name,
            messages=messages,
            tools=TOOL_SPECS,
        )
        return ChatResponse(conversation_id=conversation_id, reply=messages[-1].content)

    @app.post("/widget", response_class=HTMLResponse)
    def widget(request: ChatRequest, user: Annotated[str, Depends(current_user)]) -> HTMLResponse:
        """One answer as an HTML fragment, for the embeddable chat widget."""
        messages = run_agent(llm, SYSTEM_PROMPT, [], request.message, user)
        return HTMLResponse(f'<div class="acme-reply">{html.escape(messages[-1].content)}</div>')

    @app.post("/v1/complete")
    def complete(
        request: CompletionRequest, user: Annotated[str, Depends(current_user)]
    ) -> dict[str, str]:
        """A raw completion for internal tools: no conversation, no tools."""
        reply = llm.complete([ChatMessage("user", request.prompt)], [], max_tokens=MAX_TOKENS)
        return {"completion": reply.content}

    return app


app = create_app(
    backend_from_env(defaults=SETTINGS.get("llm")),
    TraceLog(Path(os.environ.get("DEMO_TRACE_FILE", APP_DIR / "logs" / "live.jsonl"))),
)
