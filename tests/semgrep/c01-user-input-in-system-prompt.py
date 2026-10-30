from typing import Annotated

from fastapi import Depends, FastAPI
from langchain_core.messages import SystemMessage

app = FastAPI()
SYSTEM_PROMPT = "You are a support agent."


@app.post("/chat")
def chat(request: ChatRequest, user: Annotated[str, Depends(current_user)]):
    # ruleid: llmaudit-c01-user-input-in-system-prompt
    system_prompt = f"{SYSTEM_PROMPT}\nCustomer notes: {request.note}"
    # ruleid: llmaudit-c01-user-input-in-system-prompt
    messages = [{"role": "system", "content": SYSTEM_PROMPT + request.message}]
    return system_prompt, messages


def answer(client, user_message):
    # ruleid: llmaudit-c01-user-input-in-system-prompt
    return client.messages.create(model="m", system=f"Help with: {user_message}", messages=[])


def build(question):
    # ruleid: llmaudit-c01-user-input-in-system-prompt
    return [SystemMessage(content="Answer this: " + question)]


@app.post("/safe")
def safe_chat(request: ChatRequest):
    # ok: llmaudit-c01-user-input-in-system-prompt
    system_prompt = SYSTEM_PROMPT
    # ok: llmaudit-c01-user-input-in-system-prompt
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": request.message}]
    return system_prompt, messages


def internal(today):
    # ok: llmaudit-c01-user-input-in-system-prompt
    system_prompt = f"{SYSTEM_PROMPT} Today is {today}."
    return system_prompt
