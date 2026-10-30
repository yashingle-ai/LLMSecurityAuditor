import logging

from fastapi import HTTPException
from openai import OpenAI, OpenAIError

client = OpenAI()
log = logging.getLogger(__name__)


def ask(question: str) -> str:
    try:
        reply = client.chat.completions.create(model="gpt-x", messages=[])
    except OpenAIError as error:
        log.warning("provider error: %s", str(error))
        raise HTTPException(status_code=502, detail="The model is unavailable.") from error
    return reply.choices[0].message.content or ""
