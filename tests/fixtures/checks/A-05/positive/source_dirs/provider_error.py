from fastapi import HTTPException
from openai import OpenAI, OpenAIError

client = OpenAI()


def ask(question: str) -> str:
    try:
        reply = client.chat.completions.create(model="gpt-x", messages=[])
    except OpenAIError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return reply.choices[0].message.content or ""
