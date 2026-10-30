import traceback

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI()


@app.exception_handler(Exception)
async def show_error(request: Request, error: Exception) -> PlainTextResponse:
    return PlainTextResponse(traceback.format_exc(), status_code=500)
