import logging
import traceback

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI()
logger = logging.getLogger(__name__)


@app.exception_handler(Exception)
async def hide_error(request: Request, error: Exception) -> PlainTextResponse:
    logger.error("request failed: %s", traceback.format_exc())
    return PlainTextResponse("Something went wrong.", status_code=500)
