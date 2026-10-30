"""Serve the demo site on localhost: ``uv run python -m demo.showcase [--port 8000]``."""

import argparse

import uvicorn

from demo.showcase.app import create_app

parser = argparse.ArgumentParser(description="Serve the LLM Security Auditor demo site.")
parser.add_argument("--port", type=int, default=8000, help="port on 127.0.0.1 (default 8000)")
port = parser.parse_args().port
print(f"LLM Security Auditor demo: http://127.0.0.1:{port}  (Ctrl+C to stop)")
uvicorn.run(create_app(), host="127.0.0.1", port=port, log_level="warning")
