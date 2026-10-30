import ast
import os
import subprocess
from typing import Any


def calculate(user: str, arguments: dict[str, Any]) -> str:
    # ruleid: llmaudit-c02-llm-output-to-code-execution
    return str(eval(str(arguments.get("expression", ""))))


def run_command(client, task):
    reply = client.chat.completions.create(model="m", messages=[{"role": "user", "content": task}])
    command = reply.choices[0].message.content
    # ruleid: llmaudit-c02-llm-output-to-code-execution
    subprocess.run(command, shell=True)
    # ruleid: llmaudit-c02-llm-output-to-code-execution
    os.system(command)


def handle(tool_call):
    # ruleid: llmaudit-c02-llm-output-to-code-execution
    exec(tool_call.function.arguments)


def safe_calculate(user: str, arguments: dict[str, Any]) -> str:
    # ok: llmaudit-c02-llm-output-to-code-execution
    return str(ast.literal_eval(str(arguments.get("expression", ""))))


def maintenance():
    # ok: llmaudit-c02-llm-output-to-code-execution
    subprocess.run(["git", "status"], check=True)
    # ok: llmaudit-c02-llm-output-to-code-execution
    return eval("1 + 1")
