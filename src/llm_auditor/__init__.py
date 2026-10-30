"""LLM Security Auditor."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("llm-auditor")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0+unknown"
