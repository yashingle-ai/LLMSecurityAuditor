"""Application config files: YAML, JSON, TOML, and ``.env``."""

from pathlib import Path
from typing import Literal

from llm_auditor.ingestion.base import Artifact, IngestReport, read_structured, read_text
from llm_auditor.models import ConfigFile

ConfigFormat = Literal["yaml", "json", "toml", "env"]


class ConfigFileLoader:
    extensions = frozenset({".yaml", ".yml", ".json", ".toml", ".env"})

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        config_format = _format(file)
        if config_format == "env":
            text = read_text(file, rel, report)
            data = None if text is None else _parse_env(text)
        else:
            data = read_structured(file, rel, report)
        if data is None:
            return []
        return [ConfigFile(path=rel, format=config_format, data=data)]


def _format(file: Path) -> ConfigFormat:
    name = file.name.lower()
    if name == ".env" or name.startswith(".env.") or file.suffix.lower() == ".env":
        return "env"
    if file.suffix.lower() in (".yaml", ".yml"):
        return "yaml"
    if file.suffix.lower() == ".toml":
        return "toml"
    return "json"


def _parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        values[key.strip()] = value.strip().strip("\"'")
    return values
