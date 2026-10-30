"""Rule packs shipped with the auditor: secret formats and Semgrep rules."""

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

RULES_DIR = Path(__file__).parent
SEMGREP_RULES_DIR = RULES_DIR / "semgrep"
GENERATED_CODE_RULES_DIR = RULES_DIR / "semgrep_generated"  # O-06, for code in responses


class SecretRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]+$")
    title: str = Field(min_length=1)
    pattern: str
    group: int = Field(default=0, ge=0)
    replacement: str | None = None
    generic: bool = False

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, pattern: str) -> str:
        re.compile(pattern)
        return pattern


@dataclass(frozen=True)
class SecretPattern:
    id: str
    title: str
    regex: re.Pattern[str]
    group: int = 0
    replacement: str | None = None
    generic: bool = False

    @classmethod
    def from_rule(cls, rule: SecretRule) -> Self:
        return cls(
            id=rule.id,
            title=rule.title,
            regex=re.compile(rule.pattern),
            group=rule.group,
            replacement=rule.replacement,
            generic=rule.generic,
        )


def load_secret_rules(path: Path) -> tuple[SecretPattern, ...]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = [SecretRule.model_validate(item) for item in data["rules"]]
    return tuple(SecretPattern.from_rule(rule) for rule in rules)


@cache
def secret_patterns() -> tuple[SecretPattern, ...]:
    """The built-in secret formats, in priority order."""
    return load_secret_rules(RULES_DIR / "secrets.yaml")
