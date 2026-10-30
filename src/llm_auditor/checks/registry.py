"""Registry of every check the auditor can run."""

from typing import TypeVar

from llm_auditor.checks.base import Check
from llm_auditor.models import CheckMeta

CheckT = TypeVar("CheckT", bound=type[Check])


class DuplicateCheckError(ValueError):
    pass


class UnknownCheckError(KeyError):
    pass


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, type[Check]] = {}

    def register(self, check: CheckT) -> CheckT:
        """Register a check class. Usable as a decorator."""
        check_id = check.meta.id
        if check_id in self._checks:
            raise DuplicateCheckError(f"check {check_id} is already registered")
        self._checks[check_id] = check
        return check

    def get(self, check_id: str) -> type[Check]:
        try:
            return self._checks[check_id]
        except KeyError:
            raise UnknownCheckError(check_id) from None

    def list_checks(self) -> list[CheckMeta]:
        """All registered checks, in natural ID order (P-02 before P-10)."""
        return sorted((check.meta for check in self._checks.values()), key=_natural_id)


def _natural_id(meta: CheckMeta) -> tuple[str, int]:
    prefix, number = meta.id.split("-")
    return prefix, int(number)


registry = CheckRegistry()
register = registry.register
