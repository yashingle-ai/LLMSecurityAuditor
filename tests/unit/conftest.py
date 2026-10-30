from collections.abc import Callable
from typing import Any, cast

import pytest

from llm_auditor.checks import Check
from llm_auditor.models import (
    Access,
    Boundary,
    Capability,
    CheckMeta,
    FindingKind,
    InputKind,
    Surface,
)


@pytest.fixture
def make_meta() -> Callable[..., CheckMeta]:
    """Build a valid CheckMeta (an indirect-injection check by default) with overrides."""

    def make(**overrides: Any) -> CheckMeta:
        fields: dict[str, Any] = {
            "id": "T-03",
            "title": "Prompt injection in tool results",
            "surface": Surface.TOOL,
            "kind": FindingKind.WEAKNESS,
            "min_access": Access.GRAY,
            "inputs": (InputKind.LOGS,),
            "boundaries": (Boundary.B3,),
            "maps_to": ("LLM01", "ASI01"),
            "base_impact": 5,
            "amplified_by": frozenset(
                {
                    Capability.EXTERNAL_COMMUNICATION,
                    Capability.CODE_EXECUTION,
                    Capability.FILE_WRITE,
                    Capability.DESTRUCTIVE,
                    Capability.FINANCIAL,
                }
            ),
            "remediation": "Treat tool results as untrusted input.",
        }
        return CheckMeta(**(fields | overrides))

    return make


@pytest.fixture
def make_check() -> Callable[[CheckMeta], type[Check]]:
    """Build a minimal check class carrying the given metadata."""

    def make(meta: CheckMeta) -> type[Check]:
        name = "Check" + meta.id.replace("-", "")
        return cast("type[Check]", type(name, (), {"meta": meta}))

    return make
