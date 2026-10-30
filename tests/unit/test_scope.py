from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from llm_auditor.models import Access, AuditScope, Capability, InputKind, ScopeInputs

EXAMPLE_SCOPE = Path(__file__).parents[2] / "configs" / "audit_scope.example.yaml"

PROFILE: dict[str, Any] = {
    "exposure": "internal",
    "autonomy": "human_in_loop",
    "data_sensitivity": "medium",
    "multi_tenant": False,
    "capabilities": [],
}


def test_example_scope_file_loads() -> None:
    scope = AuditScope.from_yaml(EXAMPLE_SCOPE)

    assert scope.access is Access.WHITE
    assert scope.target is not None
    assert Capability.EXTERNAL_COMMUNICATION in scope.capability_profile.capabilities
    assert scope.inputs.tool_defs


def test_target_must_be_in_its_own_allow_list() -> None:
    with pytest.raises(ValidationError, match="not in allow_list"):
        AuditScope.model_validate(
            {
                "name": "x",
                "access": "black",
                "capability_profile": PROFILE,
                "target": {
                    "adapter": "http_chat",
                    "base_url": "https://prod.example.com",
                    "allow_list": ["localhost:8001"],
                },
            }
        )


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError, match="acess"):
        AuditScope.model_validate(
            {"name": "x", "acess": "white", "access": "white", "capability_profile": PROFILE}
        )


@pytest.mark.parametrize("missing", ["exposure", "autonomy", "data_sensitivity", "capabilities"])
def test_capability_profile_has_no_silent_defaults(missing: str) -> None:
    profile = {key: value for key, value in PROFILE.items() if key != missing}

    with pytest.raises(ValidationError, match=missing):
        AuditScope.model_validate({"name": "x", "access": "white", "capability_profile": profile})


def test_input_kinds_match_scope_input_fields() -> None:
    file_inputs = {kind.value for kind in InputKind} - {InputKind.TARGET, InputKind.ATTESTATIONS}

    assert file_inputs == set(ScopeInputs.model_fields)
