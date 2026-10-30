from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import llm_auditor.detectors  # noqa: F401  (registers the built-in checks)
from llm_auditor.audit import run_audit
from llm_auditor.checks import CheckRegistry, registry
from llm_auditor.models import Access, AuditReport, AuditScope, CapabilityProfile

AuditOne = Callable[..., AuditReport]


@pytest.fixture
def audit_one() -> AuditOne:
    """Run one built-in check: ``audit_one("SC-01", root, inputs={...}, attestations={...})``."""

    def run(check_id: str, root: Path, **scope: Any) -> AuditReport:
        catalog = CheckRegistry()
        catalog.register(registry.get(check_id))
        audit_scope = AuditScope.model_validate(
            {
                "name": "test",
                "access": Access.WHITE,
                "capability_profile": CapabilityProfile.neutral(),
                "root": root,
                **scope,
            }
        )
        return run_audit(audit_scope, checks=catalog)

    return run
