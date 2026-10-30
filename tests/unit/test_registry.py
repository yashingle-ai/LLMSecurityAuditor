from collections.abc import Callable, Iterable
from typing import ClassVar

import pytest

from llm_auditor.checks import (
    Check,
    CheckRegistry,
    Detection,
    DuplicateCheckError,
    UnknownCheckError,
)
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import CheckMeta

MakeMeta = Callable[..., CheckMeta]
MakeCheck = Callable[[CheckMeta], type[Check]]


def test_lists_checks_in_natural_id_order(make_meta: MakeMeta, make_check: MakeCheck) -> None:
    catalog = CheckRegistry()
    for check_id in ("P-10", "P-02", "SC-01", "A-01"):
        catalog.register(make_check(make_meta(id=check_id)))

    assert [meta.id for meta in catalog.list_checks()] == ["A-01", "P-02", "P-10", "SC-01"]


def test_register_works_as_a_decorator(make_meta: MakeMeta) -> None:
    catalog = CheckRegistry()
    expected = make_meta(id="P-01")

    @catalog.register
    class SecretsInPrompts:
        meta: ClassVar[CheckMeta] = expected

        def run(self, context: AuditContext) -> Iterable[Detection]:
            return []

    assert catalog.get("P-01") == SecretsInPrompts
    assert catalog.list_checks() == [expected]


def test_rejects_duplicate_ids(make_meta: MakeMeta, make_check: MakeCheck) -> None:
    catalog = CheckRegistry()
    catalog.register(make_check(make_meta(id="P-01")))

    with pytest.raises(DuplicateCheckError, match="P-01"):
        catalog.register(make_check(make_meta(id="P-01", title="Another check")))


def test_unknown_check_ids_raise() -> None:
    with pytest.raises(UnknownCheckError):
        CheckRegistry().get("P-99")
