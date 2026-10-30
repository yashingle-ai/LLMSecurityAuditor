import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from llm_auditor.ingestion import Artifact, IngestReport, Loader
from llm_auditor.models import IngestIssue

FIXTURES = Path(__file__).parents[1] / "fixtures" / "ingestion"
GOLDEN = FIXTURES / "expected"


@pytest.fixture
def load() -> Callable[[Loader, str], tuple[list[Artifact], list[IngestIssue]]]:
    """Run a loader on a fixture file; returns its artifacts and reported issues."""

    def run(loader: Loader, rel: str) -> tuple[list[Artifact], list[IngestIssue]]:
        report = IngestReport()
        artifacts = loader.load(FIXTURES / rel, rel, report)
        return artifacts, report.issues

    return run


@pytest.fixture
def golden() -> Callable[[str, Sequence[Artifact]], None]:
    """Compare artifacts with tests/fixtures/ingestion/expected/<name>.json.

    Set UPDATE_GOLDEN=1 to rewrite the expected files, then review the diff.
    """

    def check(name: str, artifacts: Sequence[Artifact]) -> None:
        path = GOLDEN / f"{name}.json"
        data = [artifact.model_dump(mode="json") for artifact in artifacts]
        actual = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if os.environ.get("UPDATE_GOLDEN"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(actual, encoding="utf-8")
        assert path.exists(), f"no golden file {path.name}; run with UPDATE_GOLDEN=1"
        assert actual == path.read_text(encoding="utf-8"), (
            f"{name} differs from its golden file; if the change is intended, "
            "rerun with UPDATE_GOLDEN=1 and review the diff"
        )

    return check
