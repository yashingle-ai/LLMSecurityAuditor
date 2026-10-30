import pytest

from llm_auditor.models import Location
from llm_auditor.scoring import fingerprint

BASE = ("P-01", Location(file="prompts/system.txt", line=12), "key = sk-****9f2a")


def test_fingerprint_ignores_line_numbers_and_whitespace() -> None:
    moved_and_reformatted = fingerprint(
        "P-01", Location(file="./prompts/system.txt", line=40), "key  =\n    sk-****9f2a "
    )

    assert fingerprint(*BASE) == moved_and_reformatted


def test_fingerprint_normalizes_windows_paths() -> None:
    windows = fingerprint("P-01", Location(file="prompts\\system.txt"), BASE[2])

    assert fingerprint(*BASE) == windows


@pytest.mark.parametrize(
    ("check_id", "location", "evidence"),
    [
        ("P-02", BASE[1], BASE[2]),
        ("P-01", Location(file="prompts/other.txt"), BASE[2]),
        ("P-01", Location(file="prompts/system.txt", artifact="tool:x"), BASE[2]),
        ("P-01", BASE[1], "key = sk-****0000"),
    ],
)
def test_fingerprint_changes_when_the_issue_changes(
    check_id: str, location: Location, evidence: str
) -> None:
    assert fingerprint(*BASE) != fingerprint(check_id, location, evidence)
