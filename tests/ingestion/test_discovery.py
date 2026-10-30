from pathlib import Path

import pytest

from llm_auditor.ingestion import base
from llm_auditor.ingestion.discovery import discover, relative_path
from llm_auditor.ingestion.source import SourceLoader
from llm_auditor.ingestion.traces import TraceLoader

FIXTURES = Path(__file__).parents[1] / "fixtures" / "ingestion"
SOURCE = SourceLoader.extensions


def names(files: list[Path], root: Path = FIXTURES) -> list[str]:
    return [relative_path(file, root) for file in files]


def test_a_file_entry_is_taken_as_is() -> None:
    assert names(discover(FIXTURES, "source/README.txt", SOURCE)) == ["source/README.txt"]


def test_directories_are_walked_for_matching_files_skipping_dependencies() -> None:
    assert names(discover(FIXTURES, "source", SOURCE)) == ["source/app.py", "source/web/client.ts"]


def test_glob_patterns_match_relative_to_the_root() -> None:
    files = discover(FIXTURES, "traces/anth*.jsonl", TraceLoader.extensions)

    assert names(files) == ["traces/anthropic.jsonl"]


def test_recursive_globs() -> None:
    assert names(discover(FIXTURES, "source/**/*.ts", SOURCE)) == ["source/web/client.ts"]


def test_absolute_entries_ignore_the_root() -> None:
    absolute = str(FIXTURES / "prompts" / "system.txt")

    assert discover(Path("/nonexistent"), absolute, frozenset()) == [Path(absolute)]


def test_entries_that_match_nothing_give_no_files() -> None:
    assert discover(FIXTURES, "missing/*.jsonl", TraceLoader.extensions) == []


def test_symlinks_are_not_followed_when_walking(tmp_path: Path) -> None:
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(FIXTURES / "source" / "app.py")

    assert names(discover(tmp_path, ".", SOURCE), tmp_path) == ["real.py"]


def test_paths_outside_the_root_stay_absolute(tmp_path: Path) -> None:
    file = tmp_path / "x.py"

    assert relative_path(file, FIXTURES) == file.resolve().as_posix()


def test_oversized_files_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "MAX_FILE_BYTES", 10)
    file = tmp_path / "big.txt"
    file.write_text("x" * 11, encoding="utf-8")
    report = base.IngestReport()

    assert base.read_text(file, "big.txt", report) is None
    assert "larger than" in report.issues[0].message
