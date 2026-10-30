import json
from pathlib import Path

import pytest

from llm_auditor.ingestion import IngestReport
from llm_auditor.ingestion.dependencies import DependencyFileLoader, parse_requirement
from llm_auditor.ingestion.model_files import ModelFileLoader
from llm_auditor.models import DependencyFile, IngestIssue, ModelFile


def load(tmp_path: Path, name: str, text: str) -> tuple[list[DependencyFile], list[IngestIssue]]:
    file = tmp_path / name
    file.write_text(text, encoding="utf-8")
    report = IngestReport()
    artifacts = DependencyFileLoader().load(file, name, report)
    return [a for a in artifacts if isinstance(a, DependencyFile)], report.issues


def pins(files: list[DependencyFile]) -> dict[str, str | None]:
    return {d.name: d.version for f in files for d in f.dependencies}


@pytest.mark.parametrize(
    ("text", "name", "version"),
    [
        ("langchain==0.0.150", "langchain", "0.0.150"),
        ("LangChain[openai] == 0.1.0 ; python_version >= '3.9'  # pinned", "LangChain", "0.1.0"),
        ("transformers===4.30.0", "transformers", "4.30.0"),
        ("transformers>=4.30,<5", "transformers", None),
        ("gradio", "gradio", None),
    ],
)
def test_parse_requirement(text: str, name: str, version: str | None) -> None:
    dependency = parse_requirement(text)

    assert dependency is not None
    assert (dependency.name, dependency.version) == (name, version)


@pytest.mark.parametrize(
    "text",
    ["", "# a comment", "-r base.txt", "--index-url https://pypi.example.com", "git+https://x/y"],
)
def test_parse_requirement_skips_options_and_urls(text: str) -> None:
    assert parse_requirement(text) is None


def test_requirements_keep_line_numbers(tmp_path: Path) -> None:
    text = "# tools\n-r requirements.txt\nlangchain==0.0.150\n\nfastapi>=0.110\n"

    [file], issues = load(tmp_path, "requirements-dev.txt", text)

    assert file.ecosystem == "PyPI"
    assert [(d.name, d.version, d.line) for d in file.dependencies] == [
        ("langchain", "0.0.150", 3),
        ("fastapi", None, 5),
    ]
    assert issues == []


def test_pyproject_reads_dependencies_and_extras(tmp_path: Path) -> None:
    text = """
[project]
name = "bot"
dependencies = ["langchain==0.0.150", "httpx>=0.27"]

[project.optional-dependencies]
ml = ["transformers==4.30.0"]
"""
    files, _ = load(tmp_path, "pyproject.toml", text)

    assert pins(files) == {"langchain": "0.0.150", "httpx": None, "transformers": "4.30.0"}


@pytest.mark.parametrize("name", ["uv.lock", "poetry.lock"])
def test_python_lockfiles_pin_everything(tmp_path: Path, name: str) -> None:
    text = '[[package]]\nname = "langchain"\nversion = "0.0.150"\n\n[[package]]\nname = "x"\n'

    files, _ = load(tmp_path, name, text)

    assert pins(files) == {"langchain": "0.0.150"}  # entries without a version are skipped


def test_package_json_counts_only_exact_versions_as_pinned(tmp_path: Path) -> None:
    data = {
        "dependencies": {"langchain": "0.0.200", "@langchain/core": "^0.1.0"},
        "devDependencies": {"@modelcontextprotocol/sdk": "1.0.0-beta.1"},
    }

    files, _ = load(tmp_path, "package.json", json.dumps(data))

    assert files[0].ecosystem == "npm"
    assert pins(files) == {
        "langchain": "0.0.200",
        "@langchain/core": None,
        "@modelcontextprotocol/sdk": "1.0.0-beta.1",
    }


def test_package_lock_reads_nested_packages(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "bot"},
            "node_modules/langchain": {"version": "0.0.200"},
            "node_modules/langchain/node_modules/@langchain/core": {"version": "0.1.0"},
        },
    }

    files, _ = load(tmp_path, "package-lock.json", json.dumps(data))

    assert pins(files) == {"langchain": "0.0.200", "@langchain/core": "0.1.0"}


@pytest.mark.parametrize(
    ("name", "text", "message"),
    [
        ("notes.txt", "langchain==0.0.150", "not a recognized dependency file"),
        ("package.json", "{", "could not parse"),
        ("pyproject.toml", "[project", "could not parse"),
    ],
)
def test_unusable_files_are_reported(tmp_path: Path, name: str, text: str, message: str) -> None:
    files, issues = load(tmp_path, name, text)

    assert files == []
    assert [issue.path for issue in issues] == [name]
    assert message in issues[0].message


def test_model_files_are_identified_by_extension(tmp_path: Path) -> None:
    loader, report = ModelFileLoader(), IngestReport()
    for name in ("classifier.pkl", "checkpoint.PT", "weights.safetensors", "notes.md"):
        (tmp_path / name).write_bytes(b"1234")

    found = [
        artifact
        for name in ("classifier.pkl", "checkpoint.PT", "weights.safetensors", "notes.md")
        for artifact in loader.load(tmp_path / name, name, report)
    ]

    assert found == [
        ModelFile(path="classifier.pkl", format="pickle", size_bytes=4),
        ModelFile(path="checkpoint.PT", format="pytorch", size_bytes=4),
        ModelFile(path="weights.safetensors", format="safetensors", size_bytes=4),
    ]
    assert [issue.path for issue in report.issues] == ["notes.md"]
