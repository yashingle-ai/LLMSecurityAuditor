"""O-06 end to end: code blocks in logged replies, scanned with the generated-code rules.

The rules themselves are tested with `semgrep --test` (test_semgrep_rules.py).
"""

import json
import os
from pathlib import Path

import pytest

import llm_auditor.detectors  # noqa: F401  (registers the built-in checks)
from llm_auditor.audit import run_audit
from llm_auditor.checks import CheckRegistry, registry
from llm_auditor.detectors.code import semgrep_binary
from llm_auditor.detectors.generated_code import code_blocks
from llm_auditor.models import Access, AuditReport, AuditScope, CapabilityProfile, ScopeInputs

UNAVAILABLE = "llm_auditor.detectors.generated_code.semgrep_binary"


def audit(tmp_path: Path, *replies: str) -> AuditReport:
    runs = [
        {
            "messages": [
                {"role": "user", "content": "Can you help?"},
                {"role": "assistant", "content": reply},
            ]
        }
        for reply in replies
    ]
    (tmp_path / "run.jsonl").write_text("".join(json.dumps(r) + "\n" for r in runs))
    catalog = CheckRegistry()
    catalog.register(registry.get("O-06"))
    scope = AuditScope(
        name="o06",
        access=Access.WHITE,
        capability_profile=CapabilityProfile.neutral(),
        root=tmp_path,
        inputs=ScopeInputs(logs=["run.jsonl"]),
    )
    return run_audit(scope, checks=catalog)


@pytest.fixture
def semgrep() -> None:
    if semgrep_binary() is None:
        if os.environ.get("REQUIRE_SEMGREP") == "1":
            pytest.fail("semgrep is required (REQUIRE_SEMGREP=1) but not installed")
        pytest.skip("semgrep is not installed")


def test_code_blocks_in_languages_the_rules_cover() -> None:
    reply = (
        "Try:\n```python\nprint(1)\n```\nor\n```js\nconsole.log(1)\n```\n"
        "```bash\nls\n```\n```\nno language\n```"
    )

    assert code_blocks(reply) == [(".py", "print(1)\n"), (".js", "console.log(1)\n")]


@pytest.mark.usefixtures("semgrep")
def test_insecure_code_in_replies_is_reported(tmp_path: Path) -> None:
    report = audit(
        tmp_path,
        "Like this:\n```python\nimport subprocess\n\n\ndef count(name):\n"
        '    subprocess.run(f"wc -l {name}", shell=True)\n```',
        "Parse it with:\n```python\nimport yaml\n\n\ndef load(text):\n"
        "    return yaml.load(text)\n```",
        "Like this:\n```python\nimport subprocess\n\n\ndef count(name):\n"
        '    subprocess.run(f"wc -l {name}", shell=True)\n```',
    )

    assert sorted(f.title for f in report.findings) == [
        "Deserializes data in a way that can run code, in code the model wrote (1 run)",
        "Runs a shell command built from a variable, in code the model wrote (2 runs)",
    ]
    shell = next(f for f in report.findings if "shell" in f.title)
    assert shell.evidence == 'subprocess.run(f"wc -l {name}", shell=True)'


@pytest.mark.usefixtures("semgrep")
def test_safe_code_is_not_reported(tmp_path: Path) -> None:
    report = audit(
        tmp_path,
        "```python\nimport subprocess\n\n\ndef count(name):\n"
        '    subprocess.run(["wc", "-l", name], check=True)\n```',
    )

    assert report.coverage.ran == ("O-06",)
    assert not report.findings


def test_without_semgrep_code_blocks_skip_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(UNAVAILABLE, lambda: None)

    report = audit(tmp_path, "```python\nprint(1)\n```")

    assert [s.check_id for s in report.coverage.skipped] == ["O-06"]


def test_replies_without_code_need_no_semgrep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(UNAVAILABLE, lambda: None)

    report = audit(tmp_path, "No code here.")

    assert report.coverage.ran == ("O-06",)
    assert not report.findings
