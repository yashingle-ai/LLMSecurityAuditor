"""Run `semgrep --test` over the C-check rules and their annotated test files."""

import os
import re
import subprocess
from pathlib import Path

import pytest

from llm_auditor.detectors.code import semgrep_binary
from llm_auditor.rules import GENERATED_CODE_RULES_DIR, SEMGREP_RULES_DIR

TESTS = Path(__file__).parents[1]
# Each rule directory, and the directory of annotated test files for it.
RULE_SETS = [
    pytest.param(SEMGREP_RULES_DIR, TESTS / "semgrep", id="code"),
    pytest.param(GENERATED_CODE_RULES_DIR, TESTS / "semgrep_generated", id="generated-code"),
]


@pytest.mark.parametrize(("rules", "rule_tests"), RULE_SETS)
def test_semgrep_rules_pass_their_tests(rules: Path, rule_tests: Path) -> None:
    binary = semgrep_binary()
    if binary is None:
        if os.environ.get("REQUIRE_SEMGREP") == "1":
            pytest.fail("semgrep is required (REQUIRE_SEMGREP=1) but not installed")
        pytest.skip("semgrep is not installed")
    command = [
        binary,
        "--test",
        "--metrics=off",
        "--disable-version-check",
        "--config",
        str(rules),
        str(rule_tests),
    ]

    result = subprocess.run(  # noqa: S603  (fixed arguments; no shell)
        command, capture_output=True, text=True, timeout=600, check=False
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(("rules", "rule_tests"), RULE_SETS)
def test_every_rule_has_positive_and_negative_cases(rules: Path, rule_tests: Path) -> None:
    files = {p.stem: p for p in rule_tests.iterdir() if p.suffix in (".py", ".js", ".ts")}
    assert sorted(p.stem for p in rules.glob("*.yaml")) == sorted(files)
    for path in files.values():
        text = path.read_text(encoding="utf-8")
        for rule_id in re.findall(r"^\s*- id: (\S+)", (rules / f"{path.stem}.yaml").read_text()):
            positives = len(re.findall(rf"(#|//) ruleid: {rule_id}\b", text))
            negatives = len(re.findall(rf"(#|//) ok: {rule_id}\b", text))
            assert positives >= 2 and negatives >= 2, (rule_id, positives, negatives)
