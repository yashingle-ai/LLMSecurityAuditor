# LLM Security Auditor

An agent that audits LLM-powered applications for security vulnerabilities: their prompts, model outputs, tool calls and tool outputs, and API interactions. It produces prioritized reports mapped to the OWASP Top 10 for LLM and Agentic Applications.

> **Status:** early development. Stages 0–8 of the [implementation stages](documentation/IMPLEMENTATION_STAGES.md) are done: 48 checks. The static checks cover prompts, secrets, personal data, hidden text, how application code handles model input and output, the tools and MCP servers an agent can use, deployment and provider settings, guardrails, and supply chain (model files, dependencies, MCP installs). The runtime checks read logged conversations and documents. They cover prompt injection (with whether it worked), leaked system prompts, secrets and personal data in replies and tool results, links that carry data out, insecure generated code, and data flowing between tools. Nothing is sent to a model or a live endpoint yet.

## Authorized use only

Only run this tool against systems you own or have explicit written permission to test. Later stages add active probing, which sends attack payloads to live endpoints.

## Demo

```bash
uv run python -m demo.showcase      # then open http://127.0.0.1:8000
```

The demo site audits two versions of the same AI support agent in your browser: one with 48 flaws planted on purpose, and one with every flaw fixed. It shows each finding with its evidence and fix, the attacks seen in the logs and whether they worked, and a panel for trying the detectors on your own text. The [demo guide](documentation/DEMO_GUIDE.md) covers setup, a step-by-step walkthrough, what to give the auditor, and how to read the results.

## Usage

Describe what to audit in a scope file (see [configs/audit_scope.example.yaml](configs/audit_scope.example.yaml)), then:

```bash
uv run llmaudit scan --scope configs/audit_scope.example.yaml   # writes reports/report.{json,md,sarif}
uv run llmaudit scan --scope my-scope.yaml --fail-on high       # exit status 1 on high or critical findings
uv run llmaudit scan prompts ./prompts/                         # quick scan, no scope file needed
uv run llmaudit checks list                                     # the check catalog
uv run llmaudit tools inventory --scope my-scope.yaml           # each tool and what it can do
uv run llmaudit tools lock --scope my-scope.yaml                # approve tool definitions (T-12)
uv run llmaudit advisories update                               # refresh known vulnerabilities (SC-02)
uv run llmaudit ingest --scope my-scope.yaml --dump             # what the auditor loaded
```

Some facts can't be read from code or config, such as how long your LLM provider keeps prompts or whether keys rotate. Answer them under `attestations:` in the scope file. A check missing an answer is skipped and names the questions, so a gap never looks like a pass.

Dependencies are checked against a snapshot of [OSV](https://osv.dev) advisories bundled with the auditor, so audits work offline and give the same answer every time. `llmaudit advisories update` writes a fresh one to `.llmaudit/advisories.json`; set `advisory_db` in the scope file to use it.

Reports come in three formats: JSON (complete, machine-readable), Markdown (for people), and SARIF (for GitHub code scanning). Each one says which checks ran, which were skipped and why, and what couldn't be loaded. Secrets and personal data are redacted everywhere they appear.

## Development setup

Requires [uv](https://docs.astral.sh/uv/). uv installs a suitable Python (3.11+) if needed.

```bash
uv sync                      # create .venv and install dependencies
uv tool install semgrep      # used by the code checks (C-01 to C-06)
uv run llmaudit version      # check the CLI works
uv run pre-commit install    # optional: lint and type-check on every commit
```

Semgrep is installed as a separate tool rather than a project dependency, because its pinned dependencies clash with this project's. If `uv tool install` warns that `~/.local/bin` is not on your PATH, run `uv tool update-shell` once, or set `LLMAUDIT_SEMGREP` to the full path of the `semgrep` executable. Without Semgrep, the code checks are skipped, and the Semgrep-dependent tests are skipped too.

The same checks CI runs:

```bash
uv run ruff check
uv run ruff format --check
uv run mypy
REQUIRE_SEMGREP=1 uv run pytest   # fail, rather than skip, if Semgrep is missing
```

## Documentation

- [The project, explained](documentation/PROJECT_EXPLAINED.md): the problem, the key ideas, how an audit runs, and a tour of the code. Start here.
- [Project plan](documentation/PROJECT_PLAN.md): what we are building and why
- [Plan review](documentation/PLAN_REVIEW.md): gaps found from an auditor's point of view
- [Implementation stages](documentation/IMPLEMENTATION_STAGES.md): the build order, and the source of truth
- [Threat model](documentation/THREAT_MODEL.md) and [severity rubric](documentation/SEVERITY.md)
- [Demo target apps](demo/README.md): the deliberately vulnerable app the auditor is measured against
- [Demo guide](documentation/DEMO_GUIDE.md): how to run and present the demo, and how to read the results
