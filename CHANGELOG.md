# Changelog

## [Unreleased]

### Demo attacks for every runtime check

- New conversations in the demo traffic, where the attack arrives in what the agent reads:
  - the returns help page's white text (T-03, confirming P-08)
  - an attacker's web page that gets an invoice emailed out (T-07) and a tracking image into the reply (O-05)
  - an email in the support inbox that gets a note saved to memory (T-16) and the account deleted (T-05, and T-01 in the logs)
  - a customer getting the agent to reply with HTML for the widget (O-04)
- The hardened app blocks each one: its filters stop the inbox email and the HTML request, its `fetch_url` refuses the attacker's site, and its help page has no hidden text.
- Demo apps: a `save_memory` tool, and an attacker's email in the support inbox.
- `scripts/generate_traffic.py` serves `fetch_url` from a fixed set of pages, so generating traffic never touches the network.
- Ground truth: GT-042 to GT-048. The vulnerable app now has 48 planted flaws.
- T-03 confirms a P-08 finding that quotes the same instructions, so a hidden instruction in a document links to the logged run where the model obeyed it.
- Fixes:
  - P-07 confirmed O-03 for any successful attack. It now does so only when the model's reply reproduced the system prompt.
  - The injection classifier read a tool's report of a sent email ("Email 'Invoice' sent to x@y") as an instruction to send data out.
- T-08's runaway loop isn't in the demo traffic: the scripted model never repeats a call within a turn. It stays covered by trace fixtures.

### Demo site and guide

- `demo/showcase`: a local demo site (`uv run python -m demo.showcase`, then open http://127.0.0.1:8000). It has four tabs:
  - Audit the demo apps: runs the real auditor on the vulnerable and hardened apps. Results include severity tiles, the planted flaws found against the ground truth, a side-by-side comparison, and the attacks seen in the logs with their outcomes. Findings can be filtered and opened for evidence, severity factors, confidence and the fix, with links between findings. The tool inventory and coverage are shown too, and each report downloads as JSON, Markdown or SARIF.
  - Try the detectors: the injection classifier, hidden-text extraction, and personal-data and secret detection on pasted text, with harmless examples
  - Check catalog: every check, with its OWASP mappings
  - How it works: the pipeline, finding kinds, severity, trust boundaries
- The site answers only to localhost and audits only the two demo apps. It sends a strict Content Security Policy (no inline script, styles or images) and never renders report text as HTML. Pasted text is shown redacted.
- `documentation/PROJECT_EXPLAINED.md`: the project from the ground up: the problem, key ideas, how an audit runs, how the detectors work, all 48 checks, a tour of the code, how it's tested, what's next, and a glossary
- `documentation/DEMO_GUIDE.md`: setup, a 12-minute demo script, the auditor's inputs, how to read results, likely audience questions, troubleshooting, and how the site's frontend and backend work

### Stage 8: Output and agent-trace auditor

- Hidden-content extractors (`llm_auditor.extractors`):
  - HTML: CSS-hidden, white, tiny and off-screen text, class rules in `<style>`, comments, `alt`/`title`/`aria-label`, meta tags, hidden inputs
  - Markdown: comments and inline HTML
  - DOCX: hidden, white and tiny runs, tracked deletions, comments, properties; parsed with defusedxml, oversized parts refused
  - PDF: white text (unless on a dark fill), tiny text, invisible render modes, off-page text, metadata
  - Unicode tag characters in any text
- New input: `documents` (HTML, Markdown, text, PDF, DOCX): what the app retrieves.
- Injection classifier (`llm_auditor.classifiers`):
  - the default is built-in weighted rules: deterministic, with no download
  - two channels: the app's own user, and third-party content (where any instruction to the model is suspect)
  - `injection_classifier` in the scope picks a local Hugging Face model instead
- Incidents have an outcome (`succeeded`, `failed` or `unknown`) with a one-line reason from the log.
- The incident summary counts each outcome per check. The Markdown report lists the attacks that succeeded, and the terminal summary counts them.
- Evidence linking:
  - A succeeded incident or a vulnerability confirms the findings it corroborates. For example, a logged SQL injection that worked confirms C-03.
  - Confirmed weaknesses become vulnerabilities.
  - Both sides list each other under `related`.
- Checks:
  - **P-07:** injection attempts in user messages (incident)
  - **P-08:** instructions hidden in, or written into, retrieved documents
  - **O-01 / O-02:** personal data and secrets in replies. A secret the model was given (in the prompt or a tool result) appearing in a reply is a vulnerability.
  - **O-03:** system prompt leaks, from canary tokens (`canaries` in the scope) or shingle overlap with the logged prompt
  - **O-04:** HTML, SQL or shell payloads in replies. A vulnerability when the code passes replies to that sink unescaped.
  - **O-05:** images and links carrying conversation data out, terminal escapes, spreadsheet formulas
  - **O-06:** insecure code in replies, scanned with a second Semgrep rule set (`rules/semgrep_generated/`)
  - **A-06:** personal data stored unredacted in logs
  - **T-02:** SQL, command, path and SSRF payloads in tool arguments (incident). The outcome is read from the tool's result.
  - **T-03:** injection in tool results, including hidden HTML (incident)
  - **T-04:** personal data and secrets in tool results
  - **T-05 / T-07 / T-16:** taint tracking (as is, URL-encoded, base64) from outside content into code, file, destructive and financial tools, from private data into outbound tools, and from outside content into memory. A new `writes_memory` capability supports T-16.
  - **T-01** now also reports destructive and financial calls that ran in logs with no approval.
  - **T-08** now also reports runaway loops in logs.
  - **T-11** also asks the injection classifier about tool descriptions.
- Demo apps:
  - a `knowledge_base/` per app, with an instruction hidden in white text on the vulnerable app's returns page
  - the hardened `invoice_report` rejects a status outside its allowed values
  - Ground truth: GT-003 is enabled, and GT-036 to GT-041 are added.
- Fixes:
  - T-02 counted any result that wasn't an error as a successful attack. An empty result ("No matching invoices.") now counts as failed.
  - Personal data of two kinds on one line was merged into one finding.

### Stage 7: Config, guardrail, and supply-chain auditor

- Attestations: answers in the scope file for what code can't show. A check missing an answer is skipped, and its reason names the questions to answer. Findings from answers use `oracle: attestation`.
- New inputs:
  - `dependency_files`: requirements files, `pyproject.toml`, `uv.lock`, `poetry.lock`, `package.json`, `package-lock.json`
  - `model_dirs`: model weights, identified by extension
- Checks:
  - **A-02:** LLM endpoints with no authentication, from OpenAPI security requirements and HAR captures
  - **A-03:** output token limit off or missing, no rate limit, model calls logged without `max_tokens`
  - **A-04:** plain HTTP to public hosts in configs and HAR, TLS verification turned off
  - **A-05:** stack traces or exception messages returned to callers, debug mode, stack traces in HAR error responses
  - **A-07:** models pinned to `latest`, `trust_remote_code=True`
  - **A-08:** vector searches with no tenant filter (Semgrep; multi-tenant targets only)
  - **A-09:** tool-call audit logging turned off or missing
  - **A-10:** provider retention, training on your data, key scope, key rotation, spend limit (attestations)
  - **T-15:** admin-scoped or never-expiring agent credentials, from config or attestations
  - **G-01:** a boundary with no guardrail: the model's output always, and tool results when a tool ingests untrusted content
  - **G-02:** guardrails in monitor or log-only mode
  - **SC-01:** pickle model files that import code-running functions. The opcode scanner never unpickles anything, follows memoized names, and reads the pickles inside PyTorch archives.
  - **SC-02:** LLM framework versions with known vulnerabilities, against a bundled offline OSV snapshot
  - **SC-03:** MCP servers installed unpinned (`npx -y`, `uvx`, `pnpm dlx`, untagged images) or reached over plain HTTP
- `llmaudit advisories update [--out PATH]` fetches a fresh OSV snapshot. `advisory_db` in the scope file points an audit at it.
- Planner: checks that read attestations always run, so a skip names the missing answers instead of "none were provided".
- `configs/audit_scope.hardened.yaml`: a scope for the hardened demo app. Each demo app now has its own scope, and its own attestations.
- Demo app:
  - an unauthenticated `/v1/complete` endpoint
  - `max_tokens` turned off
  - stack traces in error responses
  - `model: latest` over plain HTTP
  - a shared note index searched without a tenant filter (`search_notes`)
  - no audit log
  - an admin-scoped, never-expiring billing token
  - an injection filter on user input only, in monitor mode
  - old LangChain and Transformers pins
  - a pickle model that imports `os.system`
  - an unpinned `npx -y` MCP server
  - The hardened app fixes each one. It also has a per-user rate limit, and its injection filter now blocks on user input, tool results and model output.
- Fix: the demo's injection filter never ran, because YAML 1.1 reads a bare `on:` key as `true`. The demo key is now `apply_to:`, and the guardrail inventory accepts both.
- Deferred: A-02's live request to a configured target waits for Stage 10's probe engine and safety layer.

### Stage 6: Tool and MCP auditor

- Tool inventory (`llm_auditor.inventory`): every tool the agent can call, from tool files and logs, with inferred capabilities and the reason for each. It appears in every report (JSON and Markdown) and in `llmaudit tools inventory`. `capability_overrides` in the scope file corrects a tool.
- A coverage note when the tools grant capabilities the scope's `capability_profile` doesn't list, since severity would be understated
- Tool lockfile: `llmaudit tools lock` approves the current definitions. `tool_lock` in the scope sets where the lockfile lives.
- Checks:
  - **T-09:** excessive permissions (shell, any URL, any recipient, any path)
  - **T-10:** the lethal trifecta
  - **T-11:** tool poisoning (imitation system markup, steps before use, hiding things from the user, credential files, hidden text, references to other tools)
  - **T-12:** definitions changed since approval, and tools not yet approved
  - **T-13:** duplicate, look-alike, and mixed-script tool names
  - **T-01:** destructive or financial tools without approval in the agent config
  - **T-08:** no step limit, or one turned off
  - **T-18:** code sandbox gaps in Docker Compose services
- Demo app:
  - new tools: `read_inbox`, `send_email`, `run_shell` (vulnerable only), `run_python`, and `delete_account`
  - an `agent.yaml` the agent loop actually loads, for the step limit and approvals
  - a sandbox Compose file, and an MCP config
  - a deliberately malicious stdio MCP server (`demo/malicious_mcp_server/`) with a rug-pulled, poisoned tool and a look-alike tool name
  - its captured `tools/list` output and a lockfile from before the rug pull
  - the hardened app now holds approval-required tools until the customer confirms
- Fix: three source files contained literal invisible or look-alike characters, decoded from `\u` escapes. They're now ASCII escapes, and the codebase is checked for them.
- Deferred: opt-in live MCP listing (`--mcp-live`) waits for Stage 10's sandbox and allow-list layer, because starting a server runs a command from a config file.

### Stage 5: Code and template auditor

- Semgrep taint rules for C-01 to C-06, shipped in `src/llm_auditor/rules/semgrep/`:
  - **C-01:** user input in the system prompt
  - **C-02:** model output to code or shell execution
  - **C-03:** model output to SQL
  - **C-04:** model output to raw HTML
  - **C-05:** model output to a file path or URL
  - **C-06:** a tool handler with no ownership check
- How the rules run: one Semgrep run per audit with `--metrics=off`. Without Semgrep, the C-checks are skipped with an install hint.
- P-03: untrusted template variables with no delimiters
- `semgrep --test` cases for every rule (`tests/semgrep/`), run by pytest. CI installs a pinned Semgrep and sets `REQUIRE_SEMGREP=1`.
- Demo app: seven new planted flaws, each with a hardened fix and a test showing it is exploitable:
  - a customer note pasted into the system prompt
  - an `eval` calculator
  - SQL injection through the report tool
  - a raw-HTML widget
  - `fetch_url` with no host restriction
  - `get_invoice` with no ownership check
  - an undelimited hand-off template

### Stage 4: First vertical slice

- Check framework: a check reports `Detection`s, and the runner redacts, scores, fingerprints, deduplicates, and numbers them. A crashing check is reported as failed; a check that can't run is reported as skipped.
- Checks:
  - **P-01:** secrets in prompts
  - **A-01:** keys in code, configs, logs, and HTTP traffic, one finding per secret per file
  - **P-02:** personal data in prompts (pattern-based)
  - **P-09:** hidden text: Unicode tags, zero-width and bidirectional characters, base64-encoded instructions, mixed-script words. In logs these are reported as incidents.
- Secret formats as a YAML rule pack, shared by redaction and the checks
- Reports: JSON (canonical, loads back losslessly), Markdown (summary, findings, hardening, incidents, coverage and limitations), and SARIF 2.1.0 (validated against the official schema in the tests)
- `llmaudit scan --scope … [--format] [--out] [--fail-on]` and `llmaudit scan prompts DIR`
- Ground-truth harness runs real audits: one test per planted flaw, plus "the hardened app has no findings"
- Demo app: an API key in the browser widget, a customer's contact details in a prompt example, and an instruction hidden in the FAQ with Unicode tag characters

### Stage 3: Ingestion and normalization

- `llm_auditor.ingestion`: loaders for every input kind:
  - **traces:** OpenAI chat and Anthropic Messages, flat or request/response; custom formats through a field mapping
  - **HAR:** LLM calls also become Interactions
  - **OpenAPI 3**
  - **tool definitions:** OpenAI, Anthropic, MCP, including captured `tools/list` responses
  - **MCP client configs:** static only; servers are never started
  - **prompts:** with template variables
  - **source files**
  - **config files:** YAML, JSON, TOML, `.env`
- Discovery of files, directories and globs, skipping dependency/cache directories and symlinks, with a 10 MiB per-file limit
- Malformed input is reported as an issue and skipped, never raised
- `AuditContext.plan()`: which checks can run, and why the others are skipped (access level, missing inputs)
- `llm_auditor.redaction`: secret and PII redaction for everything displayed or written
- `llmaudit ingest --scope <file> [--dump]`. Audited content is redacted and stripped of markup and control codes before display.
- Model changes:
  - `CheckMeta.required_inputs` is now `inputs`, and a check runs when any one of them is available
  - `Interaction.response` is removed; the final output is the last assistant message
  - `Interaction` gains `user` and `conversation_id`
  - `AuditScope` gains `root`
  - log entries can set `format` and `mapping`

### Stage 2: Ground-truth demo apps

- `demo/vulnerable_app` and `demo/hardened_app`: a FastAPI support agent with two users, invoice and billing tools, and JSONL traces in OpenAI chat format. The apps' code is identical; only planted flaws differ.
- First planted flaw: a billing API key in the vulnerable app's system prompt (`GROUND_TRUTH.yaml`: GT-001, plus its consequences in logs and replies, GT-002 and GT-003)
- LLM backends: a deterministic, deliberately gullible scripted model (default) and any OpenAI-compatible API (`LLM_BACKEND=real`)
- `scripts/generate_traffic.py`: deterministic benign and attack traffic fixtures, with a staleness test
- Ground-truth harness in `tests/groundtruth/` (passes trivially until Stage 4 enables entries)
- New `demo` dependency group (FastAPI, uvicorn, httpx2), installed by default

### Stage 1: Core domain model and threat model

- Data models in `llm_auditor.models`: `Finding` (separate severity and confidence, finding kinds, ASR, repro, lifecycle status), `Interaction` (ordered messages with tool calls and results), `AuditScope` (access level, capability profile, allow-listed target), `CheckMeta`
- Check registry (`llm_auditor.checks`) and `llmaudit checks list`
- Deterministic, explainable severity engine driven by the target's capability profile (rubric v1)
- Stable finding fingerprints that ignore line shifts and whitespace
- `configs/audit_scope.example.yaml`
- Docs: `THREAT_MODEL.md`, `SEVERITY.md`

### Stage 0: Project setup

- Python package `llm-auditor` (src layout) with the `llmaudit` CLI and a `version` command
- Tooling: uv, Ruff (lint + format), mypy (strict), pytest, pre-commit
- GitHub Actions CI on Python 3.11 and 3.12
