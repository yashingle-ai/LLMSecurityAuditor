# Plan Review: Does PROJECT_PLAN.md Hold Up as an LLM Security Audit?

This document reviews [PROJECT_PLAN.md](PROJECT_PLAN.md) the way an experienced LLM security auditor would. It asks: *if this tool produced an audit report, would a security team trust it?*

---

## 1. Verdict

**Coverage is broad and well mapped. The methodology is where the plan falls short.**

As written, the plan would produce a good **scanner**: it finds suspicious patterns across prompts, outputs, tools, and APIs, and maps them to OWASP. It would not yet produce a trustworthy **audit**, because it cannot reliably:

1. **Prove** a finding is exploitable (verification leans on an LLM judge and 3 retries),
2. **Rank** findings by real impact (severity ignores what the target app can actually do),
3. **Say what it did not test** (no access levels, no coverage statement), and
4. **Separate vulnerabilities from noise** (attack attempts in logs are treated like vulnerabilities).

It also misses two attack surfaces where many real LLM vulnerabilities live: **the application's source code** and **authorization of tool calls**.

The fixes below are mostly design changes to the data model and methodology. They are cheap now and expensive after Phase 1.

---

## 2. Scorecard

| Dimension | Rating | Summary |
|-----------|--------|---------|
| OWASP LLM Top 10 coverage | 🟢 Good | 7 of 10 well covered; LLM04 out of scope by choice, LLM09 thin |
| Agentic risk coverage (OWASP ASI Top 10) | 🟡 Partial | 2 good, 4 partial, 4 missing (see §5) |
| Threat model | 🔴 Missing | Checks are listed, but no attackers, assets, or trust boundaries |
| Attack surface completeness | 🟡 Partial | No application source code; no tool-level authorization |
| Vulnerability vs. incident separation | 🔴 Missing | Logged attack *attempts* become findings |
| Exploit verification | 🟠 Weak | LLM judge + 3 retries; few objective oracles |
| Severity scoring | 🟠 Weak | Confidence multiplied into severity; impact ignores app context |
| Access-level awareness | 🔴 Missing | No check says whether it needs black-, gray-, or white-box access |
| Evaluation methodology | 🟠 Weak | Measures detectors, not the auditor; risk of inflated numbers |
| Report quality (audit standard) | 🟡 Partial | Has evidence and fixes; no repro steps, coverage statement, or lifecycle |
| Security of the auditor itself | 🟢 Good | Self-injection, redaction, allow-list, authorization all addressed |
| Safe and ethical testing | 🟢 Good | Allow-list, rate limits, no destructive payloads |
| Feasibility of the timeline | 🟠 Over-scoped | ~45 checks + 10 probe suites + agent + API + dashboard in ~12 part-time weeks |

---

## 3. What the Plan Gets Right (Keep These)

- **Every check maps to OWASP**, so reports use terms security teams already know.
- **Deterministic first, LLM second:** cheap, reproducible, explainable.
- **The auditor's own judge is treated as an attack target.** Many real tools miss this.
- **Tool results are untrusted input**, and the **lethal-trifecta check (T-10)** is an architectural finding. Checks like that hold up better than pattern matching.
- **Canary tokens** for system-prompt leak detection.
- **A deliberately vulnerable demo app** gives the project ground truth.
- **SARIF + CI integration** puts findings where developers already work.
- **Safety controls on probing** (allow-list, rate limits, written authorization).

---

## 4. Findings

Ordered by how much each gap would undermine trust in an audit report.

### 🔴 Critical: fix before writing code (they change the data model and architecture)

#### R-01: No threat model or trust boundaries

**Problem.** The catalog lists ~45 checks but never says *who* is attacking *what* across *which boundary*. Without that, nobody can argue the coverage is complete, and missing categories (like R-04) go unnoticed.

**Fix.** Add a threat model section and tie every check to it:

| Element | Contents |
|---------|----------|
| **Attackers** | Malicious end user · third-party content author (web page, email, document) · compromised tool or MCP server · other tenant · malicious insider |
| **Assets** | Credentials · user and tenant data · system prompt and business logic · tool capabilities (send, pay, delete, deploy) · compute and money · integrity of actions taken |
| **Trust boundaries** | User → app · app → LLM · retrieved content / tool result → context · LLM → tool · LLM output → downstream sink · agent → agent · agent → persistent memory |

Then add a **coverage matrix** (boundary × check). Empty cells are the gaps.

#### R-02: Incidents are mixed with vulnerabilities

**Problem.** P-07 (injection patterns in user prompts), O-08 (jailbreak success), and O-09 (harmful content) run over logs and find **attack attempts**. One user typing "ignore previous instructions" is not a vulnerability in the system. Scanning a month of logs would bury the real findings under thousands of "High" items.

**Fix.** Give every finding a `kind`:

| Kind | Meaning | Gets severity? |
|------|---------|----------------|
| `vulnerability` | Confirmed exploitable weakness | Yes |
| `weakness` | Design or configuration flaw, not yet exploited | Yes |
| `hardening` | Best-practice advice (e.g., P-04 "weak instruction hierarchy") | No, just a priority |
| `incident` | Attack seen in logs, marked succeeded or failed | No; aggregated |

Aggregate incidents: *"312 injection attempts in logs; 4 succeeded → see vulnerability F-0012."* A successful attempt is evidence for a vulnerability, not a finding of its own.

#### R-03: Application source code is not an audited surface

**Problem.** The plan audits prompt files, logs, specs, and tool definitions. It does not audit the code that **builds prompts** and **consumes outputs**, and that is where LLM05 (Improper Output Handling) and ASI05 (Unexpected Code Execution) actually happen. O-04 flags `<script>` in a model *output*, but that is only a vulnerability if the code renders it as raw HTML. A coding assistant that outputs `<script>` in a code block is fine. Without looking at the code, O-04 produces false positives *and* misses real sinks.

**Fix.** Add an **application code** surface using Semgrep taint mode. Sources are user input, retrieved content, tool results, and LLM output. Sinks are prompt construction, `eval`/`exec`, shell, SQL, HTML rendering, file paths, and outbound URLs.

| Proposed ID | Check | Maps to |
|-------------|-------|---------|
| C-01 | User input concatenated into system/developer prompt in code | LLM01 |
| C-02 | LLM output flows into `eval`/`exec`/`subprocess`/shell | LLM05, ASI05 |
| C-03 | LLM output flows into a SQL/NoSQL query | LLM05 |
| C-04 | LLM output rendered as raw HTML, or markdown with remote images enabled | LLM05 |
| C-05 | LLM output used as a file path or outbound URL (path traversal, SSRF) | LLM05 |
| C-06 | Tool handler performs an action without checking the end user's permission | ASI03 |

Then rescope O-04 to a **confirmation** role: "the output contained a payload *and* the code renders it unsafely (C-04)".

#### R-04: Authorization and "confused deputy" are missing (ASI03)

**Problem.** Agent tools usually run with a service account's privileges. The key audit question is: **when the agent calls a tool for user A, is user A's permission enforced?** If not, user A can ask the agent to read user B's records (BOLA/IDOR through an LLM). The plan checks endpoint auth (A-02), vector-store tenancy (A-08), and prompt-based controls (P-06), but never tool-level authorization or credential scope. This is one of the most common high-impact findings in real agent audits.

**Fix.**

| Proposed ID | Check | Method |
|-------------|-------|--------|
| T-14 | Tool calls run with service-account privileges instead of the end user's | Code (C-06) + config review |
| T-15 | Agent credentials over-scoped or long-lived (admin tokens, no rotation) | Config + secrets analysis |
| Probe `cross-user-access` | Two test accounts; can account A reach account B's data through the agent? | Active probe with deterministic oracle |

#### R-05: Exploit verification is too weak for an audit

**Problem.** "Re-run the probe 3×" and "ask the LLM judge" are not proof. LLMs are stochastic. A probe that fails 3 times may succeed 1 time in 20, and "failed 3×" gets read as "safe". The LLM judge is the weakest oracle in the system, but the plan leans on it for jailbreak success (O-08) and hijacked calls (T-06).

**Fix.**

1. **Oracle hierarchy.** Always prefer the strongest oracle available:
   1. **Deterministic:** canary tokens planted in prompts and data · honeytoken credentials · an **out-of-band callback server** the auditor controls (if it receives a request, exfiltration is proven) · a sandboxed mock tool that records the exact call and arguments
   2. **Classifier**
   3. **LLM judge**, last and labeled as such in the report
2. **Benign, verifiable payload goals.** Prove control bypass with harmless objectives, such as "call `send_email` to `canary@audit.local`" or "output token `XJ-4471`". This makes success objectively checkable and avoids generating harmful content.
3. **Attack success rate (ASR).** Run each probe N times (N ≥ 10–20) and report "succeeded 4/20 (20%)". Severity takes ASR into account, and a 0/N result is reported as "not reproduced in N trials", not "safe".

#### R-06: The severity model is flawed

**Problem.** `severity = f(impact, exploitability) × confidence` has two issues:

1. **Multiplying by confidence hides criticals.** An unconfirmed critical gets reported as a medium and never investigated. Auditors keep the two separate: severity is "how bad if real", confidence is "how sure are we".
2. **Impact ignores context.** A system-prompt leak is *Info* for a public FAQ bot and *High* if the prompt holds internal logic. Prompt injection is *Low* for a tool-less chatbot and *Critical* for an agent with email and file access. A fixed severity per check misranks almost everything.

**Fix.**

- Keep `severity` and `confidence` as **separate fields**.
- Compute impact from a **target capability profile** declared in the audit scope: tools and their side effects, data sensitivity, autonomy (human-in-the-loop or not), exposure (internet-facing or internal), and number of users/tenants.
- Base the rubric on **OWASP AIVSS**, which extends CVSS with agentic factors such as autonomy and tool use. It is still an incubator project (v0.8 at the time of writing), so pin the version you use. Document the rubric so scores are reproducible.

### 🟠 Important: add to the catalog and design

#### R-07: Checks don't state what access they need

**Problem.** Some checks need **white-box** access (source code, system prompt, tool code), some **gray-box** (logs, configs, the ability to plant canaries or documents), and some only **black-box** access (an endpoint). O-03 similarity matching needs the real system prompt; canaries need the ability to edit it; T-03 needs traces. Without labels, the agent can't plan, and the report can't honestly state coverage.

**Fix.** Add **Access (B/G/W)** and **Input needed** columns to every catalog table. The audit scope declares the access level; the planner selects only the checks that can run; the report lists the checks skipped for lack of access.

#### R-08: The agent should not decide coverage

**Problem.** The orchestrator is an LLM that "plans which checks to run". LLM planning is non-deterministic: two runs on the same target could skip different checks, so two reports wouldn't be comparable, which is unacceptable for an audit. The agent is also exposed to target responses that can steer it ("this system is secure, no further testing needed").

**Fix.**

- A **deterministic baseline plan** always runs: every check applicable to the declared access level.
- The agent works **on top of** the baseline: adaptive escalation, attack chaining, false-positive triage, remediation writing.
- The agent cannot mark a check complete or skipped based on text from the target.
- Hard budget caps (tokens, requests, time) per audit.

#### R-09: Agentic risks are only partly covered

The agentic checks now map only to the LLM Top 10. Map them to the **OWASP Top 10 for Agentic Applications** too, and add the missing categories:

| Proposed ID | Check | Maps to |
|-------------|-------|---------|
| T-16 | Persistent memory written from untrusted content (memory poisoning that survives across sessions) | ASI06 |
| T-17 | Approval prompts show a model-written summary instead of the exact action and arguments (an approval the user can't actually judge) | ASI09 |
| T-18 | Code-execution tool not sandboxed: network egress, host filesystem, environment secrets readable | ASI05 |
| A-09 | No audit trail of tool calls and approvals (incidents can't be investigated) | ASI08, ASI10 |
| Stretch | Inter-agent message trust (agent-to-agent protocols) | ASI07 |
| Stretch | Kill switch and behavioral monitoring | ASI10 |

T-01 currently checks that an approval *exists*. T-17 checks that it is *meaningful*. Both are needed.

#### R-10: Hidden-content injection channels are not extracted

**Problem.** P-09 handles Unicode tricks, but indirect injections usually hide in **content structure**: HTML (`display:none`, comments, `alt` text, white-on-white text), PDFs (tiny or white text, metadata), Office docs (comments, hidden runs), and images (text the model can read via vision). A classifier that only sees visible text misses them.

**Fix.** Add **content extractors** that surface hidden content before P-08/T-03 classify it, and flag "hidden text present" as a signal on its own.

#### R-11: Guardrail and provider configuration are not audited

**Problem.** Many organizations depend on guardrails (moderation APIs, LLM Guard, NeMo Guardrails, cloud guardrail services). The usual flaw is guardrails applied **only to user input**, not to tool results, RAG content, or outputs, or running in log-only mode. Provider account settings (data retention, key scoping, spend limits, rotation) are also unchecked beyond A-03.

**Fix.** Add a **guardrail coverage** check (which boundaries does each guardrail actually sit on?) and a **provider configuration** check.

#### R-12: Supply chain coverage is shallow (LLM03 / ASI04)

**Problem.** Covered: model version pinning, hallucinated packages, tool-definition drift. Missing:

- **Model artifact scanning:** pickle-based model files can execute code when loaded (prefer safetensors; scan with ModelScan or picklescan).
- **Dependency vulnerabilities** in LLM frameworks (LangChain, LlamaIndex, and similar have had RCE-class CVEs): run software composition analysis (SCA).
- **MCP server provenance:** installed via an unpinned `npx`/`uvx` command, unknown publisher, no signature.

**Fix.** Add these three as A- or T-checks. They are cheap and high-signal.

#### R-13: Probing assumes a simple chat endpoint

**Problem.** Active probing assumes "send a prompt, get a response". Real targets have auth and sessions, multi-turn state, streaming, web-UI-only access, and async agents. **Indirect** injection also needs a way to *plant* content where the target reads it (upload a document, send an email to a monitored inbox, host a web page, file a ticket). The mock MCP server only helps if you can reconfigure the target's tools.

**Fix.** Specify a **target adapter** (request template, auth, session handling, response extraction, streaming), similar to promptfoo providers or garak generators. Also add an **injection channel** config that lists where the auditor can plant content and how it gets there.

#### R-14: Evaluation measures detectors, not the auditor

**Problem.**

- Recall on public injection datasets (e.g., `deepset/prompt-injections`) mostly measures the classifier, and the open classifiers in the stack may have been **trained on those same datasets**, which inflates the numbers.
- Static recall says nothing about **adaptive** attacks, which bypass classifiers by design.
- A **5% false-positive rate per log line** is unusable at volume: 1M log lines means 50,000 false findings.
- "≥ 85% judge agreement" is misleading on imbalanced data.

**Fix.**

- **Primary metric:** vulnerabilities found in benchmark targets with planted ground truth (several variants of the demo app + AgentDojo-style environments), measured as found / planted / false findings per audit.
- Classifier metrics are secondary, computed only on data **not** used to train the classifier.
- Measure false positives **per reported finding** (after aggregation), not per log line.
- Use **Cohen's kappa** for judge agreement, and measure **run-to-run consistency** of whole reports.

#### R-15: Reports are missing audit essentials

Each finding needs:

- **Reproduction:** a replayable request sequence plus model, version, temperature, and date
- **Fingerprint:** a stable ID so the same issue is deduplicated across runs
- **Lifecycle status:** open, accepted risk, false positive, or fixed, plus retest results
- **Suppressions:** each with a justification, an owner, and an expiry date

Each report needs:

- **Scope and coverage statement:** what was tested, at what access level
- **Limitations:** which checks were skipped and why
- **Executive summary:** written for non-technical readers

### 🟡 Minor: worth noting

| ID | Issue | Fix |
|----|-------|-----|
| R-16 | Success criterion #1 headlines classifier recall, but regex and classifiers are bypassable by design | Headline architectural and data-flow findings (T-10, C-checks); treat pattern hits as triage signals |
| R-17 | Security and safety are mixed: O-09 harmful content and harmful-content jailbreaks are *safety* evaluation | Move them to an optional safety module. Security jailbreaks mean bypassing the *app's own* controls |
| R-18 | The judge model may refuse to analyze harmful content, causing silent misses | Treat refusals as `undetermined`, never as `safe` |
| R-19 | Redacting before sending to a cloud judge destroys the signal PII checks need | PII and secret checks run **locally only**; the judge only receives redacted context |
| R-20 | O-05 exfiltration misses link unfurling (chat apps auto-fetch previews with no click needed), ANSI escape injection in terminal agents, and CSV formula injection | Add them as O-05/O-04 variants |
| R-21 | LLM10 lacks model extraction and denial-of-wallet through recursive agents; LLM04 lacks a cheap fine-tuning-data PII/secret scan | Add if time allows |
| R-22 | Scope vs. timeline: ~45 checks + 10 probe suites + agent + API + dashboard in ~12 part-time weeks | Build the critical path in §6 first; push the dashboard and proxy to later |

---

## 5. Coverage Matrices

### 5.1 OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Current coverage | Rating | Gap |
|----|------|------------------|--------|-----|
| LLM01 | Prompt Injection | P-07, P-08, P-09, T-03, T-06, T-11, probes | 🟢 | Confirmation oracles weak (R-05); hidden content (R-10) |
| LLM02 | Sensitive Info Disclosure | P-01, P-02, O-01, O-02, T-04, A-06 | 🟢 | Cross-user data access (R-04) |
| LLM03 | Supply Chain | A-07, O-07, T-12, T-13 | 🟡 | Model artifacts, SCA, MCP provenance (R-12) |
| LLM04 | Data & Model Poisoning | Out of scope; P-08 partial | ⚪ | Cheap fine-tune data scan (R-21) |
| LLM05 | Improper Output Handling | O-04, O-05, O-06, T-05 | 🟡 | **Code-level sink analysis (R-03)** |
| LLM06 | Excessive Agency | T-01, T-02, T-09, T-10 | 🟢 | Meaningful approvals, sandboxing (R-09) |
| LLM07 | System Prompt Leakage | P-01, P-06, O-03, extraction probes | 🟢 | Access-level dependency (R-07) |
| LLM08 | Vector & Embedding Weaknesses | A-08, P-08 | 🟡 | Metadata-filter injection; embedding inversion (niche) |
| LLM09 | Misinformation | O-07, judge | 🟠 | Acceptable if stated as a limitation |
| LLM10 | Unbounded Consumption | A-03, T-08 | 🟡 | Model extraction, denial-of-wallet (R-21) |

### 5.2 OWASP Top 10 for Agentic Applications (2026)

| ID | Risk | Current coverage | Rating | Gap |
|----|------|------------------|--------|-----|
| ASI01 | Agent Goal Hijack | T-03, T-06, T-11, tool-output probes | 🟢 | Oracles (R-05) |
| ASI02 | Tool Misuse & Exploitation | T-01, T-02, T-09 | 🟢 | n/a |
| ASI03 | Identity & Privilege Abuse | none | 🔴 | Confused deputy, credential scope (R-04) |
| ASI04 | Agentic Supply Chain | T-11, T-12, T-13 | 🟡 | MCP provenance (R-12) |
| ASI05 | Unexpected Code Execution | T-02, T-09 | 🟡 | Code sinks (R-03), sandboxing (R-09) |
| ASI06 | Memory & Context Poisoning | none | 🔴 | T-16 (R-09) |
| ASI07 | Insecure Inter-Agent Communication | none | 🔴 | Stretch (R-09) |
| ASI08 | Cascading Failures | T-08 partial | 🔴 | Audit trail A-09 (R-09) |
| ASI09 | Human-Agent Trust Exploitation | T-01 partial | 🟡 | T-17 (R-09) |
| ASI10 | Rogue Agents | none | 🔴 | Kill switch / monitoring; mostly a runtime concern (stretch) |

---

## 6. Recommended Changes

### P0: before Phase 0 code (data model and architecture)

1. Add a **threat model** and **trust-boundary coverage matrix** (R-01)
2. Add finding `kind`; **separate severity and confidence**; context-based severity with a **target capability profile** and the AIVSS rubric (R-02, R-06)
3. Add an **access level** to every check and to the audit scope (R-07)
4. Define the **oracle hierarchy**, benign verifiable payloads, and **ASR over N trials** (R-05)
5. Use a **deterministic baseline plan** with the agent on top (R-08)
6. Add **reproduction, fingerprint, lifecycle, and coverage/limitations** to the Finding and Report models (R-15)

### P1: catalog additions (fold into Phases 1–5)

7. Application code surface: **C-01 to C-06** (R-03)
8. Authorization: **T-14, T-15**, `cross-user-access` probe (R-04)
9. Agentic gaps: **T-16, T-17, T-18, A-09**; map T-checks to ASI IDs (R-09)
10. Hidden-content extractors (R-10)
11. Guardrail coverage and provider config checks (R-11)
12. Model artifact scanning, SCA, MCP provenance (R-12)
13. Target adapter and injection-channel config (R-13)

### P2: quality and polish

14. Rework the evaluation plan (R-14)
15. Judge refusal handling; PII checks local-only (R-18, R-19)
16. Split out a safety module (R-17)
17. Minor output-sink variants (R-20, R-21)

### Revised MVP critical path

If time runs short, these produce the most real, high-severity findings per week of work:

| # | Capability | Checks | Why first |
|---|-----------|--------|-----------|
| 1 | Secrets in prompts and config | P-01, A-01 | Trivial to build, very common, always high impact |
| 2 | Code taint analysis | C-01 to C-05 | Where LLM05/ASI05 vulnerabilities actually live |
| 3 | Tool capability analysis | T-09, T-10 | Architectural; doesn't depend on bypassable detectors |
| 4 | Tool authorization | T-14, C-06, cross-user probe | Most common high-impact agent flaw |
| 5 | Indirect injection, *confirmed* | T-03 + tool-output probe + canary/callback oracle | Turns "possible" into "proven" |
| 6 | Markdown and link exfiltration | O-05 | Zero-click data theft, simple to confirm |
| 7 | Limits and cost controls | A-03, T-08 | Cheap config checks |

**Defer:** harmful content (O-09), misinformation (LLM09), hallucinated packages (O-07), dashboard, proxy mode.

---

## 7. References

- [OWASP Top 10 for Agentic Applications (ASI01–ASI10), summary](https://cycode.com/blog/owasp-top-10-agentic-applications/) · [another summary](https://securew2.com/blog/owasp-top-10-agentic-ai). Verify the names against the official OWASP GenAI Security Project page.
- [OWASP AI Vulnerability Scoring System (AIVSS)](https://aivss.owasp.org/) · [OWASP project page](https://owasp.org/projects/ai-vulnerability-scoring-system-aivss)
