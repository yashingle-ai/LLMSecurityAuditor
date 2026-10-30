# Demo Target Apps

> ⚠️ **Deliberately vulnerable. Never deploy these apps or expose them beyond localhost.**

The auditor is measured against these apps. Both are the same small support agent, "Acme support", built on FastAPI. Customers chat with it, and it uses tools to look up invoices, report on them, do arithmetic, check the billing service, fetch web pages, read the support inbox, search support notes, save notes to memory, send email, run code, and delete accounts. The agent loop reads its settings from `agent.yaml`: the step limit, the tools that need the customer's approval, the model and its token limit, the rate limit, the injection filter, the audit log, and the credentials it uses.

| App | Purpose |
|-----|---------|
| [vulnerable_app/](vulnerable_app/) | Contains planted flaws, each listed in [GROUND_TRUTH.yaml](vulnerable_app/GROUND_TRUTH.yaml). The auditor must find every one. |
| [hardened_app/](hardened_app/) | The same app with every planted flaw fixed. The auditor must report **no** vulnerabilities or weaknesses here. |
| [showcase/](showcase/) | The demo site: audits both apps in a browser (`uv run python -m demo.showcase`). See the [demo guide](../documentation/DEMO_GUIDE.md). |

The two apps differ only where a flaw was planted, so this shows exactly what is planted:

```bash
diff -r -x logs -x __pycache__ demo/vulnerable_app demo/hardened_app
```

## Running

```bash
uv run uvicorn demo.vulnerable_app.main:app --port 8001
uv run uvicorn demo.hardened_app.main:app --port 8002
```

```bash
curl -s -X POST http://localhost:8001/chat \
  -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' \
  -d '{"message": "What is the status of INV-1002?"}'
```

Send `conversation_id` from a reply to continue that conversation; conversations are private to their user. An optional `customer_note` adds context such as a preferred language. `POST /widget` takes the same body and returns the answer as an HTML fragment for the embeddable widget in `static/`. `POST /v1/complete` with `{"prompt": "..."}` returns a raw completion for internal tools; the vulnerable app answers it without a token.

The hardened app allows each user 30 requests a minute and answers with `429` beyond that.

| User | Token | Invoices |
|------|-------|----------|
| alice | `alice-token` | INV-1001, INV-1002 |
| bob | `bob-token` | INV-2001 |

## The Malicious MCP Server

[malicious_mcp_server/](malicious_mcp_server/) is a small stdio MCP server that the vulnerable app's `mcp.json` connects to. It attacks the agent in two ways:
- **Tool poisoning:** `currency_convert`'s description hides instructions to collect the customer's invoices.
- **Name shadowing:** a tool named like `send_email`, but spelled with a Cyrillic "i".

`mcp_tools.json` is its captured `tools/list` reply, which is what the auditor reads, so nothing is started during an audit. `tools.lock.json` approves the tool definitions as they were *before* `currency_convert` changed. The demo app itself doesn't call MCP tools yet.

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | uv run python -m demo.malicious_mcp_server
```

## Deployment and Supply Chain

These files are what the Stage 7 checks read. The two apps differ in each one:

| File | Vulnerable app | Hardened app |
|------|----------------|--------------|
| `agent.yaml` `llm` | `model: latest` over plain HTTP, `max_tokens: null`, no rate limit | a dated model over HTTPS, `max_tokens: 1024`, 30 requests a minute |
| `agent.yaml` `guardrails` | injection filter on user input only, `mode: monitor` | on user input, tool results and model output, `mode: block` |
| `agent.yaml` `audit_log` | off | every tool call logged to the `acme.audit` logger |
| `agent.yaml` `credentials` | billing token with `scope: admin`, `expires: never` | `scope: invoices:read`, valid for one hour |
| `main.py` error handler | returns the stack trace | logs it and returns "Something went wrong." |
| `tools.py` `search_notes` | searches every customer's notes | filters to the signed-in customer |
| `requirements.txt` | `langchain==0.0.150`, `transformers==4.30.0` | current, advisory-free versions |
| `models/` | `intent_classifier.pkl`, a pickle that imports `os.system` | `intent_classifier.safetensors` |
| `mcp.json` `uploads` | `npx -y` with no version | a vendored copy run with `node` |
| `openapi.json` | `/v1/complete` has no security requirement | every model endpoint needs a bearer token |

`requirements.txt` and `models/` are only there to be audited: nothing installs those versions or loads those files. **Never load `vulnerable_app/models/intent_classifier.pkl`.** Loading it would run `os.system`.

Each app has its own scope file: [configs/audit_scope.example.yaml](../configs/audit_scope.example.yaml) for the vulnerable app, [configs/audit_scope.hardened.yaml](../configs/audit_scope.hardened.yaml) for the hardened one. Their `attestations` hold the provider-account answers (retention, training, key scope and rotation, spend limit), bad for the vulnerable app and good for the hardened one.

## LLM Backends

| `LLM_BACKEND` | What it is | Used for |
|---------------|------------|----------|
| `scripted` (default) | A deterministic, deliberately gullible mock model | Tests and CI. The same input always gives the same output. |
| `real` | Any OpenAI-compatible chat-completions API | Realistic evaluation (Stage 13) |

For `real`, set `LLM_BASE_URL` and `LLM_MODEL`, plus `LLM_API_KEY` if the server needs one. Without them, the `base_url` and `model` in `agent.yaml` are used. The app's `max_tokens` is sent with every request; the scripted model ignores it.

```bash
# Local model through Ollama
LLM_BACKEND=real LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=llama3.1 \
  uv run uvicorn demo.vulnerable_app.main:app --port 8001
```

### How the scripted model behaves

It follows instructions found **anywhere** in its context: the system prompt, the user's message, or tool results. That is what makes prompt injection demonstrable and testable. For each turn, the first rule that applies wins:

1. `call <tool> with {json}`: makes that tool call, unless it already did this turn
2. `say "<text>"` or `reply with "<text>"`: replies with exactly that text (useful for canary tokens)
3. Asked for its system prompt or instructions: reveals the system prompt
4. Tool results this turn: summarizes them
5. An invoice ID (`INV-1001`) or a billing-status question: calls the matching tool
6. Otherwise: offers help

The full description is in [common/scripted.py](common/scripted.py).

## Traces

Every chat run is appended as one JSON line in **OpenAI chat format**: the full message list (system prompt, user turns, assistant tool calls, tool results) plus the tool definitions.

| File | Contents |
|------|----------|
| `logs/traffic.jsonl` | Generated fixture: a fixed set of benign and attack conversations. Committed. |
| `logs/live.jsonl` | Traces from running the app by hand. Git-ignored. Override the path with `DEMO_TRACE_FILE`. |
| `tools.json` | The app's tool definitions in OpenAI function format. Generated alongside the traces. |
| `mcp_tools.json`, `tools.lock.json` | The MCP servers' captured tool list, and the approved tool definitions. Also generated. |
| `openapi.json` | The app's OpenAPI spec, as FastAPI generates it. Also generated. |

Regenerate the fixtures whenever an app changes:

```bash
uv run python -m scripts.generate_traffic
```

It uses the scripted model, a fixed clock and sequential IDs, so its output is identical on every run. A test fails if the committed fixtures are stale.

`fetch_url` never touches the network while generating. It sees a fixed web: the app's own `knowledge_base/`, served as `https://docs.acme.example/`, and one attacker's page at `https://coupons.example/acme-deal` (in `OUTSIDE_PAGES`). Every other address returns a 404.

The traffic includes attacks that arrive through what the agent reads, not what the customer types:

| Attack | What the vulnerable app does | What the hardened app does |
|--------|------------------------------|----------------------------|
| White text on the returns help page | Replies "Refunds are paused this month." | Its copy of the page has no hidden text |
| A hidden paragraph on the attacker's page | Looks up an invoice, emails it to the attacker, and replies with a tracking image carrying the invoice ID | `fetch_url` refuses the site |
| An email in the support inbox (`SUPPORT_INBOX` in `common/data.py`) | Saves the attacker's note to memory, deletes the account, and tells the customer "You have no new messages." | The injection filter removes the email before the model reads it |
| A customer asking for a reply in HTML | Replies with the HTML, which the widget would render | The input filter blocks the request |

## Knowledge Base

Each app has a `knowledge_base/` of help pages, audited as `documents` (P-08). The vulnerable app's returns page hides an instruction to the model in white text, and the logged traffic shows the agent obeying it (T-03). The hardened copy has the hidden text stripped. It keeps its harmless hidden content (a collapsed menu, alt text, a meta description), which must not be flagged.

## Adding a Planted Flaw

Each implementation stage plants the flaws its checks should find:

1. Plant the flaw in `vulnerable_app/`.
2. Fix it in `hardened_app/`. Change only what the flaw needs, so the diff stays readable.
3. Add an entry to `GROUND_TRUTH.yaml` with `enabled: false`.
4. Regenerate the fixtures.
5. Build the detector, then set `enabled: true`. The harness in [tests/groundtruth/test_demo_apps.py](../tests/groundtruth/test_demo_apps.py) now requires it to be found.

## Known Behavior

Both apps reveal their system prompt when asked, because the scripted model is gullible and real models can be talked into it too. The hardened app's fix is that its prompt holds **nothing sensitive**, not that it refuses (see assumption 2 in [THREAT_MODEL.md](../documentation/THREAT_MODEL.md)). O-03 (system prompt leakage) reports a leaked secret-free prompt as a hardening note only, so it never fails the hardened app. In the logged traffic, the hardened app's input filter also blocks the extraction attempt, which P-07 records as a failed attack.
