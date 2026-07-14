## Custom Policy to utilize a Presidio Service for PII

Presidio is a well known PII detection and removal service
https://github.com/data-privacy-stack/presidio

https://presidio.dataprivacystack.org/samples/python/customizing_presidio_analyzer/

Presidio can be run in a Docker environment and maybe utilizued from a Custom Policy.

**Extended by Amir Khan**
# PII Shield via Presidio — Omni Gateway PDK Policy (Idea)

**Working name:** `pii-shield-presidio-policy`
**Type:** MuleSoft Omni Gateway custom policy, built with the Policy Development Kit (PDK) **v1.9.0**, Rust → `wasm32-wasip1`, split-model project (definition + flex implementation), Apache-2.0.
**One-liner:** Detects, redacts, or blocks PII in-flight — on requests before they reach an LLM, an MCP server, an A2A agent, or a backend API, and on responses before they reach the caller — by delegating detection and anonymization to a co-deployed [Presidio](https://github.com/data-privacy-stack/presidio) Analyzer/Anonymizer service running in Docker. Protocol-aware across the three agentic asset types Omni Gateway governs: **MCP**, **A2A**, and **LLM**, plus generic JSON APIs.

---

## Why

Omni Gateway is positioned as the governance control point for agentic traffic: MCP `tools/call` requests, A2A messages, LLM completions, and plain REST APIs all cross it. That traffic is exactly where PII leaks happen today:

- An agent stuffs a customer email thread — names, phone numbers, IBANs — into the `params.arguments` of an MCP `tools/call`, and it flows straight into a third-party tool or an LLM prompt.
- An orchestrating agent delegates a task to a remote A2A agent and passes the user's raw conversation as `message.parts[]` — free text crossing an organizational trust boundary with no inspection; the remote agent's task artifacts stream PII right back.
- A backend or MCP tool result echoes PII back into an agent's context window, from which it can be re-emitted anywhere.
- Compliance teams (GDPR, HIPAA, PCI) have no enforcement point: PII handling is left to each upstream service's discipline.

There is no first-party Omni Gateway policy that does semantic PII detection. Regex-only header/body filters miss names, locations, and context-dependent entities. Presidio solves the detection problem — it is a context-aware, pluggable PII engine combining NER models, regex, checksum validators, deny-lists, and context-word scoring, exposed as two small REST services (Analyzer, Anonymizer) that ship as Docker images and are trivially co-deployed next to the gateway. The gap is the **glue at the gateway**: a PDK policy that classifies the traffic, extracts the right text fields, calls Presidio, and applies an operator-configured posture. That glue is this policy.

This follows the same "gateway as PII boundary" pattern Presidio itself documents for LiteLLM proxy (masking LLM calls at the proxy layer) — but brings it to Anypoint-governed traffic, where it composes with contracts, auth, and the existing agent-governance policy family (tool token rate limiting, tool drift detection, agent-card governance).

## What it does

A **request/response body filter** policy. Per direction, it:

1. **Classifies the payload** (protocol-aware, like the sibling MCP policies):
   - **MCP** JSON-RPC `tools/call` → scan the string leaves of `params.arguments` (request) and `result.content[*].text` where `type == "text"` (response) — the same traversal contract the token rate-limit policy established.
   - **A2A** message/task traffic → detected by JSON-RPC method name across both protocol bindings, using the same V1-vs-Legacy discrimination the skill-governor policy established: the `A2A-Version: 1.0` signal (request header or `?A2A-Version=1.0` query parameter) marks the V1 binding (`SendMessage`, `SendStreamingMessage`, `GetTask`), its absence marks Legacy (`message/send`, `message/stream`, `tasks/get`, `tasks/resubscribe`). Extraction (see the A2A surfaces table below): request → the `text` field of every text part in `params.message.parts[]`; response → text parts of the result `Message`, or for a `Task` result the `status.message.parts[]` and `artifacts[*].parts[]`; streaming → text parts inside each SSE task/status/artifact-update event. `DataPart` payloads are optionally scanned as generic JSON string leaves (`scanDataParts`); `FilePart` entries are not scanned in v1. Agent Card fetches (`/.well-known/agent-card.json`, extended-card calls) pass through untouched — card governance is the skill-governor policy's job, and the two compose cleanly on the same API instance.
   - **LLM** OpenAI/Anthropic-style bodies → scan `messages[*].content` (request) and choice/content text (response).
   - Generic JSON → scan string leaves, optionally narrowed by operator-configured JSONPath targets.
   - Everything else (binary, non-JSON, image/audio/resource MCP content) passes through untouched.
2. **Calls Presidio** over the PDK HTTP client:
   - `POST {analyzerUrl}/analyze` with the extracted text, `language`, requested `entities`, `score_threshold`, `allow_list`, `context` words, and optional `ad_hoc_recognizers` — all passed through from policy config, so operators tune detection *without* rebuilding the Presidio image. Deeper customization (custom recognizers, other NLP models/languages, no-code YAML recognizers) lives inside the Presidio container and is transparent to the policy.
   - In `redact` mode, `POST {anonymizerUrl}/anonymize` with the analyzer results and per-entity operators (`replace`, `mask`, `hash`, `redact`, `encrypt`) — or performs the splice locally from analyzer offsets to save a round trip (implementation choice).
3. **Applies the configured action**, first-match per entity rule (the hybrid-rule style of the skill-governor policy):
   - `audit` — pass through unmodified; emit detection metadata (headers + log event) only.
   - `redact` — rewrite the offending spans in place and forward the sanitized body.
   - `block` — reject the message. For MCP/JSON-RPC traffic, a JSON-RPC error envelope (`-32600`-family) with HTTP 422/451; for plain HTTP, a JSON error body — surface-appropriate errors, as the skill-governor does.
4. **Emits evidence**: `X-PII-Detected: true`, `X-PII-Entities: EMAIL_ADDRESS:2,IBAN_CODE:1`, `X-PII-Action: redacted`, plus a structured log/metric event per detection — feeding the same "drift/violation event" observability story as the drift-detection policy.

## A2A surfaces scanned

All A2A surfaces carry the same `Message`/`Task` shapes; only the wire binding and the location of the text parts differ. The policy detects the binding from the request and locates the parts accordingly — the same detection contract as the skill-governor policy, extended from card fetches to message traffic.

| Surface | Request | Scanned on request | Scanned on response |
|---|---|---|---|
| JSON-RPC V1 (`A2A-Version: 1.0`) | `POST` `SendMessage` / `GetTask` | `params.message.parts[]` text parts | `result` Message parts, or Task `status.message.parts[]` + `artifacts[*].parts[]` |
| JSON-RPC Legacy | `POST` `message/send` / `tasks/get` / `tasks/resubscribe` | same | same |
| Streaming (V1 `SendStreamingMessage` / Legacy `message/stream`) | `POST`, response is `text/event-stream` | `params.message.parts[]` text parts | text parts inside each SSE `status-update` / `artifact-update` event, buffered and scanned per event |
| HTTP+JSON binding (V1, with `A2A-Version: 1.0`) | e.g. `POST /v1/message:send` | body `message.parts[]` text parts | body Message/Task parts as above |
| Agent Card (public well-known / extended) | `GET /.well-known/agent-card.json`, extended-card calls | — passthrough | — passthrough (compose with the A2A Agent Card Skill Governor) |

Part-kind handling: `text` parts are always scanned; `data` parts are scanned as generic JSON string leaves when `scanDataParts: true`; `file` parts (bytes/URI) pass through in v1. On `redact`, the offending spans are rewritten inside the part `text` in place — task/message structure, part ordering, and non-text parts are preserved byte-faithful. On `block` of a streaming response, the current SSE event is replaced with a JSON-RPC error event and the stream is terminated, so no further PII frames leave.

## Configuration (GCL sketch)

| Property | Type | Default | Description |
|---|---|---|---|
| `analyzerUrl` | string | — (required) | Base URL of the Presidio Analyzer service (Docker sidecar / cluster service). |
| `anonymizerUrl` | string | `""` | Presidio Anonymizer URL; required only when any rule uses `redact` with server-side anonymization. |
| `assetTypes` | array of `mcp` \| `a2a` \| `llm` \| `generic` | all | Which traffic classes to inspect; others pass through untouched. Lets one build serve MCP, A2A, and LLM API instances with per-instance scoping. |
| `direction` | `request` \| `response` \| `both` | `both` | Which legs to inspect. |
| `scanDataParts` | boolean | `false` | A2A only: also scan `DataPart` structured payloads as generic JSON string leaves. |
| `defaultAction` | `audit` \| `redact` \| `block` | `audit` | Action for detected entities that match no rule (safe-by-default rollout: audit first, tighten later). |
| `rules` | array | `[]` | Ordered, first-match-wins entity rules (below). |
| `entities` | array<string> | `[]` = all | Presidio entity types to request (`EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `PERSON`, `LOCATION`, …). |
| `scoreThreshold` | number 0–1 | `0.5` | Minimum analyzer confidence to act on. |
| `language` | string | `en` | Analyzer language (must be loaded in the Presidio container). |
| `allowList` | array<string> | `[]` | Exact values never treated as PII (passed to Presidio `allow_list`). |
| `contextWords` | array<string> | `[]` | Outer context passed to the analyzer to boost weak-pattern confidence (Presidio's context-enhancement mechanism). |
| `adHocRecognizers` | array | `[]` | Inline regex/deny-list recognizers forwarded to `/analyze` — org-specific IDs (employee numbers, contract IDs) with zero image rebuilds. |
| `scanTargets` | array<string> (JSONPath) | `[]` = auto | Override auto-classification; scan only these body paths. |
| `maxBodyBytes` | integer | `262144` | Bodies larger than this skip inspection per `oversizePosture`. |
| `failurePosture` | `open` \| `closed` | `open` | What to do when Presidio is unreachable/times out (see below). |
| `presidioTimeoutMs` | integer | `1500` | Per-call analyzer/anonymizer timeout. |

**Rule entry:** `entityType` (exact or glob, e.g. `US_*`), optional `assetType` (`mcp`/`a2a`/`llm`/`generic`, default any), optional `direction`, optional `audienceType`/`audienceValue` (`client`/`scope`, read from the Anypoint `Authentication` injectable only — never parsing raw tokens, same identity contract as the skill governor), `action` (`audit`/`redact`/`block`), and for `redact` an `operator` (`replace`/`mask`/`hash`/`redact`) with parameters. Example: block `CREDIT_CARD` everywhere; hash `EMAIL_ADDRESS` on requests for callers without the `pii.read` scope; redact `PERSON` and `PHONE_NUMBER` only on `a2a` traffic (data leaving the org boundary to remote agents) while merely auditing them on internal `mcp` traffic.

## Behavior summary

- Targets `POST`/`PUT`/`PATCH` with JSON, plus `text/event-stream` responses for both MCP and A2A streaming (`message/stream` / `SendStreamingMessage`) — text content only, buffered and scanned per SSE event like the token policy's SSE handling, so redaction happens before each event leaves the gateway.
- Request phase: extract → analyze → act → forward (possibly rewritten) body upstream.
- Response phase: same, gateway→caller. In `block` mode on the response leg, the body is **replaced** with the error envelope but, on the split headers→body flow, `:status` stays as upstream sent it — the same body-only fail-closed constraint the skill-governor documented for this runtime; the security property (no PII bytes leave) is preserved regardless.
- Empty `rules` + `defaultAction: audit` ⇒ observability-only deployment; empty config beyond that ⇒ effectively inert (mirrors the "empty ruleset = passthrough" principle).
- Non-target traffic always passes through (fail-open on parse), matching the sibling policies' posture.

## Failure behavior

| Condition | Posture |
|---|---|
| Non-JSON / no scannable text / oversized body | Pass through (or block, per `oversizePosture`/config), debug log. |
| Presidio timeout or 5xx, `failurePosture: open` | Pass through unscanned, WARN + `X-PII-Scan: skipped` header. |
| Presidio timeout or 5xx, `failurePosture: closed` | Reject with surface-appropriate error (JSON-RPC `-32603` for MCP, HTTP 503 body otherwise) — for regulated APIs where "unscanned" is unacceptable. |
| Redaction splice fails on a confirmed detection | Never forward the original: fall back to `block` for that message. ERROR log. |
| Invalid config at load | Policy will not configure; malformed rules dropped with WARN. |

## Deployment shape

Presidio Analyzer (+ optionally Anonymizer) runs as Docker containers next to the gateway (sidecar, same host, or cluster service) — the exact deployment model Presidio ships via its `docker-compose.yml`. The policy repo includes a `playground/` with a compose file wiring local Omni Gateway + Presidio for `make run`, and the standard PDK targets (`make build`, `make test-unit`, `make test` with pdk-test integration tests), matching the project layout of the reviewed policies:

```
pii-shield-presidio-policy/
├── definition/            # gcl.yaml + exchange.json + Makefile
└── implementation/        # Rust → wasm32-wasip1
    ├── src/
    │   ├── lib.rs          # entrypoint, request/response filter wiring
    │   ├── detect.rs       # payload classification (MCP / A2A / LLM / generic JSON)
    │   ├── mcp.rs          # tools/call shapes + traversal
    │   ├── a2a.rs          # Message/Task/Part shapes, V1+Legacy method constants, SSE events
    │   ├── extract.rs      # text-leaf traversal + JSONPath targets
    │   ├── presidio.rs     # /analyze + /anonymize HTTP client
    │   ├── engine.rs       # rule evaluation (first-match, audience, action)
    │   └── generated/      # config struct from gcl.yaml
    ├── playground/         # Omni Gateway + Presidio docker-compose
    └── tests/
```

## Scope notes / v1 limits

- Text only: MCP image/audio/resource content entries, A2A `FilePart` payloads, and binary bodies are not scanned in v1 (Presidio Image Redactor is a natural v2 for base64 image and file-part content).
- A2A gRPC binding is out of scope (same boundary the skill governor draws); JSON-RPC, HTTP+JSON, and SSE streaming are covered. Push-notification callbacks configured by tasks travel agent→client outside this API instance and are not inspected.
- Detection is probabilistic — Presidio itself warns there is no guarantee of catching all PII; position this as defense-in-depth at the perimeter, not a compliance silver bullet (the same "disclosure ≠ authorization"-style honesty box the skill governor uses).
- Latency: one analyzer round trip per inspected leg; mitigations are `scanTargets`, `maxBodyBytes`, entity narrowing, and co-located deployment. A v2 could add response-only sampling or caching by body hash.

## Why this fits the P4A catalog

It completes the agent-governance triangle the existing policies started: the token rate-limit policy governs **how much** agents consume, drift/rug-pull detection governs **what tools claim to be**, the skill governor governs **what agents advertise** — this policy governs **what data flows through them**, uniformly across all three agentic asset types Omni Gateway fronts (MCP, A2A, LLM) plus plain APIs. Same PDK stack, same protocol-awareness (including the skill governor's V1/Legacy A2A binding detection, now applied to message traffic), same config idioms (ordered first-match rules, Anypoint-identity binding, fail postures, inert-when-empty), and it turns a best-in-class open-source PII engine into a one-click Anypoint policy. On an A2A instance it pairs naturally with the Agent Card Skill Governor: the governor shapes what the agent *says it can do*, this policy sanitizes what actually *flows* when those skills are invoked.