# PII Shield via Presidio — Omni Gateway PDK Policy

Detects, redacts, or blocks PII **in-flight** by delegating detection and
anonymization to a co-deployed [Presidio](https://github.com/data-privacy-stack/presidio)
Analyzer/Anonymizer service. Protocol-aware across the agentic asset types
MuleSoft **Omni Gateway** governs — **MCP** `tools/call`, **A2A** message/task
traffic (V1 + Legacy bindings, including SSE streaming), and **LLM**
completions — plus generic JSON APIs.

Built with the Policy Development Kit (PDK) **1.9.0**, Rust →
`wasm32-wasip1`, split-model project (definition + flex implementation).

```
omni-pii-shield-presidio-policy/
├── definition/            # gcl.yaml + exchange.json + Makefile  (Exchange asset)
└── implementation/        # Rust → wasm32-wasip1
    ├── src/
    │   ├── lib.rs          # entrypoint, request/response filter wiring
    │   ├── detect.rs       # payload classification (MCP / A2A / LLM / generic)
    │   ├── mcp.rs          # tools/call shapes + traversal
    │   ├── a2a.rs          # Message/Task/Part shapes, V1+Legacy methods
    │   ├── extract.rs      # path-addressable text-leaf traversal + JSONPath
    │   ├── presidio.rs     # /analyze + /anonymize client + local operators
    │   ├── engine.rs       # first-match rule evaluation (audience, action)
    │   ├── sse.rs          # byte-perfect SSE parse/serialize
    │   ├── evidence.rs     # X-PII-* headers + structured log events
    │   ├── config.rs       # typed, validated config view
    │   └── generated/      # config struct generated from gcl.yaml
    ├── playground/         # Omni Gateway + Presidio docker-compose
    └── tests/              # host-side pipeline integration tests
```

## What it does

Per inspected leg the policy:

1. **Classifies** the payload (protocol-aware):
   - **MCP** JSON-RPC `tools/call` → scans the string leaves of
     `params.arguments` (request) and `result.content[*].text` where
     `type == "text"` (response).
   - **A2A** message/task traffic → binding detected from `A2A-Version: 1.0`
     (header or `?A2A-Version=1.0` query) → V1 (`SendMessage`, `GetTask`, …),
     else Legacy (`message/send`, `tasks/get`, …). Scans the `text` of every
     text part in `params.message.parts[]` (request) and the response
     `Message`/`Task` parts (`status.message.parts[]`, `artifacts[*].parts[]`),
     including per-event SSE `status-update` / `artifact-update` frames.
     `DataPart` payloads are scanned as generic JSON leaves when
     `scanDataParts: true`; `FilePart` entries are never scanned in v1.
   - **LLM** OpenAI/Anthropic bodies → `messages[*].content` (request) and
     `choices[*].message|delta.content` / top-level `content[*].text`
     (response).
   - **Generic JSON** → all string leaves, or only the operator-configured
     `scanTargets` (JSONPath).
   - Everything else (binary, non-JSON, image/audio content) passes through.
2. **Calls Presidio** `POST {analyzerUrl}/analyze` with the extracted text and
   the configured `language`, `entities`, `scoreThreshold`, `allowList`,
   `contextWords`, and `adHocRecognizers` — so operators tune detection
   without rebuilding the Presidio image.
3. **Applies the first-matching rule** per detected entity:
   - `audit` — pass through unmodified; emit detection evidence only.
   - `redact` — rewrite the offending spans in place (local splice from
     analyzer offsets, or `POST {anonymizerUrl}/anonymize` when
     `operator.serverSide: true`). Structure, key order, and non-text parts
     are preserved byte-faithful.
   - `block` — reject with a surface-appropriate error: a JSON-RPC error
     envelope (HTTP 422) for MCP/A2A, a JSON error body otherwise.
4. **Emits evidence**: `X-PII-Detected: true`,
   `X-PII-Entities: EMAIL_ADDRESS:2,IBAN_CODE:1`, `X-PII-Action: redacted`
   (request leg), plus a structured `pii-shield-evt` log line per leg.

Empty `rules` + `defaultAction: audit` ⇒ an observability-only, pass-through
deployment. No `analyzerUrl` reachability + `failurePosture: open` ⇒ traffic
passes unscanned with `X-PII-Scan: skipped`.

## Configuration

See [`definition/gcl.yaml`](definition/gcl.yaml) for the full schema. Key
properties:

| Property | Default | Description |
|---|---|---|
| `analyzerUrl` (required) | — | Presidio Analyzer base URL (`format: service`). |
| `anonymizerUrl` | `""` | Presidio Anonymizer URL; only needed for `operator.serverSide`. |
| `assetTypes` | all | `mcp` \| `a2a` \| `llm` \| `generic` to inspect. |
| `direction` | `both` | `request` \| `response` \| `both`. |
| `scanDataParts` | `false` | A2A: also scan `DataPart` JSON leaves. |
| `entities` | all | Presidio entity types to request. |
| `scoreThreshold` | `0.5` | Minimum analyzer confidence to act on. |
| `language` | `en` | Analyzer language (must be loaded in the container). |
| `allowList` / `contextWords` / `adHocRecognizers` | `[]` | Forwarded to `/analyze`. |
| `scanTargets` | auto | JSONPath overrides for what to scan. |
| `maxBodyBytes` / `oversizePosture` | `262144` / `pass` | Skip or block oversized bodies. |
| `defaultAction` | `audit` | Action for entities matching no rule. |
| `rules` | `[]` | Ordered, first-match-wins entity rules. |
| `failurePosture` | `open` | `open` (pass) or `closed` (reject) when Presidio is down. |
| `presidioTimeoutMs` | `1500` | Per-call analyzer/anonymizer timeout. |

**Rule entry:** `entityType` (exact or glob, e.g. `US_*`), optional
`assetType`, optional `direction`, optional `audienceType`
(`client`/`scope`) + `audienceValue` (read from the Anypoint
`Authentication` injectable only — never parsing raw tokens), `action`, and
for `redact` an `operator` (`replace`/`mask`/`hash`/`redact`).

Example — block payment data everywhere, hash emails for callers lacking the
`pii.read` scope, redact names only on A2A (data leaving the org):

```yaml
defaultAction: audit
rules:
  - entityType: CREDIT_CARD
    action: block
  - entityType: EMAIL_ADDRESS
    audienceType: scope
    audienceValue: pii.read
    action: audit            # privileged caller: observe only
  - entityType: EMAIL_ADDRESS
    action: redact
    operator: { kind: hash }
  - entityType: PERSON
    assetType: a2a
    direction: request
    action: redact
```

## Build & test

```bash
cd implementation
cargo test                                   # host unit + integration tests
cargo build --target wasm32-wasip1 --release # WASM artifact
make build                                   # regenerates config.rs + GCL, then builds
make run                                      # boots the playground (Flex + Presidio)
```

`make build` regenerates `src/generated/config.rs` from
`definition/gcl.yaml` via `cargo anypoint config-gen`; the checked-in copy
mirrors that output so `cargo test` works without the codegen step.

## Deployment shape

Presidio Analyzer (+ optionally Anonymizer) runs as Docker containers next to
the gateway (sidecar, same host, or cluster service) — the deployment model
Presidio ships via its `docker-compose.yml`. The
[`playground/`](implementation/playground) wires a local Flex Gateway,
Presidio Analyzer + Anonymizer, and a JSON backend for `make run`.

## Scope notes / v1 limits

- **Text only.** MCP image/audio/resource entries, A2A `FilePart` payloads,
  and binary bodies are not scanned (Presidio Image Redactor is a v2).
- **A2A gRPC** is out of scope; JSON-RPC, HTTP+JSON, and SSE streaming are
  covered. Agent Card fetches pass through (compose with the A2A Agent Card
  Skill Governor).
- **Detection is probabilistic** — position this as defense-in-depth at the
  perimeter, not a compliance silver bullet.
- **Runtime note.** The request leg calls Presidio after buffering the request
  body. This is the standard "gateway as PII boundary" flow and works on
  self-managed / self-hosted Flex Gateway (including the playground). Some
  managed Omni Gateway environments restrict policy-originated outbound HTTP
  once the request body phase has started; deploy Presidio as a reachable
  sidecar/service accordingly.
- On the response leg the body is rewritten (or, on `block`, replaced with an
  error envelope) but the upstream `:status` is preserved — the body-only
  fail-closed constraint of this runtime. The security property (no PII bytes
  leave) holds regardless.
```
