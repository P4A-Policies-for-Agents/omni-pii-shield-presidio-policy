# PII Shield via Presidio — Omni Gateway PDK Policy

Detects, redacts, or blocks PII **in-flight** by delegating detection and
anonymization to a [Presidio](https://github.com/data-privacy-stack/presidio)
Analyzer/Anonymizer service — co-deployed as a sidecar, or remotely hosted
(e.g. on [Railway](https://railway.com)) and reached via a same-gateway
loopback. Protocol-aware across the agentic asset types
MuleSoft **Omni Gateway** governs — **MCP** `tools/call`, **A2A** message/task
traffic (V1 + Legacy bindings, including SSE streaming), and **LLM**
completions — plus generic JSON APIs.

Built with the Policy Development Kit (PDK) **1.9.0**, Rust →
`wasm32-wasip1`, split-model project (definition + flex implementation).

> [!IMPORTANT]
> **⚠️ MANDATORY on a managed Omni Gateway — Presidio on a `Host`-routed edge (Railway/Vercel/…).**
>
> If Presidio runs on a multi-tenant edge platform that routes by the HTTP `Host` header / TLS SNI — **Railway, Vercel, Render, Heroku, Cloudflare Pages/Workers, Fly.io, Netlify** — then on a **managed** Omni Gateway (e.g. Anypoint CloudHub 2.0) the gateway rewrites the egress `Host` to an internal Envoy cluster name and the platform rejects the call (`404`/`502`).
>
> **You MUST route the callout through a same-gateway loopback "pin":**
> 1. Set **`analyzerUrl`** (and **`anonymizerUrl`**) = `http://127.0.0.1:8081` (the gateway's own internal listener).
> 2. Set **`analyzerPathPrefix`** = `/presidio-analyzer-pin` (and **`anonymizerPathPrefix`** = `/presidio-anonymizer-pin`).
> 3. Create a plain passthrough route per service on the **same** gateway at those prefixes, upstream = the real Railway/edge URL, with **`auto_host_rewrite`** so the correct `Host` is restored on egress.
>
> Without the pin the policy **cannot reach Presidio** on a managed gateway. Full recipe: [Deployment shape](#deployment-shape). The same pin applies to any of the edge platforms listed above.
>
> **Self-managed / connected Flex Gateway**, or a dedicated single-tenant host (fixed VM, static-IP load balancer, its own domain): leave the prefixes empty for a direct call.

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

## Purpose

Omni Gateway is the governance control point for agentic traffic — **MCP** `tools/call`
requests, **A2A** agent-to-agent messages, **LLM** completions, and plain REST APIs
all cross it. That traffic is exactly where PII leaks happen today, and there is no
first-party enforcement point for it:

- An agent stuffs a customer email thread — names, phone numbers, IBANs — into the
  `params.arguments` of an MCP `tools/call`, and it flows straight into a third-party
  tool or an LLM prompt.
- An orchestrating agent delegates a task to a **remote** A2A agent, passing the user's
  raw conversation as `message.parts[]` — free text crossing an organizational trust
  boundary uninspected — and the remote agent's task artifacts stream PII right back.
- A backend or MCP tool result echoes PII into an agent's context window, from which it
  can be re-emitted anywhere.
- Compliance teams (GDPR, HIPAA, PCI-DSS) have no single choke point; PII handling is
  left to each upstream service's discipline.

Regex-only header/body filters miss names, locations, and context-dependent entities.
[Presidio](https://github.com/data-privacy-stack/presidio) already solves *detection* —
a context-aware engine combining NER models, regex, checksum validators, deny-lists, and
context-word scoring, shipped as two small Dockerized REST services (Analyzer +
Anonymizer). The missing piece is the **glue at the gateway**: a policy that classifies
the traffic, extracts the right text fields, calls Presidio, and enforces an
operator-configured posture. That glue is this policy.

## Goal

Turn a best-in-class open-source PII engine into a one-click, protocol-aware Anypoint
policy that gives operators a **single, uniform PII boundary** across every asset type
Omni Gateway fronts. Concretely:

- **Detect, redact, or block PII in-flight** — on requests before they reach an LLM, MCP
  server, A2A agent, or backend API, and on responses before they reach the caller — so
  no PII bytes cross the boundary once a rule says they shouldn't.
- **Be protocol-aware, not payload-blind** — understand MCP, A2A (V1 + Legacy bindings,
  including SSE streaming), and LLM shapes so only the right text leaves are scanned and
  structure/ordering is preserved byte-faithful.
- **Safe-by-default rollout** — start in `audit` (observe only), then tighten to
  `redact`/`block` per entity, per asset type, per direction, per caller identity,
  without redeploying Presidio.
- **Compose, don't replace** — sit alongside contracts, auth, and the existing
  agent-governance policy family on the same API instance.

## Business benefits

| Benefit | How the policy delivers it |
|---|---|
| **Reduce compliance risk** | A single, auditable enforcement point for GDPR / HIPAA / PCI-DSS / CCPA data-handling obligations, instead of trusting every upstream service. |
| **Prevent data exfiltration to third parties** | Sanitizes payloads before they reach external LLMs, SaaS MCP tools, and remote A2A agents — the trust boundaries where leaks are hardest to control. |
| **Faster, safer AI adoption** | Teams can wire agents to external models and tools sooner, because the gateway guarantees PII never leaves unmasked. |
| **Centralized policy, zero app changes** | Detection/redaction rules live at the gateway; upstream apps and agents need no code changes. |
| **Tunable without rebuilds** | Entities, thresholds, allow-lists, context words, and org-specific ad-hoc recognizers (employee IDs, contract numbers) are configured in policy — no Presidio image rebuild. |
| **Audit-ready evidence** | Every leg emits `X-PII-*` headers and a structured `pii-shield-evt` log line, feeding SIEM/observability for proof of enforcement. |
| **Cost control** | Open-source Presidio + self-hosted deployment means no per-call SaaS PII-scanning fees. |

## Real-world use cases

- **Agent → external LLM guardrail.** A support-copilot agent sends conversation history
  to a hosted LLM. The policy hashes `EMAIL_ADDRESS`/`PHONE_NUMBER` and blocks
  `CREDIT_CARD` on the request leg, so the model never sees raw customer PII.
- **Cross-org A2A delegation.** An orchestrator hands a task to a partner's A2A agent.
  `PERSON`, `LOCATION`, and `PHONE_NUMBER` are redacted on `a2a` `request` traffic (data
  leaving the org) while merely audited on internal `mcp` traffic — one build, two
  postures.
- **Third-party MCP tool call.** An agent invokes a SaaS MCP tool via `tools/call`. PII
  in `params.arguments` is redacted before it leaves; PII echoed back in
  `result.content[*].text` is caught on the response leg before it re-enters the agent's
  context.
- **Regulated API fail-closed.** A healthcare API instance sets `failurePosture: closed`
  so that if Presidio is unreachable, traffic is rejected rather than passed unscanned —
  "unscanned" is unacceptable for PHI.
- **Identity-aware disclosure.** Callers holding the `pii.read` scope get emails passed
  through (audit only); everyone else gets them hashed — enforced from the Anypoint
  `Authentication` injectable, never by parsing raw tokens.
- **Observability-only baseline.** Empty `rules` + `defaultAction: audit` deploys a
  pass-through sensor that reports *where* PII is flowing across MCP/A2A/LLM/APIs before
  any team commits to enforcement.
- **Streaming response redaction.** For SSE `message/stream` / `SendStreamingMessage`
  responses, each `status-update` / `artifact-update` frame is scanned and rewritten per
  event, so PII is masked before each frame leaves the gateway.

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
| `analyzerUrl` (required) | — | Presidio Analyzer base URL (`format: service`). On a managed gateway, the gateway's own loopback listener (see Deployment). |
| `anonymizerUrl` | `""` | Presidio Anonymizer URL; only needed for `operator.serverSide`. |
| `analyzerPathPrefix` | `""` | Managed-gateway loopback prefix (e.g. `/presidio-analyzer-pin`); prepended to `/analyze` so the call re-enters a same-gateway passthrough route. Empty = direct call. See Deployment. |
| `anonymizerPathPrefix` | `""` | Loopback prefix for the Anonymizer (see `analyzerPathPrefix`). |
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

Presidio Analyzer (+ optionally Anonymizer) is a pair of small Dockerized REST
services. Where they run — and how the policy addresses them — depends on the
gateway.

### Self-managed / local Flex Gateway (direct)

Run Presidio as a sidecar / same-host / cluster service (the model Presidio
ships via its `docker-compose.yml`). Point the policy straight at it and leave
the path-prefix properties empty:

```yaml
analyzerUrl: http://presidio-analyzer:3000
anonymizerUrl: http://presidio-anonymizer:3000   # only for operator.serverSide
```

The [`playground/`](implementation/playground) wires a local Flex Gateway,
Presidio Analyzer + Anonymizer, and a JSON backend for `make run`.

### Managed Omni Gateway (CloudHub 2.0) with Presidio hosted remotely (e.g. Railway)

Managed Omni gateways rewrite the egress `Host` header on policy-originated
outbound calls, so the policy cannot reliably call an arbitrary external
Presidio URL directly. The `analyzerPathPrefix` / `anonymizerPathPrefix`
properties work around this with a **same-gateway loopback**:

1. **Host Presidio** anywhere reachable over HTTPS — e.g. two Railway services
   deployed from [`presidio-railway`](https://railway.com):
   - Analyzer: `https://presidio-railway-production.up.railway.app`
   - Anonymizer: `https://presidio-railway-anonymizer-production.up.railway.app`
2. **Publish a passthrough route** on the *same* gateway per service, whose base
   path is the prefix (e.g. `/presidio-analyzer-pin`) and whose upstream is the
   Railway URL, with `auto_host_rewrite` so the real Presidio `Host` is restored
   on the way out.
3. **Point the policy at the gateway's internal listener** and set the prefix:

```yaml
analyzerUrl: http://127.0.0.1:8081
analyzerPathPrefix: /presidio-analyzer-pin
anonymizerUrl: http://127.0.0.1:8081            # only for operator.serverSide
anonymizerPathPrefix: /presidio-anonymizer-pin
presidioTimeoutMs: 5000                          # remote hop + cold starts
```

The policy then POSTs to
`http://127.0.0.1:8081/presidio-analyzer-pin/analyze`, which the passthrough
route forwards out to Railway. Presidio's REST APIs are unauthenticated, so put
an API-key/mTLS proxy in front of the public Railway endpoints (or restrict
inbound) before routing production traffic.

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
  self-managed / self-hosted Flex Gateway (including the playground). Managed
  Omni Gateway environments (e.g. CloudHub 2.0) rewrite the egress `Host` on
  policy-originated outbound calls, so reach a remote Presidio via the
  `analyzerPathPrefix` / `anonymizerPathPrefix` same-gateway loopback (see
  Deployment) rather than pointing `analyzerUrl` at the external host directly.
- On the response leg the body is rewritten (or, on `block`, replaced with an
  error envelope) but the upstream `:status` is preserved — the body-only
  fail-closed constraint of this runtime. The security property (no PII bytes
  leave) holds regardless.
