//! PII Shield via Presidio — Omni Gateway PDK policy entrypoint.
//!
//! A protocol-aware request/response body filter. Per inspected leg it
//! (1) classifies the payload (MCP / A2A / LLM / generic JSON), (2)
//! extracts the scannable text leaves, (3) delegates detection to a
//! co-deployed Presidio Analyzer, (4) applies operator-configured
//! first-match rules (`audit` / `redact` / `block`), and (5) emits
//! evidence. Non-target traffic and parse failures pass through.
//!
//! The rule engine, classifiers, extractors, Presidio (de)serialization,
//! anonymization, and SSE framing all live in sibling modules with pure,
//! host-testable functions; this file is the thin PDK glue.

pub mod a2a;
pub mod config;
pub mod detect;
pub mod engine;
pub mod evidence;
pub mod extract;
pub mod generated;
pub mod mcp;
pub mod presidio;
pub mod sse;

use std::rc::Rc;

use anyhow::anyhow;
use pdk::authentication::{Authentication, AuthenticationHandler};
use pdk::hl::*;
use pdk::logger;
use serde_json::{json, Value};

use crate::config::{AssetType, Direction, FailurePosture, OversizePosture, PolicyConfig};
use crate::detect::Classified;
use crate::engine::{Decision, EvalContext};
use crate::evidence::{Event, HEADER_ACTION, HEADER_DETECTED, HEADER_ENTITIES, HEADER_SCAN};
use crate::generated::config::Config;
use crate::presidio::{PresidioError, RecognizerResult};

const JSON_RPC_INVALID_REQUEST: i32 = -32600;
const JSON_RPC_INTERNAL_ERROR: i32 = -32603;
const HTTP_UNPROCESSABLE: u32 = 422;
const HTTP_UNAVAILABLE: u32 = 503;

/// Per-request handoff to the response phase (identity for audience rules).
#[derive(Clone, Debug, Default)]
struct RequestCtx {
    client_id: Option<String>,
    scopes: Vec<String>,
}

/// Shared, cloneable policy state. `PolicyConfig` is pure; the live
/// `Service` handles are kept beside it for the Presidio client.
#[derive(Clone)]
struct PolicyState {
    cfg: Rc<PolicyConfig>,
    analyzer: Option<Service>,
    anonymizer: Option<Service>,
}

#[entrypoint]
pub async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
) -> anyhow::Result<()> {
    let raw: Config = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("invalid policy configuration: {e}"))?;
    let cfg = PolicyConfig::from_generated(&raw)
        .map_err(|e| anyhow!("policy configuration rejected: {e}"))?;

    logger::info!(
        "pii-shield-presidio: analyzer={} anonymizer={} assetTypes={:?} direction={:?} rules={} defaultAction={} failurePosture={:?}",
        cfg.analyzer_url,
        cfg.anonymizer_url.as_deref().unwrap_or("<none>"),
        cfg.asset_types.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
        cfg.direction,
        cfg.rules.len(),
        cfg.default_action.label(),
        cfg.failure_posture,
    );

    let state = PolicyState {
        cfg: Rc::new(cfg),
        analyzer: raw.analyzer_url.clone(),
        anonymizer: raw.anonymizer_url.clone(),
    };

    let request_state = state.clone();
    let response_state = state;

    let filter = on_request(
        move |request: RequestHeadersState, client: HttpClient, auth: Authentication| {
            let s = request_state.clone();
            async move { request_filter(request, client, auth, s).await }
        },
    )
    .on_response(
        move |response: ResponseHeadersState, client: HttpClient, data: RequestData<RequestCtx>| {
            let s = response_state.clone();
            async move { response_filter(response, client, data, s).await }
        },
    );

    launcher.launch(filter).await?;
    Ok(())
}

// ---------------------------------------------------------------------
// Request leg.
// ---------------------------------------------------------------------

async fn request_filter(
    request: RequestHeadersState,
    client: HttpClient,
    auth: Authentication,
    state: PolicyState,
) -> Flow<RequestCtx> {
    let ctx = read_identity(&auth);
    let cfg = &state.cfg;

    if !cfg.direction.includes(Direction::Request) {
        return Flow::Continue(ctx);
    }

    let method = request
        .handler()
        .header(":method")
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        return Flow::Continue(ctx);
    }

    let content_type = request.handler().header("content-type").unwrap_or_default();
    if !is_json(&content_type) {
        return Flow::Continue(ctx);
    }

    if !request.contains_body() {
        return Flow::Continue(ctx);
    }

    let path = request.path();
    // Snapshot headers needed for A2A version detection before consuming.
    let a2a_version = request
        .handler()
        .header(a2a::A2A_VERSION_HEADER)
        .or_else(|| request.handler().header("A2A-Version"));

    let body_state = request.into_headers_body_state().await;
    let body = body_state.handler().body();

    if body.len() > cfg.max_body_bytes {
        return match cfg.oversize_posture {
            OversizePosture::Block => {
                logger::warn!("pii-shield-presidio: blocking oversize request body ({}B)", body.len());
                Flow::Break(plain_error(HTTP_UNPROCESSABLE, "payload too large"))
            }
            OversizePosture::Pass => {
                body_state.handler().set_header(HEADER_SCAN, "skipped-oversize");
                Flow::Continue(ctx)
            }
        };
    }

    let mut parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return Flow::Continue(ctx), // fail-open on parse
    };

    let classified = match detect::classify_request(
        &parsed,
        &path,
        |name| header_lookup(name, &a2a_version),
        cfg,
    ) {
        Some(c) => c,
        None => return Flow::Continue(ctx),
    };

    if classified.fields.is_empty() {
        return Flow::Continue(ctx);
    }

    let analyzer = match state.analyzer.as_ref() {
        Some(a) => a,
        None => match cfg.failure_posture {
            FailurePosture::Open => {
                body_state.handler().set_header(HEADER_SCAN, "skipped");
                return Flow::Continue(ctx);
            }
            FailurePosture::Closed => {
                return Flow::Break(scan_unavailable_response(classified.asset_type, &parsed));
            }
        },
    };

    let field_results = match scan_fields(&client, analyzer, cfg, &classified).await {
        Ok(r) => r,
        Err(e) => {
            logger::warn!("pii-shield-presidio: analyzer error on request: {e}");
            return match cfg.failure_posture {
                FailurePosture::Open => {
                    body_state.handler().set_header(HEADER_SCAN, "skipped");
                    Flow::Continue(ctx)
                }
                FailurePosture::Closed => {
                    Flow::Break(scan_unavailable_response(classified.asset_type, &parsed))
                }
            };
        }
    };

    let eval_ctx = EvalContext {
        asset_type: classified.asset_type,
        direction: Direction::Request,
        client_id: ctx.client_id.as_deref(),
        scopes: &ctx.scopes,
    };
    let decision = engine::evaluate(&field_results, cfg, &eval_ctx);

    emit_evidence(Direction::Request, classified.asset_type, &decision);

    if decision.block {
        return Flow::Break(block_response(classified.asset_type, &parsed, &decision));
    }

    if decision.any_detected() {
        set_evidence_headers(body_state.handler(), &decision, decision.action_label());
    }

    if decision.any_redaction()
        && apply_redactions(
            &client,
            state.anonymizer.as_ref(),
            cfg,
            &mut parsed,
            &classified,
            &decision,
        )
        .await
    {
        match serde_json::to_vec(&parsed) {
            Ok(bytes) => {
                let len = bytes.len();
                if let Err(e) = body_state.handler().set_body(&bytes) {
                    logger::error!("pii-shield-presidio: request set_body failed: {e:?}");
                    return Flow::Break(plain_error(HTTP_UNPROCESSABLE, "redaction failed"));
                }
                body_state
                    .handler()
                    .set_header("content-length", &len.to_string());
            }
            Err(e) => {
                logger::error!("pii-shield-presidio: request re-serialize failed: {e}");
                return Flow::Break(plain_error(HTTP_UNPROCESSABLE, "redaction failed"));
            }
        }
    }

    Flow::Continue(ctx)
}

// ---------------------------------------------------------------------
// Response leg.
// ---------------------------------------------------------------------

async fn response_filter(
    response: ResponseHeadersState,
    client: HttpClient,
    data: RequestData<RequestCtx>,
    state: PolicyState,
) {
    let ctx = match data {
        RequestData::Continue(c) => c,
        _ => return,
    };
    let cfg = &state.cfg;

    if !cfg.direction.includes(Direction::Response) {
        return;
    }

    let content_type = response.handler().header("content-type").unwrap_or_default();
    let is_sse = content_type.contains("text/event-stream");
    let is_json_ct = is_json(&content_type);
    if !is_sse && !is_json_ct {
        return;
    }

    let Some(analyzer) = state.analyzer.clone() else {
        return;
    };

    if !response.contains_body() {
        return;
    }

    // The rewrite (or a no-op re-serialize) can change the body length.
    response.handler().remove_header("content-length");

    let body_state = response.into_body_state().await;
    let body = body_state.handler().body();

    if body.len() > cfg.max_body_bytes {
        logger::warn!("pii-shield-presidio: response body oversize; pass-through");
        return;
    }

    let rewritten = if is_sse {
        scan_sse_response(&client, &analyzer, &state, &ctx, &body).await
    } else {
        scan_json_response(&client, &analyzer, &state, &ctx, &body).await
    };

    if let Some(new_body) = rewritten {
        if let Err(e) = body_state.handler().set_body(&new_body) {
            logger::error!("pii-shield-presidio: response set_body failed: {e:?}");
        }
    }
}

/// Scan one plain-JSON response. Returns `Some(new_body)` when the body
/// was blocked (replaced with an error envelope) or redacted.
async fn scan_json_response(
    client: &HttpClient,
    analyzer: &Service,
    state: &PolicyState,
    ctx: &RequestCtx,
    body: &[u8],
) -> Option<Vec<u8>> {
    let mut parsed: Value = serde_json::from_slice(body).ok()?;
    let outcome = scan_value_response(client, analyzer, state, ctx, &mut parsed).await?;
    match outcome {
        ResponseOutcome::Blocked(asset, decision) => {
            Some(serde_json::to_vec(&block_body(asset, &parsed, &decision)).unwrap_or_default())
        }
        ResponseOutcome::Redacted => serde_json::to_vec(&parsed).ok(),
    }
}

/// Scan an SSE response event-by-event. On block, replace the offending
/// event with a JSON-RPC error event and drop every later event so no
/// further PII frames leave the gateway.
async fn scan_sse_response(
    client: &HttpClient,
    analyzer: &Service,
    state: &PolicyState,
    ctx: &RequestCtx,
    body: &[u8],
) -> Option<Vec<u8>> {
    let mut events = sse::parse(body);
    let mut mutated = false;
    let mut truncate_at: Option<usize> = None;

    for (i, ev) in events.iter_mut().enumerate() {
        let Some(data) = ev.data.as_deref() else {
            continue;
        };
        let Ok(mut parsed) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        match scan_value_response(client, analyzer, state, ctx, &mut parsed).await {
            Some(ResponseOutcome::Blocked(asset, decision)) => {
                let err = block_body(asset, &parsed, &decision);
                ev.data = Some(serde_json::to_string(&err).unwrap_or_default());
                mutated = true;
                truncate_at = Some(i + 1);
                break;
            }
            Some(ResponseOutcome::Redacted) => {
                ev.data = Some(serde_json::to_string(&parsed).unwrap_or_default());
                mutated = true;
            }
            None => {}
        }
    }

    if let Some(n) = truncate_at {
        events.truncate(n);
    }
    if !mutated {
        return None;
    }
    Some(sse::serialize(&events))
}

enum ResponseOutcome {
    Blocked(AssetType, Decision),
    Redacted,
}

/// Classify + analyze + evaluate a single response JSON value, applying
/// redactions in place. Returns `None` when nothing changed.
async fn scan_value_response(
    client: &HttpClient,
    analyzer: &Service,
    state: &PolicyState,
    ctx: &RequestCtx,
    parsed: &mut Value,
) -> Option<ResponseOutcome> {
    let cfg = &state.cfg;
    let classified = detect::classify_response(parsed, cfg)?;
    if classified.fields.is_empty() {
        return None;
    }

    let field_results = match scan_fields(client, analyzer, cfg, &classified).await {
        Ok(r) => r,
        Err(e) => {
            logger::warn!("pii-shield-presidio: analyzer error on response: {e}");
            return None; // response leg cannot fail closed by status; pass body through
        }
    };

    let eval_ctx = EvalContext {
        asset_type: classified.asset_type,
        direction: Direction::Response,
        client_id: ctx.client_id.as_deref(),
        scopes: &ctx.scopes,
    };
    let decision = engine::evaluate(&field_results, cfg, &eval_ctx);
    emit_evidence(Direction::Response, classified.asset_type, &decision);

    if decision.block {
        return Some(ResponseOutcome::Blocked(classified.asset_type, decision));
    }
    if decision.any_redaction()
        && apply_redactions(
            client,
            state.anonymizer.as_ref(),
            cfg,
            parsed,
            &classified,
            &decision,
        )
        .await
    {
        return Some(ResponseOutcome::Redacted);
    }
    None
}

// ---------------------------------------------------------------------
// Presidio scanning + redaction.
// ---------------------------------------------------------------------

/// Analyze every scannable field. One analyzer round trip per field.
async fn scan_fields(
    client: &HttpClient,
    analyzer: &Service,
    cfg: &PolicyConfig,
    classified: &Classified,
) -> Result<Vec<Vec<RecognizerResult>>, PresidioError> {
    let mut out = Vec::with_capacity(classified.fields.len());
    for field in &classified.fields {
        let results = presidio::analyze(client, analyzer, cfg, &field.text).await?;
        out.push(results);
    }
    Ok(out)
}

/// Apply the decision's redactions in place. Returns whether the tree
/// changed. Never forwards the original on a confirmed detection: a
/// splice failure downgrades to a best-effort local rewrite.
async fn apply_redactions(
    client: &HttpClient,
    anonymizer: Option<&Service>,
    cfg: &PolicyConfig,
    parsed: &mut Value,
    classified: &Classified,
    decision: &Decision,
) -> bool {
    let mut changed = false;
    for fr in &decision.per_field {
        let Some(field) = classified.fields.get(fr.field_index) else {
            continue;
        };
        let wants_server = fr.redactions.iter().any(|(_, op)| op.server_side);
        let new_text = if wants_server && anonymizer.is_some() {
            match presidio::anonymize_remote(
                client,
                anonymizer.unwrap(),
                &cfg.anonymizer_path_prefix,
                cfg.presidio_timeout_ms,
                &field.text,
                &fr.redactions,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    logger::warn!(
                        "pii-shield-presidio: anonymizer error; local splice fallback: {e}"
                    );
                    presidio::anonymize_local(&field.text, &fr.redactions)
                }
            }
        } else {
            presidio::anonymize_local(&field.text, &fr.redactions)
        };
        if extract::set_text(parsed, &field.path, &new_text) {
            changed = true;
        }
    }
    changed
}

// ---------------------------------------------------------------------
// Evidence + error envelopes.
// ---------------------------------------------------------------------

impl Decision {
    fn action_label(&self) -> &'static str {
        if self.block {
            "blocked"
        } else if self.any_redaction() {
            "redacted"
        } else {
            "audited"
        }
    }
}

fn emit_evidence(direction: Direction, asset: AssetType, decision: &Decision) {
    let dir = match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    };
    Event {
        direction: dir,
        asset_type: asset.as_str(),
        action: decision.action_label(),
        detected: decision.any_detected(),
        entities: &decision.counts,
        note: None,
    }
    .emit();
}

fn set_evidence_headers(handler: &dyn HeadersHandler, decision: &Decision, action: &str) {
    handler.set_header(HEADER_DETECTED, "true");
    handler.set_header(HEADER_ENTITIES, &evidence::format_entities(&decision.counts));
    handler.set_header(HEADER_ACTION, action);
}

fn is_rpc_asset(asset: AssetType) -> bool {
    matches!(asset, AssetType::Mcp | AssetType::A2a)
}

fn block_body(asset: AssetType, parsed: &Value, decision: &Decision) -> Value {
    let detail = format!(
        "request blocked: PII detected ({})",
        evidence::format_entities(&decision.counts)
    );
    if is_rpc_asset(asset) {
        json!({
            "jsonrpc": "2.0",
            "id": parsed.get("id").cloned().unwrap_or(Value::Null),
            "error": { "code": JSON_RPC_INVALID_REQUEST, "message": detail }
        })
    } else {
        json!({ "error": detail, "entities": decision.counts })
    }
}

fn block_response(asset: AssetType, parsed: &Value, decision: &Decision) -> Response {
    let body = serde_json::to_vec(&block_body(asset, parsed, decision)).unwrap_or_default();
    Response::new(HTTP_UNPROCESSABLE)
        .with_headers(vec![
            ("content-type".into(), "application/json".into()),
            (HEADER_DETECTED.into(), "true".into()),
            (HEADER_ENTITIES.into(), evidence::format_entities(&decision.counts)),
            (HEADER_ACTION.into(), "blocked".into()),
        ])
        .with_body(body)
}

fn scan_unavailable_response(asset: AssetType, parsed: &Value) -> Response {
    if is_rpc_asset(asset) {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": parsed.get("id").cloned().unwrap_or(Value::Null),
            "error": { "code": JSON_RPC_INTERNAL_ERROR, "message": "PII scan unavailable" }
        }))
        .unwrap_or_default();
        Response::new(HTTP_UNPROCESSABLE)
            .with_headers(vec![("content-type".into(), "application/json".into())])
            .with_body(body)
    } else {
        plain_error(HTTP_UNAVAILABLE, "PII scan unavailable")
    }
}

fn plain_error(status: u32, message: &str) -> Response {
    let body = serde_json::to_vec(&json!({ "error": message })).unwrap_or_default();
    Response::new(status)
        .with_headers(vec![("content-type".into(), "application/json".into())])
        .with_body(body)
}

// ---------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------

fn is_json(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("application/json") || ct.contains("+json")
}

/// A2A version lookup used by the classifier: prefer the request header,
/// fall back to nothing (the classifier also inspects the query string).
fn header_lookup(name: &str, a2a_version: &Option<String>) -> Option<String> {
    if name.eq_ignore_ascii_case(a2a::A2A_VERSION_HEADER) || name.eq_ignore_ascii_case("A2A-Version")
    {
        return a2a_version.clone();
    }
    None
}

fn read_identity(auth: &Authentication) -> RequestCtx {
    match auth.authentication() {
        Some(data) => {
            let client_id = data.client_id.clone();
            let claims: Value = data.properties.into();
            RequestCtx {
                client_id,
                scopes: read_scopes(&claims),
            }
        }
        None => RequestCtx::default(),
    }
}

fn read_scopes(claims: &Value) -> Vec<String> {
    for key in ["scope", "scopes", "scp"] {
        match claims.get(key) {
            Some(Value::String(s)) => return split_scopes(s),
            Some(Value::Array(arr)) => {
                return arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            }
            _ => {}
        }
    }
    Vec::new()
}

fn split_scopes(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_content_type_detection() {
        assert!(is_json("application/json"));
        assert!(is_json("application/json; charset=utf-8"));
        assert!(is_json("application/vnd.api+json"));
        assert!(!is_json("text/plain"));
        assert!(!is_json("text/event-stream"));
    }

    #[test]
    fn scopes_parse_string_and_array() {
        assert_eq!(
            read_scopes(&json!({"scope": "pii.read pci.read"})),
            vec!["pii.read", "pci.read"]
        );
        assert_eq!(
            read_scopes(&json!({"scopes": ["a", "b"]})),
            vec!["a", "b"]
        );
        assert!(read_scopes(&json!({"other": 1})).is_empty());
    }

    #[test]
    fn rpc_block_body_is_jsonrpc_error() {
        let mut decision = Decision::default();
        decision.counts.insert("EMAIL_ADDRESS".into(), 1);
        let parsed = json!({"jsonrpc":"2.0","id":7,"method":"SendMessage"});
        let body = block_body(AssetType::A2a, &parsed, &decision);
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], JSON_RPC_INVALID_REQUEST);
    }

    #[test]
    fn generic_block_body_is_plain_error() {
        let mut decision = Decision::default();
        decision.counts.insert("PERSON".into(), 2);
        let body = block_body(AssetType::Generic, &json!({}), &decision);
        assert!(body.get("error").is_some());
        assert_eq!(body["entities"]["PERSON"], 2);
    }
}
