//! End-to-end pipeline tests over the pure building blocks: classify →
//! (mocked analyzer results) → evaluate → redact/block. These exercise
//! the same code paths the WASM filter drives, without a live Presidio
//! or an Envoy worker.

use pii_shield_presidio_policy::config::{Direction, PolicyConfig};
use pii_shield_presidio_policy::engine::{self, EvalContext};
use pii_shield_presidio_policy::extract;
use pii_shield_presidio_policy::generated::config::Config;
use pii_shield_presidio_policy::presidio::{anonymize_local, RecognizerResult};
use pii_shield_presidio_policy::{a2a, detect};
use serde_json::{json, Value};

fn config(json: Value) -> PolicyConfig {
    let raw: Config = serde_json::from_value(json).unwrap();
    PolicyConfig::from_parts("http://analyzer:5001".into(), &raw).unwrap()
}

/// Stand-in for the Presidio analyzer: finds every occurrence of a fixed
/// set of needles in a text and returns recognizer results with offsets.
fn fake_analyze(text: &str, needles: &[(&str, &str)]) -> Vec<RecognizerResult> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    for (needle, entity) in needles {
        let nchars: Vec<char> = needle.chars().collect();
        let mut i = 0;
        while i + nchars.len() <= chars.len() {
            if chars[i..i + nchars.len()] == nchars[..] {
                out.push(RecognizerResult {
                    entity_type: (*entity).to_string(),
                    start: i,
                    end: i + nchars.len(),
                    score: 0.95,
                });
                i += nchars.len();
            } else {
                i += 1;
            }
        }
    }
    out
}

fn scan_and_apply(
    cfg: &PolicyConfig,
    body: &mut Value,
    classified_fields: &[extract::Field],
    asset: pii_shield_presidio_policy::config::AssetType,
    direction: Direction,
    needles: &[(&str, &str)],
) -> engine::Decision {
    let field_results: Vec<Vec<RecognizerResult>> = classified_fields
        .iter()
        .map(|f| fake_analyze(&f.text, needles))
        .collect();
    let ctx = EvalContext {
        asset_type: asset,
        direction,
        client_id: None,
        scopes: &[],
    };
    let decision = engine::evaluate(&field_results, cfg, &ctx);
    for fr in &decision.per_field {
        let field = &classified_fields[fr.field_index];
        let new_text = anonymize_local(&field.text, &fr.redactions);
        extract::set_text(body, &field.path, &new_text);
    }
    decision
}

#[test]
fn a2a_request_redacts_email_in_place() {
    let cfg = config(json!({
        "rules": [
            {"entityType": "EMAIL_ADDRESS", "action": "redact",
             "operator": {"kind": "replace", "newValue": "[email]"}}
        ]
    }));
    let mut body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
        "params": {"message": {"parts": [
            {"text": "reach me at bob@corp.com please"},
            {"file": {"uri": "http://x"}}
        ]}}
    });
    let classified =
        detect::classify_request(&body, "/rpc?A2A-Version=1.0", |_| None, &cfg).unwrap();
    let decision = scan_and_apply(
        &cfg,
        &mut body,
        &classified.fields,
        classified.asset_type,
        Direction::Request,
        &[("bob@corp.com", "EMAIL_ADDRESS")],
    );
    assert!(!decision.block);
    assert_eq!(decision.counts["EMAIL_ADDRESS"], 1);
    assert_eq!(
        body.pointer("/params/message/parts/0/text").unwrap(),
        &json!("reach me at [email] please")
    );
    // Non-text part preserved byte-faithful.
    assert_eq!(
        body.pointer("/params/message/parts/1/file/uri").unwrap(),
        &json!("http://x")
    );
}

#[test]
fn mcp_request_blocks_on_credit_card() {
    let cfg = config(json!({
        "rules": [{"entityType": "CREDIT_CARD", "action": "block"}]
    }));
    let body = json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "pay", "arguments": {"card": "4111111111111111"}}
    });
    let classified = detect::classify_request(&body, "/mcp", |_| None, &cfg).unwrap();
    let field_results: Vec<Vec<RecognizerResult>> = classified
        .fields
        .iter()
        .map(|f| fake_analyze(&f.text, &[("4111111111111111", "CREDIT_CARD")]))
        .collect();
    let ctx = EvalContext {
        asset_type: classified.asset_type,
        direction: Direction::Request,
        client_id: None,
        scopes: &[],
    };
    let decision = engine::evaluate(&field_results, &cfg, &ctx);
    assert!(decision.block);
    assert_eq!(decision.blocked_entities, vec!["CREDIT_CARD"]);
}

#[test]
fn audit_default_is_passthrough_observability() {
    // Empty ruleset + defaultAction audit ⇒ detect but never modify.
    let cfg = config(json!({}));
    let mut body = json!({"note": "call me at 555-123-4567"});
    let classified = detect::classify_request(&body, "/api", |_| None, &cfg).unwrap();
    let before = body.clone();
    let decision = scan_and_apply(
        &cfg,
        &mut body,
        &classified.fields,
        classified.asset_type,
        Direction::Request,
        &[("555-123-4567", "PHONE_NUMBER")],
    );
    assert!(!decision.block);
    assert!(!decision.any_redaction());
    assert_eq!(decision.audited, 1);
    assert_eq!(body, before, "audit must not modify the body");
}

#[test]
fn a2a_response_task_artifacts_masked() {
    let cfg = config(json!({
        "direction": "response",
        "rules": [
            {"entityType": "US_SSN", "action": "redact",
             "operator": {"kind": "mask", "maskingChar": "#", "charsToMask": 7}}
        ]
    }));
    let mut body = json!({
        "jsonrpc": "2.0", "id": 3,
        "result": {"task": {
            "status": {"message": {"parts": [{"text": "SSN 123-45-6789 on file"}]}},
            "artifacts": [{"parts": [{"text": "dup 123-45-6789"}]}]
        }}
    });
    let classified = detect::classify_response(&body, &cfg).unwrap();
    let decision = scan_and_apply(
        &cfg,
        &mut body,
        &classified.fields,
        classified.asset_type,
        Direction::Response,
        &[("123-45-6789", "US_SSN")],
    );
    assert!(!decision.block);
    assert_eq!(decision.counts["US_SSN"], 2);
    let status_text = body
        .pointer("/result/task/status/message/parts/0/text")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(status_text.starts_with("SSN #######"), "got {status_text}");
    assert!(!status_text.contains("123-45-6789"));
}

#[test]
fn scoped_caller_audited_others_redacted() {
    let cfg = config(json!({
        "rules": [
            {"entityType": "EMAIL_ADDRESS", "audienceType": "scope",
             "audienceValue": "pii.read", "action": "audit"},
            {"entityType": "EMAIL_ADDRESS", "action": "redact"}
        ]
    }));
    let body = json!({"note": "a@b.com"});
    let classified = detect::classify_request(&body, "/api", |_| None, &cfg).unwrap();
    let results: Vec<Vec<RecognizerResult>> = classified
        .fields
        .iter()
        .map(|f| fake_analyze(&f.text, &[("a@b.com", "EMAIL_ADDRESS")]))
        .collect();

    let privileged = vec!["pii.read".to_string()];
    let priv_ctx = EvalContext {
        asset_type: classified.asset_type,
        direction: Direction::Request,
        client_id: None,
        scopes: &privileged,
    };
    let d1 = engine::evaluate(&results, &cfg, &priv_ctx);
    assert!(!d1.any_redaction(), "privileged caller only audited");

    let anon_ctx = EvalContext {
        asset_type: classified.asset_type,
        direction: Direction::Request,
        client_id: None,
        scopes: &[],
    };
    let d2 = engine::evaluate(&results, &cfg, &anon_ctx);
    assert!(d2.any_redaction(), "unscoped caller redacted");
}

#[test]
fn a2a_variant_detection_end_to_end() {
    // Legacy body without A2A-Version marker but with kind:text parts.
    let cfg = config(json!({"assetTypes": ["a2a"]}));
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "message/send",
        "params": {"message": {"parts": [{"kind": "text", "text": "hi a@b.com"}]}}
    });
    let classified = detect::classify_request(&body, "/rpc", |_| None, &cfg).unwrap();
    assert_eq!(
        classified.asset_type,
        pii_shield_presidio_policy::config::AssetType::A2a
    );
    assert_eq!(classified.fields.len(), 1);
    // Sanity: variant detection agrees.
    assert_eq!(a2a::detect_variant("/rpc", |_| None), a2a::Variant::Legacy);
}
