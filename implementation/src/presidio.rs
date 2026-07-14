//! Presidio Analyzer / Anonymizer client and payload (de)serialization.
//!
//! The pure helpers (`build_analyze_body`, `parse_analyze_response`,
//! `anonymize_local`, ...) are host-testable; the `analyze` /
//! `anonymize_remote` async fns wrap them around the PDK HTTP client.

use std::time::Duration;

use pdk::hl::{HttpClient, Service};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{Operator, OperatorKind, PolicyConfig};

#[derive(Debug, thiserror::Error)]
pub enum PresidioError {
    #[error("presidio transport error: {0}")]
    Transport(String),
    #[error("presidio returned HTTP {status}: {body}")]
    HttpStatus { status: u32, body: String },
    #[error("presidio returned malformed payload: {0}")]
    BadPayload(String),
}

/// One analyzer finding. Offsets are Unicode code-point indices into the
/// analyzed text (matching Presidio's Python string semantics).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RecognizerResult {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

/// Build the `/analyze` request body from policy config + text.
pub fn build_analyze_body(cfg: &PolicyConfig, text: &str) -> Value {
    let mut body = json!({
        "text": text,
        "language": cfg.language,
        "score_threshold": cfg.score_threshold,
    });
    let map = body.as_object_mut().unwrap();
    if !cfg.entities.is_empty() {
        map.insert("entities".into(), json!(cfg.entities));
    }
    if !cfg.allow_list.is_empty() {
        map.insert("allow_list".into(), json!(cfg.allow_list));
    }
    if !cfg.context_words.is_empty() {
        map.insert("context".into(), json!(cfg.context_words));
    }
    if !cfg.ad_hoc_recognizers.is_empty() {
        map.insert("ad_hoc_recognizers".into(), json!(cfg.ad_hoc_recognizers));
    }
    body
}

/// Parse an `/analyze` response body into recognizer results, dropping
/// any below `score_threshold` (defensive — Presidio already filters).
pub fn parse_analyze_response(
    bytes: &[u8],
    score_threshold: f64,
) -> Result<Vec<RecognizerResult>, PresidioError> {
    let results: Vec<RecognizerResult> = serde_json::from_slice(bytes)
        .map_err(|e| PresidioError::BadPayload(e.to_string()))?;
    Ok(results
        .into_iter()
        .filter(|r| r.score >= score_threshold && r.end >= r.start)
        .collect())
}

/// Call `POST {analyzer}/analyze` for a single text.
pub async fn analyze(
    client: &HttpClient,
    service: &Service,
    cfg: &PolicyConfig,
    text: &str,
) -> Result<Vec<RecognizerResult>, PresidioError> {
    let body = serde_json::to_vec(&build_analyze_body(cfg, text))
        .map_err(|e| PresidioError::BadPayload(e.to_string()))?;
    let authority = service.uri().authority().to_string();
    let headers = vec![
        ("host", authority.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json"),
    ];
    let response = client
        .request(service)
        .path("/analyze")
        .timeout(Duration::from_millis(cfg.presidio_timeout_ms))
        .headers(headers)
        .body(&body)
        .post()
        .await
        .map_err(|e| PresidioError::Transport(format!("{e:?}")))?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(PresidioError::HttpStatus {
            status,
            body: String::from_utf8_lossy(response.body()).to_string(),
        });
    }
    parse_analyze_response(response.body(), cfg.score_threshold)
}

/// Presidio operator name for a local/remote operator kind.
fn operator_type(kind: OperatorKind) -> &'static str {
    match kind {
        OperatorKind::Replace => "replace",
        OperatorKind::Mask => "mask",
        OperatorKind::Hash => "hash",
        OperatorKind::Redact => "redact",
    }
}

/// Build the `/anonymize` request body for server-side anonymization.
pub fn build_anonymize_body(text: &str, redactions: &[(RecognizerResult, Operator)]) -> Value {
    let mut anonymizers = serde_json::Map::new();
    let mut analyzer_results = Vec::new();
    for (res, op) in redactions {
        let mut spec = serde_json::Map::new();
        spec.insert("type".into(), json!(operator_type(op.kind)));
        match op.kind {
            OperatorKind::Replace => {
                let new_value = op
                    .new_value
                    .clone()
                    .unwrap_or_else(|| format!("<{}>", res.entity_type));
                spec.insert("new_value".into(), json!(new_value));
            }
            OperatorKind::Mask => {
                spec.insert("masking_char".into(), json!(op.masking_char.to_string()));
                spec.insert("chars_to_mask".into(), json!(op.chars_to_mask));
                spec.insert("from_end".into(), json!(op.from_end));
            }
            OperatorKind::Hash => {
                spec.insert("hash_type".into(), json!("sha256"));
            }
            OperatorKind::Redact => {}
        }
        anonymizers.insert(res.entity_type.clone(), Value::Object(spec));
        analyzer_results.push(json!({
            "entity_type": res.entity_type,
            "start": res.start,
            "end": res.end,
            "score": res.score,
        }));
    }
    json!({
        "text": text,
        "anonymizers": anonymizers,
        "analyzer_results": analyzer_results,
    })
}

/// Parse an `/anonymize` response, returning the anonymized text.
pub fn parse_anonymize_response(bytes: &[u8]) -> Result<String, PresidioError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| PresidioError::BadPayload(e.to_string()))?;
    value
        .get("text")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| PresidioError::BadPayload("missing `text` in anonymize response".into()))
}

/// Call `POST {anonymizer}/anonymize` for a single text.
pub async fn anonymize_remote(
    client: &HttpClient,
    service: &Service,
    timeout_ms: u64,
    text: &str,
    redactions: &[(RecognizerResult, Operator)],
) -> Result<String, PresidioError> {
    let body = serde_json::to_vec(&build_anonymize_body(text, redactions))
        .map_err(|e| PresidioError::BadPayload(e.to_string()))?;
    let authority = service.uri().authority().to_string();
    let headers = vec![
        ("host", authority.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json"),
    ];
    let response = client
        .request(service)
        .path("/anonymize")
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .body(&body)
        .post()
        .await
        .map_err(|e| PresidioError::Transport(format!("{e:?}")))?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(PresidioError::HttpStatus {
            status,
            body: String::from_utf8_lossy(response.body()).to_string(),
        });
    }
    parse_anonymize_response(response.body())
}

/// Splice redactions into `text` locally from analyzer offsets — no
/// second round trip. Operating on code points matches Presidio's
/// offset semantics. Overlapping spans are resolved highest-start-first.
pub fn anonymize_local(text: &str, redactions: &[(RecognizerResult, Operator)]) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut ordered: Vec<&(RecognizerResult, Operator)> = redactions.iter().collect();
    ordered.sort_by(|a, b| b.0.start.cmp(&a.0.start));

    let mut last_start = len + 1;
    for (res, op) in ordered {
        if res.start > res.end || res.end > chars.len() {
            continue;
        }
        // Skip spans that overlap one we already spliced (defensive).
        if res.end > last_start {
            continue;
        }
        let span = &chars[res.start..res.end];
        let replacement = render(op, span, &res.entity_type);
        chars.splice(res.start..res.end, replacement);
        last_start = res.start;
    }
    chars.into_iter().collect()
}

fn render(op: &Operator, span: &[char], entity_type: &str) -> Vec<char> {
    match op.kind {
        OperatorKind::Replace => op
            .new_value
            .clone()
            .unwrap_or_else(|| format!("<{entity_type}>"))
            .chars()
            .collect(),
        OperatorKind::Redact => Vec::new(),
        OperatorKind::Hash => {
            let s: String = span.iter().collect();
            let digest = Sha256::digest(s.as_bytes());
            hex(&digest)
        }
        OperatorKind::Mask => {
            let n = span.len();
            let count = if op.chars_to_mask == 0 {
                n
            } else {
                op.chars_to_mask.min(n)
            };
            let mut out = span.to_vec();
            if op.from_end {
                for slot in out.iter_mut().skip(n - count) {
                    *slot = op.masking_char;
                }
            } else {
                for slot in out.iter_mut().take(count) {
                    *slot = op.masking_char;
                }
            }
            out
        }
    }
}

fn hex(bytes: &[u8]) -> Vec<char> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(kind: OperatorKind) -> Operator {
        Operator {
            kind,
            ..Operator::default()
        }
    }

    fn res(entity: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult {
            entity_type: entity.into(),
            start,
            end,
            score: 0.9,
        }
    }

    #[test]
    fn analyze_body_includes_optional_fields_only_when_set() {
        use crate::generated::config::Config;
        let raw: Config = serde_json::from_value(serde_json::json!({
            "entities": ["EMAIL_ADDRESS"],
            "allowList": ["ok@corp.com"],
            "contextWords": ["email"],
            "scoreThreshold": 0.7
        }))
        .unwrap();
        let cfg = PolicyConfig::from_parts("http://a".into(), &raw).unwrap();
        let body = build_analyze_body(&cfg, "hi");
        assert_eq!(body["text"], "hi");
        assert_eq!(body["score_threshold"], 0.7);
        assert_eq!(body["entities"][0], "EMAIL_ADDRESS");
        assert_eq!(body["allow_list"][0], "ok@corp.com");
        assert_eq!(body["context"][0], "email");
    }

    #[test]
    fn parse_analyze_filters_by_threshold() {
        let body = br#"[{"entity_type":"EMAIL_ADDRESS","start":0,"end":5,"score":0.9},
                        {"entity_type":"PERSON","start":6,"end":9,"score":0.2}]"#;
        let results = parse_analyze_response(body, 0.5).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn local_replace_default_placeholder() {
        let text = "email me at a@b.com now";
        let reds = vec![(res("EMAIL_ADDRESS", 12, 19), op(OperatorKind::Replace))];
        assert_eq!(anonymize_local(text, &reds), "email me at <EMAIL_ADDRESS> now");
    }

    #[test]
    fn local_redact_removes_span() {
        let text = "ssn 123-45-6789.";
        let reds = vec![(res("US_SSN", 4, 15), op(OperatorKind::Redact))];
        assert_eq!(anonymize_local(text, &reds), "ssn .");
    }

    #[test]
    fn local_mask_from_end() {
        let text = "card 4111111111111111";
        let mut o = op(OperatorKind::Mask);
        o.chars_to_mask = 12;
        o.from_end = true;
        let reds = vec![(res("CREDIT_CARD", 5, 21), o)];
        assert_eq!(anonymize_local(text, &reds), "card 4111************");
    }

    #[test]
    fn local_hash_is_deterministic_hex() {
        let text = "x a@b.com";
        let reds = vec![(res("EMAIL_ADDRESS", 2, 9), op(OperatorKind::Hash))];
        let out = anonymize_local(text, &reds);
        assert!(out.starts_with("x "));
        let hashed = &out[2..];
        assert_eq!(hashed.len(), 64);
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn multiple_spans_spliced_right_to_left() {
        // "a@b.com and c@d.com"
        let text = "a@b.com and c@d.com";
        let reds = vec![
            (res("EMAIL_ADDRESS", 0, 7), op(OperatorKind::Replace)),
            (res("EMAIL_ADDRESS", 12, 19), op(OperatorKind::Replace)),
        ];
        assert_eq!(
            anonymize_local(text, &reds),
            "<EMAIL_ADDRESS> and <EMAIL_ADDRESS>"
        );
    }

    #[test]
    fn anonymize_body_shapes_per_operator() {
        let reds = vec![(res("EMAIL_ADDRESS", 0, 5), op(OperatorKind::Replace))];
        let body = build_anonymize_body("hello", &reds);
        assert_eq!(body["anonymizers"]["EMAIL_ADDRESS"]["type"], "replace");
        assert_eq!(
            body["anonymizers"]["EMAIL_ADDRESS"]["new_value"],
            "<EMAIL_ADDRESS>"
        );
        assert_eq!(body["analyzer_results"][0]["start"], 0);
    }
}
