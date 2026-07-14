//! Protocol-aware payload classification.
//!
//! Given a parsed JSON body and the request context, decide which
//! agentic asset class the traffic belongs to (MCP / A2A / LLM /
//! generic) and hand back the scannable text leaves for that shape.
//! `scanTargets` (JSONPath) short-circuits auto-classification.
//! Anything that doesn't classify — or classifies to a class the
//! operator excluded — yields `None` (pass through untouched).

use serde_json::Value;

use crate::a2a;
use crate::config::{AssetType, PolicyConfig};
use crate::extract::{collect_by_jsonpath, collect_string_leaves, Field, PathSeg};
use crate::mcp;

#[derive(Debug)]
pub struct Classified {
    pub asset_type: AssetType,
    pub fields: Vec<Field>,
}

fn is_json_rpc(body: &Value) -> bool {
    body.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
}

// ---------------------------------------------------------------------
// LLM shapes (OpenAI / Anthropic style).
// ---------------------------------------------------------------------

fn llm_extract_content(content: &Value, base: Vec<PathSeg>, out: &mut Vec<Field>) {
    match content {
        Value::String(s) => out.push(Field::new(base, s.clone())),
        Value::Array(blocks) => {
            for (i, block) in blocks.iter().enumerate() {
                if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                    if let Some(Value::String(text)) = block.get("text") {
                        let mut p = base.clone();
                        p.push(PathSeg::Index(i));
                        p.push(PathSeg::Key("text".into()));
                        out.push(Field::new(p, text.clone()));
                    }
                }
            }
        }
        _ => {}
    }
}

fn llm_extract_request(body: &Value) -> Vec<Field> {
    let mut out = Vec::new();
    if let Some(Value::Array(messages)) = body.get("messages") {
        for (i, msg) in messages.iter().enumerate() {
            if let Some(content) = msg.get("content") {
                let base = vec![
                    PathSeg::Key("messages".into()),
                    PathSeg::Index(i),
                    PathSeg::Key("content".into()),
                ];
                llm_extract_content(content, base, &mut out);
            }
        }
    }
    out
}

fn llm_extract_response(body: &Value) -> Vec<Field> {
    let mut out = Vec::new();
    // OpenAI: choices[*].message.content / choices[*].delta.content
    if let Some(Value::Array(choices)) = body.get("choices") {
        for (i, choice) in choices.iter().enumerate() {
            for key in ["message", "delta"] {
                if let Some(content) = choice.pointer(&format!("/{key}/content")) {
                    let base = vec![
                        PathSeg::Key("choices".into()),
                        PathSeg::Index(i),
                        PathSeg::Key(key.into()),
                        PathSeg::Key("content".into()),
                    ];
                    llm_extract_content(content, base, &mut out);
                }
            }
        }
    }
    // Anthropic: top-level content[*].text
    if let Some(content @ Value::Array(_)) = body.get("content") {
        llm_extract_content(content, vec![PathSeg::Key("content".into())], &mut out);
    }
    out
}

fn is_llm_request(body: &Value) -> bool {
    body.get("messages").map(|m| m.is_array()).unwrap_or(false)
}

fn is_llm_response(body: &Value) -> bool {
    body.get("choices").map(|c| c.is_array()).unwrap_or(false)
        || (body.get("content").map(|c| c.is_array()).unwrap_or(false)
            && body.get("role").is_some())
}

// ---------------------------------------------------------------------
// Classification entrypoints.
// ---------------------------------------------------------------------

/// Classify a request body. `path` and `get_header` feed A2A binding
/// detection.
pub fn classify_request(
    body: &Value,
    path: &str,
    get_header: impl FnMut(&str) -> Option<String>,
    cfg: &PolicyConfig,
) -> Option<Classified> {
    if !cfg.scan_targets.is_empty() {
        return scan_targets(body, cfg);
    }

    let variant = a2a::detect_variant(path, get_header);

    if is_json_rpc(body) {
        let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
        if mcp::is_tools_call(body) {
            return gate(cfg, AssetType::Mcp, mcp::extract_request(body));
        }
        if a2a::is_supported_method(method, variant) {
            return gate(
                cfg,
                AssetType::A2a,
                a2a::extract_request(body, variant, cfg.scan_data_parts),
            );
        }
        // Unrecognized JSON-RPC control frame — only scan when the
        // operator opted generic traffic in.
        return generic(body, cfg);
    }

    if is_llm_request(body) {
        return gate(cfg, AssetType::Llm, llm_extract_request(body));
    }

    if variant == a2a::Variant::V1 {
        let a2a_fields = a2a::extract_request(body, variant, cfg.scan_data_parts);
        if !a2a_fields.is_empty() {
            return gate(cfg, AssetType::A2a, a2a_fields);
        }
    }

    generic(body, cfg)
}

/// Classify a response body (already de-framed from any SSE envelope).
pub fn classify_response(body: &Value, cfg: &PolicyConfig) -> Option<Classified> {
    if !cfg.scan_targets.is_empty() {
        return scan_targets(body, cfg);
    }

    if is_llm_response(body) {
        return gate(cfg, AssetType::Llm, llm_extract_response(body));
    }
    if mcp::is_tool_result(body) {
        return gate(cfg, AssetType::Mcp, mcp::extract_response(body));
    }
    let a2a_fields = a2a::extract_response(body, cfg.scan_data_parts);
    if !a2a_fields.is_empty() {
        return gate(cfg, AssetType::A2a, a2a_fields);
    }

    generic(body, cfg)
}

fn gate(cfg: &PolicyConfig, asset: AssetType, fields: Vec<Field>) -> Option<Classified> {
    if !cfg.inspects(asset) {
        return None;
    }
    Some(Classified {
        asset_type: asset,
        fields,
    })
}

fn generic(body: &Value, cfg: &PolicyConfig) -> Option<Classified> {
    if !cfg.inspects(AssetType::Generic) {
        return None;
    }
    let mut fields = Vec::new();
    collect_string_leaves(body, &[], &mut fields);
    Some(Classified {
        asset_type: AssetType::Generic,
        fields,
    })
}

fn scan_targets(body: &Value, cfg: &PolicyConfig) -> Option<Classified> {
    let mut fields = Vec::new();
    for target in &cfg.scan_targets {
        collect_by_jsonpath(body, &target.path, &mut fields);
    }
    Some(Classified {
        asset_type: AssetType::Generic,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::config::Config;

    fn cfg_with(json: serde_json::Value) -> PolicyConfig {
        let raw: Config = serde_json::from_value(json).unwrap();
        PolicyConfig::from_parts("http://analyzer".into(), &raw).unwrap()
    }

    fn base_cfg() -> PolicyConfig {
        cfg_with(serde_json::json!({}))
    }

    #[test]
    fn classifies_mcp_request() {
        let body = serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"arguments":{"q":"email a@b.com"}}
        });
        let c = classify_request(&body, "/mcp", |_| None, &base_cfg()).unwrap();
        assert_eq!(c.asset_type, AssetType::Mcp);
        assert_eq!(c.fields.len(), 1);
    }

    #[test]
    fn classifies_a2a_v1_request() {
        let body = serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"SendMessage",
            "params":{"message":{"parts":[{"text":"hi a@b.com"}]}}
        });
        let c = classify_request(&body, "/rpc?A2A-Version=1.0", |_| None, &base_cfg()).unwrap();
        assert_eq!(c.asset_type, AssetType::A2a);
    }

    #[test]
    fn classifies_llm_request() {
        let body = serde_json::json!({
            "model":"gpt","messages":[{"role":"user","content":"my ssn is 123-45-6789"}]
        });
        let c = classify_request(&body, "/v1/chat", |_| None, &base_cfg()).unwrap();
        assert_eq!(c.asset_type, AssetType::Llm);
        assert_eq!(c.fields[0].text, "my ssn is 123-45-6789");
    }

    #[test]
    fn classifies_generic_json() {
        let body = serde_json::json!({"note":"call 555-1234"});
        let c = classify_request(&body, "/api", |_| None, &base_cfg()).unwrap();
        assert_eq!(c.asset_type, AssetType::Generic);
    }

    #[test]
    fn asset_type_filter_excludes() {
        let cfg = cfg_with(serde_json::json!({"assetTypes":["mcp"]}));
        let body = serde_json::json!({"note":"call 555-1234"});
        assert!(classify_request(&body, "/api", |_| None, &cfg).is_none());
    }

    #[test]
    fn scan_targets_override() {
        let cfg = cfg_with(serde_json::json!({"scanTargets":["$.user.email"]}));
        let body = serde_json::json!({"user":{"email":"a@b.com","name":"Bob"}});
        let c = classify_request(&body, "/api", |_| None, &cfg).unwrap();
        assert_eq!(c.fields.len(), 1);
        assert_eq!(c.fields[0].text, "a@b.com");
    }

    #[test]
    fn llm_openai_response() {
        let body = serde_json::json!({
            "choices":[{"index":0,"message":{"role":"assistant","content":"reach me at a@b.com"}}]
        });
        let c = classify_response(&body, &base_cfg()).unwrap();
        assert_eq!(c.asset_type, AssetType::Llm);
        assert_eq!(c.fields[0].text, "reach me at a@b.com");
    }
}
