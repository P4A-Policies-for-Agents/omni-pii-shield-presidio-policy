//! A2A payload shapes, protocol-variant detection, and text traversal.
//!
//! Both the V1 (`A2A-Version: 1.0`) and Legacy JSON-RPC bindings — plus
//! the V1 HTTP+JSON binding (bare body, URL-routed) — carry the same
//! `Message` / `Task` / `Part` shapes; only the wire framing and the
//! location of the text parts differ. Text parts are always scanned;
//! `DataPart` payloads are scanned as generic JSON string leaves when
//! `scanDataParts` is on; `FilePart` entries are never scanned in v1.

use serde_json::Value;

use crate::extract::{collect_string_leaves, Field, PathSeg};

/// Canonical lowercase A2A version header name.
pub const A2A_VERSION_HEADER: &str = "a2a-version";
pub const A2A_V1_VERSION: &str = "1.0";

// V1 JSON-RPC / HTTP+JSON method names.
pub const V1_METHODS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "SubscribeToTask",
    "ListTasks",
    "CancelTask",
];

// Legacy JSON-RPC method names.
pub const LEGACY_METHODS: &[&str] = &[
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/stream",
    "tasks/resubscribe",
    "tasks/cancel",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    V1,
    Legacy,
}

/// True when the `A2A-Version=1.0` marker appears in the request path
/// (query string) in any common casing.
pub fn version_v1_in_path(path: &str) -> bool {
    path.contains("A2A-Version=1.0")
        || path.contains("A2A-VERSION=1.0")
        || path.contains("a2a-version=1.0")
}

/// Detect the A2A binding variant from the request path and a header
/// lookup. Presence of the `A2A-Version: 1.0` signal (header or query)
/// selects V1; its absence selects Legacy.
pub fn detect_variant(path: &str, mut get_header: impl FnMut(&str) -> Option<String>) -> Variant {
    let header_v1 = get_header(A2A_VERSION_HEADER)
        .or_else(|| get_header("A2A-Version"))
        .or_else(|| get_header("A2A-VERSION"))
        .map(|v| v.trim() == A2A_V1_VERSION)
        .unwrap_or(false);
    if header_v1 || version_v1_in_path(path) {
        Variant::V1
    } else {
        Variant::Legacy
    }
}

pub fn is_v1_method(method: &str) -> bool {
    V1_METHODS.contains(&method)
}

pub fn is_legacy_method(method: &str) -> bool {
    LEGACY_METHODS.contains(&method)
}

/// Whether `method` is an A2A message/task method for the given variant.
pub fn is_supported_method(method: &str, variant: Variant) -> bool {
    match variant {
        Variant::V1 => is_v1_method(method),
        Variant::Legacy => is_legacy_method(method),
    }
}

/// Whether a JSON value is a text part for the given variant.
fn is_text_part(value: &Value, variant: Variant) -> bool {
    if !value.is_object() {
        return false;
    }
    match variant {
        Variant::V1 => value.get("text").and_then(|v| v.as_str()).is_some(),
        Variant::Legacy => {
            let kind = value
                .get("kind")
                .or_else(|| value.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            kind == "text" && value.get("text").and_then(|v| v.as_str()).is_some()
        }
    }
}

/// Whether a JSON value is a data part (structured payload).
fn is_data_part(value: &Value) -> bool {
    value.is_object() && value.get("data").map(|d| d.is_object() || d.is_array()).unwrap_or(false)
}

fn keys(parts: &[&str]) -> Vec<PathSeg> {
    parts.iter().map(|k| PathSeg::Key((*k).to_string())).collect()
}

/// Scan a `parts` array located at `base` (a resolved path into `root`).
fn scan_parts_at(
    root: &Value,
    base: Vec<PathSeg>,
    variant: Variant,
    scan_data_parts: bool,
    out: &mut Vec<Field>,
) {
    let Some(Value::Array(parts)) = crate::extract::get(root, &base) else {
        return;
    };
    for (i, part) in parts.iter().enumerate() {
        if is_text_part(part, variant) {
            if let Some(Value::String(text)) = part.get("text") {
                let mut p = base.clone();
                p.push(PathSeg::Index(i));
                p.push(PathSeg::Key("text".into()));
                out.push(Field::new(p, text.clone()));
            }
        } else if scan_data_parts && is_data_part(part) {
            if let Some(data) = part.get("data") {
                let mut p = base.clone();
                p.push(PathSeg::Index(i));
                p.push(PathSeg::Key("data".into()));
                collect_string_leaves(data, &p, out);
            }
        }
    }
}

/// Scan every `parts` array inside an `artifacts[*]` array at `base`.
fn scan_artifacts_at(
    root: &Value,
    base: Vec<PathSeg>,
    variant: Variant,
    scan_data_parts: bool,
    out: &mut Vec<Field>,
) {
    let Some(Value::Array(artifacts)) = crate::extract::get(root, &base) else {
        return;
    };
    for i in 0..artifacts.len() {
        let mut p = base.clone();
        p.push(PathSeg::Index(i));
        p.push(PathSeg::Key("parts".into()));
        scan_parts_at(root, p, variant, scan_data_parts, out);
    }
}

const REQUEST_PART_BASES: &[&[&str]] = &[
    &["params", "message", "parts"],
    &["params", "task", "parts"],
    &["message", "parts"],
    &["task", "parts"],
];

const REQUEST_DESCRIPTION_PATHS: &[&[&str]] = &[
    &["params", "task", "description"],
    &["task", "description"],
];

const RESPONSE_PART_BASES: &[&[&str]] = &[
    &["result", "status", "message", "parts"],
    &["result", "message", "parts"],
    &["result", "parts"],
    &["result", "task", "parts"],
    &["result", "task", "status", "message", "parts"],
    &["result", "artifact", "parts"],
    &["result", "statusUpdate", "status", "message", "parts"],
    &["result", "artifactUpdate", "artifact", "parts"],
];

const RESPONSE_ARTIFACT_BASES: &[&[&str]] = &[
    &["result", "artifacts"],
    &["result", "task", "artifacts"],
];

/// Extract scannable text from an A2A request envelope (JSON-RPC or the
/// V1 HTTP+JSON bare body).
pub fn extract_request(value: &Value, variant: Variant, scan_data_parts: bool) -> Vec<Field> {
    let mut out = Vec::new();
    for base in REQUEST_PART_BASES {
        scan_parts_at(value, keys(base), variant, scan_data_parts, &mut out);
    }
    for path in REQUEST_DESCRIPTION_PATHS {
        let p = keys(path);
        if let Some(Value::String(text)) = crate::extract::get(value, &p) {
            out.push(Field::new(p, text.clone()));
        }
    }
    out
}

/// Extract scannable text from an A2A response envelope (Message / Task,
/// including SSE `status-update` / `artifact-update` event bodies).
pub fn extract_response(value: &Value, scan_data_parts: bool) -> Vec<Field> {
    let mut out = Vec::new();
    // Response text-part detection is binding-agnostic: accept a text
    // field regardless of `kind`, matching real V1 + Legacy responses.
    for base in RESPONSE_PART_BASES {
        scan_parts_at(value, keys(base), Variant::V1, scan_data_parts, &mut out);
    }
    for base in RESPONSE_ARTIFACT_BASES {
        scan_artifacts_at(value, keys(base), Variant::V1, scan_data_parts, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::set_text;
    use serde_json::json;

    #[test]
    fn variant_detection() {
        assert_eq!(
            detect_variant("/rpc", |h| if h == "a2a-version" {
                Some("1.0".into())
            } else {
                None
            }),
            Variant::V1
        );
        assert_eq!(
            detect_variant("/rpc?A2A-Version=1.0", |_| None),
            Variant::V1
        );
        assert_eq!(detect_variant("/rpc", |_| None), Variant::Legacy);
    }

    #[test]
    fn v1_request_message_parts() {
        let v = json!({
            "jsonrpc":"2.0","id":1,"method":"SendMessage",
            "params":{"message":{"parts":[
                {"text":"email a@b.com"},
                {"file":{"uri":"http://x"}}
            ]}}
        });
        let fields = extract_request(&v, Variant::V1, false);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text, "email a@b.com");
    }

    #[test]
    fn legacy_requires_kind_text() {
        let v = json!({
            "jsonrpc":"2.0","id":1,"method":"message/send",
            "params":{"message":{"parts":[
                {"text":"no kind"},
                {"kind":"text","text":"has kind"}
            ]}}
        });
        let fields = extract_request(&v, Variant::Legacy, false);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text, "has kind");
    }

    #[test]
    fn scan_data_parts_when_enabled() {
        let v = json!({
            "jsonrpc":"2.0","id":1,"method":"SendMessage",
            "params":{"message":{"parts":[
                {"data":{"ssn":"123-45-6789","nested":{"n":"x"}}}
            ]}}
        });
        let off = extract_request(&v, Variant::V1, false);
        assert_eq!(off.len(), 0);
        let on = extract_request(&v, Variant::V1, true);
        let mut texts: Vec<&str> = on.iter().map(|f| f.text.as_str()).collect();
        texts.sort();
        assert_eq!(texts, vec!["123-45-6789", "x"]);
    }

    #[test]
    fn response_task_artifacts_and_status() {
        let v = json!({
            "jsonrpc":"2.0","id":1,
            "result":{"task":{
                "status":{"message":{"parts":[{"text":"phone 555-1234"}]}},
                "artifacts":[{"parts":[{"text":"card 4111111111111111"}]}]
            }}
        });
        let fields = extract_response(&v, false);
        let mut texts: Vec<&str> = fields.iter().map(|f| f.text.as_str()).collect();
        texts.sort();
        assert_eq!(texts, vec!["card 4111111111111111", "phone 555-1234"]);
        // Ensure paths are writable back.
        let mut v2 = v.clone();
        for f in &fields {
            assert!(set_text(&mut v2, &f.path, "<x>"));
        }
    }

    #[test]
    fn supported_methods() {
        assert!(is_supported_method("SendMessage", Variant::V1));
        assert!(!is_supported_method("message/send", Variant::V1));
        assert!(is_supported_method("tasks/resubscribe", Variant::Legacy));
    }
}
