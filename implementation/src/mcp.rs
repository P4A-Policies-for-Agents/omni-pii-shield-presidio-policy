//! MCP (JSON-RPC over Streamable HTTP) payload shapes and traversal.
//!
//! Request:  `tools/call` → scan the string leaves of `params.arguments`.
//! Response: `result.content[*].text` where `type == "text"`; image /
//!           audio / resource content entries pass through untouched.

use serde_json::Value;

use crate::extract::{collect_string_leaves, Field, PathSeg};

pub const TOOLS_CALL_METHOD: &str = "tools/call";

/// True when the JSON-RPC envelope is an MCP `tools/call` request.
pub fn is_tools_call(value: &Value) -> bool {
    value.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
        && value.get("method").and_then(|v| v.as_str()) == Some(TOOLS_CALL_METHOD)
}

/// True when the JSON-RPC envelope carries an MCP tool `result.content`
/// array (the response side of `tools/call`).
pub fn is_tool_result(value: &Value) -> bool {
    value
        .pointer("/result/content")
        .map(|c| c.is_array())
        .unwrap_or(false)
}

/// Extract scannable text from a `tools/call` request: every string leaf
/// under `params.arguments`.
pub fn extract_request(value: &Value) -> Vec<Field> {
    let mut out = Vec::new();
    if let Some(args) = value.pointer("/params/arguments") {
        let base = vec![
            PathSeg::Key("params".into()),
            PathSeg::Key("arguments".into()),
        ];
        collect_string_leaves(args, &base, &mut out);
    }
    out
}

/// Extract scannable text from a tool result: each `result.content[i]`
/// whose `type == "text"` contributes its `text` field.
pub fn extract_response(value: &Value) -> Vec<Field> {
    let mut out = Vec::new();
    if let Some(Value::Array(items)) = value.pointer("/result/content") {
        for (i, item) in items.iter().enumerate() {
            if item.get("type").and_then(|v| v.as_str()) == Some("text") {
                if let Some(Value::String(text)) = item.get("text") {
                    out.push(Field::new(
                        vec![
                            PathSeg::Key("result".into()),
                            PathSeg::Key("content".into()),
                            PathSeg::Index(i),
                            PathSeg::Key("text".into()),
                        ],
                        text.clone(),
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::set_text;
    use serde_json::json;

    #[test]
    fn detects_tools_call() {
        assert!(is_tools_call(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}})
        ));
        assert!(!is_tools_call(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})
        ));
    }

    #[test]
    fn request_scans_argument_string_leaves() {
        let v = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"send","arguments":{"to":"a@b.com","cc":["c@d.com"],"count":3}}
        });
        // Only `params.arguments` leaves are scanned; `params.name` ("send")
        // is the tool name, not an argument, so it is not extracted.
        let fields = extract_request(&v);
        let mut texts: Vec<&str> = fields.iter().map(|f| f.text.as_str()).collect();
        texts.sort();
        assert_eq!(texts, vec!["a@b.com", "c@d.com"]);
    }

    #[test]
    fn response_scans_only_text_content() {
        let v = json!({
            "jsonrpc":"2.0","id":1,
            "result":{"content":[
                {"type":"text","text":"call 555-1234"},
                {"type":"image","data":"base64=="},
                {"type":"text","text":"ok"}
            ]}
        });
        let mut v2 = v.clone();
        let fields = extract_response(&v);
        assert_eq!(fields.len(), 2);
        assert!(set_text(&mut v2, &fields[0].path, "<x>"));
        assert_eq!(v2.pointer("/result/content/0/text").unwrap(), &json!("<x>"));
        // Image entry untouched.
        assert_eq!(
            v2.pointer("/result/content/1/data").unwrap(),
            &json!("base64==")
        );
    }
}
