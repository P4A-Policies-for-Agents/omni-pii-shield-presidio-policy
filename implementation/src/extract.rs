//! Path-addressable text extraction and in-place rewrite over a parsed
//! `serde_json::Value`.
//!
//! Every scannable text leaf is captured as a [`Field`] carrying its
//! location as a [`PathSeg`] sequence, so the engine can (a) send the
//! text to Presidio and (b) splice a redacted replacement back into the
//! exact same slot without disturbing surrounding structure, key order,
//! or non-text siblings.

use serde_json::Value;
use serde_json_path::{JsonPath, PathElement};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSeg {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone)]
pub struct Field {
    pub path: Vec<PathSeg>,
    pub text: String,
}

impl Field {
    pub fn new(path: Vec<PathSeg>, text: impl Into<String>) -> Self {
        Field {
            path,
            text: text.into(),
        }
    }
}

/// Recursively collect every string leaf under `value`, rooted at
/// `base`. Object keys and array indices are appended to the path.
pub fn collect_string_leaves(value: &Value, base: &[PathSeg], out: &mut Vec<Field>) {
    match value {
        Value::String(s) => out.push(Field::new(base.to_vec(), s.clone())),
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let mut p = base.to_vec();
                p.push(PathSeg::Index(i));
                collect_string_leaves(v, &p, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let mut p = base.to_vec();
                p.push(PathSeg::Key(k.clone()));
                collect_string_leaves(v, &p, out);
            }
        }
        _ => {}
    }
}

/// Collect string leaves selected by a JSONPath expression. When a
/// selected node is itself a string it becomes one field; when it is an
/// object/array every string leaf beneath it is collected.
pub fn collect_by_jsonpath(root: &Value, path: &JsonPath, out: &mut Vec<Field>) {
    for node in path.query_located(root).all() {
        let base: Vec<PathSeg> = node
            .location()
            .iter()
            .map(|el| match el {
                PathElement::Name(n) => PathSeg::Key((*n).to_string()),
                PathElement::Index(i) => PathSeg::Index(*i),
            })
            .collect();
        collect_string_leaves(node.node(), &base, out);
    }
}

/// Read the value at `path`, if present.
pub fn get<'a>(root: &'a Value, path: &[PathSeg]) -> Option<&'a Value> {
    let mut node = root;
    for seg in path {
        node = match (node, seg) {
            (Value::Object(map), PathSeg::Key(k)) => map.get(k)?,
            (Value::Array(arr), PathSeg::Index(i)) => arr.get(*i)?,
            _ => return None,
        };
    }
    Some(node)
}

/// Replace the string at `path` with `new_text`. Returns `true` when the
/// slot existed and was a string (or the root). Any other shape is a
/// no-op returning `false`, so a stale path can never corrupt structure.
pub fn set_text(root: &mut Value, path: &[PathSeg], new_text: &str) -> bool {
    let Some((last, prefix)) = path.split_last() else {
        if root.is_string() {
            *root = Value::String(new_text.to_string());
            return true;
        }
        return false;
    };
    let mut node = root;
    for seg in prefix {
        node = match (node, seg) {
            (Value::Object(map), PathSeg::Key(k)) => match map.get_mut(k) {
                Some(v) => v,
                None => return false,
            },
            (Value::Array(arr), PathSeg::Index(i)) => match arr.get_mut(*i) {
                Some(v) => v,
                None => return false,
            },
            _ => return false,
        };
    }
    match (node, last) {
        (Value::Object(map), PathSeg::Key(k)) => match map.get_mut(k) {
            Some(slot) if slot.is_string() => {
                *slot = Value::String(new_text.to_string());
                true
            }
            _ => false,
        },
        (Value::Array(arr), PathSeg::Index(i)) => match arr.get_mut(*i) {
            Some(slot) if slot.is_string() => {
                *slot = Value::String(new_text.to_string());
                true
            }
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collect_leaves_captures_all_strings() {
        let v = json!({"a": "x", "b": [1, "y", {"c": "z"}], "n": 3});
        let mut out = Vec::new();
        collect_string_leaves(&v, &[], &mut out);
        let texts: Vec<&str> = out.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, vec!["x", "y", "z"]);
    }

    #[test]
    fn set_text_round_trips_through_path() {
        let mut v = json!({"msg": {"parts": [{"text": "secret"}]}});
        let mut out = Vec::new();
        collect_string_leaves(&v, &[], &mut out);
        assert_eq!(out.len(), 1);
        assert!(set_text(&mut v, &out[0].path, "<redacted>"));
        assert_eq!(v, json!({"msg": {"parts": [{"text": "<redacted>"}]}}));
    }

    #[test]
    fn set_text_stale_path_is_noop() {
        let mut v = json!({"a": "x"});
        let path = vec![PathSeg::Key("missing".into())];
        assert!(!set_text(&mut v, &path, "y"));
        assert_eq!(v, json!({"a": "x"}));
    }

    #[test]
    fn jsonpath_collects_selected_leaves() {
        let v = json!({"user": {"email": "a@b.com", "name": "Bob"}, "other": "z"});
        let path = JsonPath::parse("$.user.email").unwrap();
        let mut out = Vec::new();
        collect_by_jsonpath(&v, &path, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "a@b.com");
        assert!(set_text_ok(&v, &out[0].path));
    }

    fn set_text_ok(root: &Value, path: &[PathSeg]) -> bool {
        get(root, path).map(|v| v.is_string()).unwrap_or(false)
    }
}
