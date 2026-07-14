//! Detection evidence: response/request headers + structured log events.
//!
//! Emits `X-PII-Detected`, `X-PII-Entities` (e.g.
//! `EMAIL_ADDRESS:2,IBAN_CODE:1`), and `X-PII-Action`, plus a JSON log
//! line per inspected leg — feeding the same observability story as the
//! sibling agent-governance policies.

use std::collections::BTreeMap;

use pdk::logger;
use serde::Serialize;

pub const HEADER_DETECTED: &str = "x-pii-detected";
pub const HEADER_ENTITIES: &str = "x-pii-entities";
pub const HEADER_ACTION: &str = "x-pii-action";
pub const HEADER_SCAN: &str = "x-pii-scan";

/// Render an entity-count map as `TYPE:n,TYPE:n` in stable order.
pub fn format_entities(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Serialize)]
pub struct Event<'a> {
    pub direction: &'a str,
    pub asset_type: &'a str,
    pub action: &'a str,
    pub detected: bool,
    pub entities: &'a BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
}

impl<'a> Event<'a> {
    pub fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_else(|_| "{}".into());
        if self.detected {
            logger::warn!("pii-shield-evt {json}");
        } else {
            logger::debug!("pii-shield-evt {json}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_entity_counts_in_order() {
        let mut counts = BTreeMap::new();
        counts.insert("IBAN_CODE".to_string(), 1);
        counts.insert("EMAIL_ADDRESS".to_string(), 2);
        assert_eq!(format_entities(&counts), "EMAIL_ADDRESS:2,IBAN_CODE:1");
    }
}
