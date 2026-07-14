//! Rule engine: bind analyzer findings to actions.
//!
//! For every detected entity the engine walks the ordered rule list and
//! takes the first rule whose `entityType` glob, optional `assetType`,
//! optional `direction`, and optional audience filter all match; falling
//! back to `defaultAction`. Results aggregate into a single [`Decision`]:
//! any `block` blocks the whole message; `redact` findings are collected
//! per field for splicing; `audit` findings only feed evidence.

use std::collections::BTreeMap;

use crate::config::{glob_match, Action, Audience, AudienceType, Direction, Operator, PolicyConfig, Rule};
use crate::presidio::RecognizerResult;

/// Identity + routing context for rule matching. Identity is read from
/// the Anypoint `Authentication` injectable only.
#[derive(Debug, Clone)]
pub struct EvalContext<'a> {
    pub asset_type: crate::config::AssetType,
    pub direction: Direction,
    pub client_id: Option<&'a str>,
    pub scopes: &'a [String],
}

/// Redactions to apply to a single scanned field.
#[derive(Debug, Default)]
pub struct FieldRedaction {
    pub field_index: usize,
    pub redactions: Vec<(RecognizerResult, Operator)>,
}

#[derive(Debug, Default)]
pub struct Decision {
    pub block: bool,
    pub blocked_entities: Vec<String>,
    pub per_field: Vec<FieldRedaction>,
    pub counts: BTreeMap<String, usize>,
    pub audited: usize,
}

impl Decision {
    pub fn any_detected(&self) -> bool {
        !self.counts.is_empty()
    }

    pub fn any_redaction(&self) -> bool {
        self.per_field.iter().any(|f| !f.redactions.is_empty())
    }
}

fn audience_matches(audience: &Audience, ctx: &EvalContext) -> bool {
    match audience.kind {
        AudienceType::Client => ctx.client_id == Some(audience.value.as_str()),
        AudienceType::Scope => ctx.scopes.iter().any(|s| s == &audience.value),
    }
}

fn rule_matches(rule: &Rule, entity_type: &str, ctx: &EvalContext) -> bool {
    if !glob_match(&rule.entity_glob, entity_type) {
        return false;
    }
    if let Some(asset) = rule.asset_type {
        if asset != ctx.asset_type {
            return false;
        }
    }
    if let Some(dir) = rule.direction {
        if dir != ctx.direction {
            return false;
        }
    }
    if let Some(audience) = &rule.audience {
        if !audience_matches(audience, ctx) {
            return false;
        }
    }
    true
}

/// Resolve the action for a single detected entity (first-match, then
/// `defaultAction`).
pub fn action_for<'a>(
    cfg: &'a PolicyConfig,
    entity_type: &str,
    ctx: &EvalContext,
) -> &'a Action {
    for rule in &cfg.rules {
        if rule_matches(rule, entity_type, ctx) {
            return &rule.action;
        }
    }
    &cfg.default_action
}

/// Evaluate all findings across every scanned field.
pub fn evaluate(
    field_results: &[Vec<RecognizerResult>],
    cfg: &PolicyConfig,
    ctx: &EvalContext,
) -> Decision {
    let mut decision = Decision::default();
    for (idx, results) in field_results.iter().enumerate() {
        let mut fr = FieldRedaction {
            field_index: idx,
            ..Default::default()
        };
        for res in results {
            *decision.counts.entry(res.entity_type.clone()).or_insert(0) += 1;
            match action_for(cfg, &res.entity_type, ctx) {
                Action::Block => {
                    decision.block = true;
                    decision.blocked_entities.push(res.entity_type.clone());
                }
                Action::Redact(op) => {
                    fr.redactions.push((res.clone(), op.clone()));
                }
                Action::Audit => {
                    decision.audited += 1;
                }
            }
        }
        if !fr.redactions.is_empty() {
            decision.per_field.push(fr);
        }
    }
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AssetType;
    use crate::generated::config::Config;

    fn cfg(json: serde_json::Value) -> PolicyConfig {
        let raw: Config = serde_json::from_value(json).unwrap();
        PolicyConfig::from_parts("http://a".into(), &raw).unwrap()
    }

    fn ctx() -> EvalContext<'static> {
        EvalContext {
            asset_type: AssetType::A2a,
            direction: Direction::Request,
            client_id: None,
            scopes: &[],
        }
    }

    fn res(entity: &str) -> RecognizerResult {
        RecognizerResult {
            entity_type: entity.into(),
            start: 0,
            end: 1,
            score: 0.9,
        }
    }

    #[test]
    fn default_action_applies_without_rules() {
        let c = cfg(serde_json::json!({"defaultAction":"block"}));
        let d = evaluate(&[vec![res("PERSON")]], &c, &ctx());
        assert!(d.block);
        assert_eq!(d.counts["PERSON"], 1);
    }

    #[test]
    fn first_match_rule_wins() {
        let c = cfg(serde_json::json!({
            "defaultAction":"audit",
            "rules":[
                {"entityType":"CREDIT_CARD","action":"block"},
                {"entityType":"*","action":"audit"}
            ]
        }));
        let d = evaluate(&[vec![res("CREDIT_CARD"), res("PERSON")]], &c, &ctx());
        assert!(d.block);
        assert_eq!(d.audited, 1);
        assert_eq!(d.blocked_entities, vec!["CREDIT_CARD"]);
    }

    #[test]
    fn redact_collects_per_field_operator() {
        let c = cfg(serde_json::json!({
            "rules":[{"entityType":"EMAIL_ADDRESS","action":"redact","operator":{"kind":"mask"}}]
        }));
        let d = evaluate(&[vec![], vec![res("EMAIL_ADDRESS")]], &c, &ctx());
        assert!(!d.block);
        assert!(d.any_redaction());
        assert_eq!(d.per_field[0].field_index, 1);
    }

    #[test]
    fn asset_and_direction_scoping() {
        let c = cfg(serde_json::json!({
            "defaultAction":"audit",
            "rules":[
                {"entityType":"PERSON","assetType":"a2a","direction":"request","action":"block"}
            ]
        }));
        // Matches asset + direction.
        let d = evaluate(&[vec![res("PERSON")]], &c, &ctx());
        assert!(d.block);
        // Wrong direction falls back to audit.
        let mut c2ctx = ctx();
        c2ctx.direction = Direction::Response;
        let d2 = evaluate(&[vec![res("PERSON")]], &c, &c2ctx);
        assert!(!d2.block);
        assert_eq!(d2.audited, 1);
    }

    #[test]
    fn audience_scope_gate() {
        let c = cfg(serde_json::json!({
            "defaultAction":"redact",
            "rules":[
                {"entityType":"EMAIL_ADDRESS","audienceType":"scope","audienceValue":"pii.read","action":"audit"}
            ]
        }));
        let scopes = vec!["pii.read".to_string()];
        let with_scope = EvalContext {
            asset_type: AssetType::Llm,
            direction: Direction::Request,
            client_id: None,
            scopes: &scopes,
        };
        // Caller has pii.read → audited (rule matched).
        let d = evaluate(&[vec![res("EMAIL_ADDRESS")]], &c, &with_scope);
        assert_eq!(d.audited, 1);
        assert!(!d.any_redaction());
        // No scope → default redact.
        let d2 = evaluate(&[vec![res("EMAIL_ADDRESS")]], &c, &ctx());
        assert!(d2.any_redaction());
    }
}
