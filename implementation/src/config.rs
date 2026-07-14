//! Typed, validated view over the generated policy configuration.
//!
//! [`PolicyConfig`] holds only plain data (no PDK `Service` handles) so
//! the whole rule engine is exercisable from host-side `cargo test`. The
//! WASM entrypoint keeps the live `Service` handles alongside it and
//! threads them into the Presidio client.

use serde_json_path::JsonPath;

use crate::generated::config::{Config, OperatorConfig, RuleConfig};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("analyzerUrl is required")]
    MissingAnalyzerUrl,
    #[error("unknown assetType: {0}")]
    UnknownAssetType(String),
    #[error("unknown direction: {0}")]
    UnknownDirection(String),
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("unknown operator kind: {0}")]
    UnknownOperatorKind(String),
    #[error("unknown audienceType: {0}")]
    UnknownAudienceType(String),
    #[error("invalid JSONPath scanTarget `{0}`: {1}")]
    BadScanTarget(String, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetType {
    Mcp,
    A2a,
    Llm,
    Generic,
}

impl AssetType {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mcp" => Ok(Self::Mcp),
            "a2a" => Ok(Self::A2a),
            "llm" => Ok(Self::Llm),
            "generic" => Ok(Self::Generic),
            other => Err(ConfigError::UnknownAssetType(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AssetType::Mcp => "mcp",
            AssetType::A2a => "a2a",
            AssetType::Llm => "llm",
            AssetType::Generic => "generic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "request" => Ok(Self::Request),
            "response" => Ok(Self::Response),
            other => Err(ConfigError::UnknownDirection(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionScope {
    Request,
    Response,
    Both,
}

impl DirectionScope {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "request" => Ok(Self::Request),
            "response" => Ok(Self::Response),
            "both" => Ok(Self::Both),
            other => Err(ConfigError::UnknownDirection(other.to_string())),
        }
    }

    pub fn includes(self, dir: Direction) -> bool {
        matches!(
            (self, dir),
            (DirectionScope::Both, _)
                | (DirectionScope::Request, Direction::Request)
                | (DirectionScope::Response, Direction::Response)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OversizePosture {
    Pass,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePosture {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorKind {
    Replace,
    Mask,
    Hash,
    Redact,
}

#[derive(Debug, Clone)]
pub struct Operator {
    pub kind: OperatorKind,
    pub new_value: Option<String>,
    pub masking_char: char,
    pub chars_to_mask: usize,
    pub from_end: bool,
    pub server_side: bool,
}

impl Default for Operator {
    fn default() -> Self {
        Operator {
            kind: OperatorKind::Replace,
            new_value: None,
            masking_char: '*',
            chars_to_mask: 0,
            from_end: false,
            server_side: false,
        }
    }
}

impl Operator {
    fn from_generated(raw: Option<&OperatorConfig>) -> Result<Self, ConfigError> {
        let Some(raw) = raw else {
            return Ok(Operator::default());
        };
        let kind = match raw.kind.as_deref().unwrap_or("replace") {
            "replace" => OperatorKind::Replace,
            "mask" => OperatorKind::Mask,
            "hash" => OperatorKind::Hash,
            "redact" => OperatorKind::Redact,
            other => return Err(ConfigError::UnknownOperatorKind(other.to_string())),
        };
        let masking_char = raw
            .masking_char
            .as_deref()
            .and_then(|s| s.chars().next())
            .unwrap_or('*');
        Ok(Operator {
            kind,
            new_value: raw.new_value.clone(),
            masking_char,
            chars_to_mask: raw.chars_to_mask.unwrap_or(0).max(0) as usize,
            from_end: raw.from_end.unwrap_or(false),
            server_side: raw.server_side.unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceType {
    Client,
    Scope,
}

#[derive(Debug, Clone)]
pub struct Audience {
    pub kind: AudienceType,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum Action {
    Audit,
    Redact(Operator),
    Block,
}

impl Action {
    fn parse(action: &str, operator: Option<&OperatorConfig>) -> Result<Self, ConfigError> {
        match action.trim().to_ascii_lowercase().as_str() {
            "audit" => Ok(Action::Audit),
            "block" => Ok(Action::Block),
            "redact" => Ok(Action::Redact(Operator::from_generated(operator)?)),
            other => Err(ConfigError::UnknownAction(other.to_string())),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Action::Audit => "audit",
            Action::Redact(_) => "redact",
            Action::Block => "block",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub entity_glob: String,
    pub asset_type: Option<AssetType>,
    pub direction: Option<Direction>,
    pub audience: Option<Audience>,
    pub action: Action,
}

/// A JSONPath scan target plus the raw expression (kept for logs).
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub raw: String,
    pub path: JsonPath,
}

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Display URL of the analyzer (authority-only when derived from a
    /// `format: service` handle); used for logging and error text.
    pub analyzer_url: String,
    pub anonymizer_url: Option<String>,
    /// Empty = all asset types.
    pub asset_types: Vec<AssetType>,
    pub direction: DirectionScope,
    pub scan_data_parts: bool,
    /// Empty = request all Presidio entity types.
    pub entities: Vec<String>,
    pub score_threshold: f64,
    pub language: String,
    pub allow_list: Vec<String>,
    pub context_words: Vec<String>,
    pub ad_hoc_recognizers: Vec<serde_json::Value>,
    pub scan_targets: Vec<ScanTarget>,
    pub max_body_bytes: usize,
    pub oversize_posture: OversizePosture,
    pub default_action: Action,
    pub rules: Vec<Rule>,
    pub failure_posture: FailurePosture,
    pub presidio_timeout_ms: u64,
}

impl PolicyConfig {
    pub fn from_generated(raw: &Config) -> Result<Self, ConfigError> {
        let analyzer_url = raw
            .analyzer_url
            .as_ref()
            .map(|s| s.uri().to_string())
            .ok_or(ConfigError::MissingAnalyzerUrl)?;
        Self::from_parts(analyzer_url, raw)
    }

    /// Build the typed config from an already-resolved analyzer URL plus
    /// the generated struct. Split out so host tests can supply a URL
    /// without a live `Service` handle.
    pub fn from_parts(analyzer_url: String, raw: &Config) -> Result<Self, ConfigError> {
        let anonymizer_url = raw
            .anonymizer_url
            .as_ref()
            .map(|s| s.uri().to_string())
            .filter(|s| !s.is_empty());

        let asset_types = raw
            .asset_types
            .iter()
            .map(|s| AssetType::parse(s))
            .collect::<Result<Vec<_>, _>>()?;

        let direction = DirectionScope::parse(raw.direction.as_deref().unwrap_or("both"))?;

        let oversize_posture = match raw.oversize_posture.as_deref().unwrap_or("pass") {
            "pass" => OversizePosture::Pass,
            "block" => OversizePosture::Block,
            other => return Err(ConfigError::UnknownDirection(other.to_string())),
        };

        let failure_posture = match raw.failure_posture.as_deref().unwrap_or("open") {
            "open" => FailurePosture::Open,
            "closed" => FailurePosture::Closed,
            other => return Err(ConfigError::UnknownDirection(other.to_string())),
        };

        let default_action = Action::parse(raw.default_action.as_deref().unwrap_or("audit"), None)?;

        let mut scan_targets = Vec::new();
        for raw_path in &raw.scan_targets {
            let path = JsonPath::parse(raw_path)
                .map_err(|e| ConfigError::BadScanTarget(raw_path.clone(), e.to_string()))?;
            scan_targets.push(ScanTarget {
                raw: raw_path.clone(),
                path,
            });
        }

        let mut rules = Vec::with_capacity(raw.rules.len());
        for rule in &raw.rules {
            rules.push(parse_rule(rule)?);
        }

        Ok(PolicyConfig {
            analyzer_url,
            anonymizer_url,
            asset_types,
            direction,
            scan_data_parts: raw.scan_data_parts.unwrap_or(false),
            entities: raw.entities.clone(),
            score_threshold: raw.score_threshold.unwrap_or(0.5).clamp(0.0, 1.0),
            language: raw
                .language
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "en".to_string()),
            allow_list: raw.allow_list.clone(),
            context_words: raw.context_words.clone(),
            ad_hoc_recognizers: raw.ad_hoc_recognizers.clone(),
            scan_targets,
            max_body_bytes: raw.max_body_bytes.unwrap_or(262_144).max(0) as usize,
            oversize_posture,
            default_action,
            rules,
            failure_posture,
            presidio_timeout_ms: raw.presidio_timeout_ms.unwrap_or(1500).clamp(25, 30_000) as u64,
        })
    }

    /// Whether the given asset type should be inspected (empty filter = all).
    pub fn inspects(&self, asset: AssetType) -> bool {
        self.asset_types.is_empty() || self.asset_types.contains(&asset)
    }
}

fn parse_rule(raw: &RuleConfig) -> Result<Rule, ConfigError> {
    let asset_type = match raw.asset_type.as_deref() {
        Some(s) => Some(AssetType::parse(s)?),
        None => None,
    };
    let direction = match raw.direction.as_deref() {
        Some(s) => Some(Direction::parse(s)?),
        None => None,
    };
    let audience = match (raw.audience_type.as_deref(), raw.audience_value.as_deref()) {
        (Some(kind), Some(value)) => {
            let kind = match kind.trim().to_ascii_lowercase().as_str() {
                "client" => AudienceType::Client,
                "scope" => AudienceType::Scope,
                other => return Err(ConfigError::UnknownAudienceType(other.to_string())),
            };
            Some(Audience {
                kind,
                value: value.to_string(),
            })
        }
        _ => None,
    };
    let action = Action::parse(&raw.action, raw.operator.as_ref())?;
    Ok(Rule {
        entity_glob: raw.entity_type.clone(),
        asset_type,
        direction,
        audience,
        action,
    })
}

/// Case-insensitive glob match supporting `*` (any run) and `?` (one
/// char). Used to bind rule `entityType` patterns like `US_*` to a
/// concrete Presidio entity type.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.to_ascii_uppercase().chars().collect();
    let val: Vec<char> = value.to_ascii_uppercase().chars().collect();
    glob_rec(&pat, &val)
}

fn glob_rec(pat: &[char], val: &[char]) -> bool {
    match pat.first() {
        None => val.is_empty(),
        Some('*') => {
            // Match zero or more chars.
            glob_rec(&pat[1..], val) || (!val.is_empty() && glob_rec(pat, &val[1..]))
        }
        Some('?') => !val.is_empty() && glob_rec(&pat[1..], &val[1..]),
        Some(&c) => !val.is_empty() && val[0] == c && glob_rec(&pat[1..], &val[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_and_wildcards() {
        assert!(glob_match("EMAIL_ADDRESS", "EMAIL_ADDRESS"));
        assert!(glob_match("email_address", "EMAIL_ADDRESS"));
        assert!(glob_match("US_*", "US_SSN"));
        assert!(glob_match("US_*", "US_DRIVER_LICENSE"));
        assert!(!glob_match("US_*", "IBAN_CODE"));
        assert!(glob_match("*", "ANYTHING"));
        assert!(glob_match("PHONE_NUMBE?", "PHONE_NUMBER"));
        assert!(!glob_match("PHONE_NUMBE?", "PHONE_NUMBERS"));
    }

    #[test]
    fn direction_scope_includes() {
        assert!(DirectionScope::Both.includes(Direction::Request));
        assert!(DirectionScope::Both.includes(Direction::Response));
        assert!(DirectionScope::Request.includes(Direction::Request));
        assert!(!DirectionScope::Request.includes(Direction::Response));
    }

    #[test]
    fn asset_type_parse_roundtrip() {
        for t in [AssetType::Mcp, AssetType::A2a, AssetType::Llm, AssetType::Generic] {
            assert_eq!(AssetType::parse(t.as_str()).unwrap(), t);
        }
        assert!(AssetType::parse("nope").is_err());
    }
}
