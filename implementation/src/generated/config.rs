use serde::Deserialize;

#[derive(Deserialize, Clone, Debug, Default)]
pub struct OperatorConfig {
    #[serde(alias = "kind", default)]
    pub kind: Option<String>,
    #[serde(alias = "newValue", default)]
    pub new_value: Option<String>,
    #[serde(alias = "maskingChar", default)]
    pub masking_char: Option<String>,
    #[serde(alias = "charsToMask", default)]
    pub chars_to_mask: Option<i64>,
    #[serde(alias = "fromEnd", default)]
    pub from_end: Option<bool>,
    #[serde(alias = "serverSide", default)]
    pub server_side: Option<bool>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RuleConfig {
    #[serde(alias = "entityType")]
    pub entity_type: String,
    #[serde(alias = "assetType", default)]
    pub asset_type: Option<String>,
    #[serde(alias = "direction", default)]
    pub direction: Option<String>,
    #[serde(alias = "audienceType", default)]
    pub audience_type: Option<String>,
    #[serde(alias = "audienceValue", default)]
    pub audience_value: Option<String>,
    #[serde(alias = "action")]
    pub action: String,
    #[serde(alias = "operator", default)]
    pub operator: Option<OperatorConfig>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(
        alias = "analyzerUrl",
        default,
        deserialize_with = "pdk::serde::deserialize_service_opt"
    )]
    pub analyzer_url: Option<pdk::hl::Service>,
    #[serde(
        alias = "anonymizerUrl",
        default,
        deserialize_with = "pdk::serde::deserialize_service_opt"
    )]
    pub anonymizer_url: Option<pdk::hl::Service>,
    #[serde(alias = "analyzerPathPrefix", default)]
    pub analyzer_path_prefix: Option<String>,
    #[serde(alias = "anonymizerPathPrefix", default)]
    pub anonymizer_path_prefix: Option<String>,
    #[serde(alias = "assetTypes", default)]
    pub asset_types: Vec<String>,
    #[serde(alias = "direction", default)]
    pub direction: Option<String>,
    #[serde(alias = "scanDataParts", default)]
    pub scan_data_parts: Option<bool>,
    #[serde(alias = "entities", default)]
    pub entities: Vec<String>,
    #[serde(alias = "scoreThreshold", default)]
    pub score_threshold: Option<f64>,
    #[serde(alias = "language", default)]
    pub language: Option<String>,
    #[serde(alias = "allowList", default)]
    pub allow_list: Vec<String>,
    #[serde(alias = "contextWords", default)]
    pub context_words: Vec<String>,
    #[serde(alias = "adHocRecognizers", default)]
    pub ad_hoc_recognizers: Vec<serde_json::Value>,
    #[serde(alias = "scanTargets", default)]
    pub scan_targets: Vec<String>,
    #[serde(alias = "maxBodyBytes", default)]
    pub max_body_bytes: Option<i64>,
    #[serde(alias = "oversizePosture", default)]
    pub oversize_posture: Option<String>,
    #[serde(alias = "defaultAction", default)]
    pub default_action: Option<String>,
    #[serde(alias = "rules", default)]
    pub rules: Vec<RuleConfig>,
    #[serde(alias = "failurePosture", default)]
    pub failure_posture: Option<String>,
    #[serde(alias = "presidioTimeoutMs", default)]
    pub presidio_timeout_ms: Option<i64>,
}

#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(abi.get_configuration()),
            err
        )
    })?;
    if let Some(service) = config.analyzer_url {
        abi.service_create(service)?;
    }
    if let Some(service) = config.anonymizer_url {
        abi.service_create(service)?;
    }
    abi.setup()?;
    Ok(())
}
