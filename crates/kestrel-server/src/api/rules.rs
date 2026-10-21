use super::{ApiJson, ApiPath};
use crate::{
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    policy_svc,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use kestrel_common::{
    now_ms, Policy, RuleBundle, RuleCategory, RuleDef, RuleKind, RuleMeta, RuleMode, Severity,
};
use kestrel_detect::{Engine, HostContext};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const MAX_RULE_SOURCE: usize = 256 * 1024;

pub async fn list(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let hits: Vec<(String, i64)> =
        sqlx::query_as("SELECT rule_id, count(*) FROM alerts WHERE ts >= $1 GROUP BY rule_id")
            .bind(now_ms() - 7 * 86_400_000)
            .fetch_all(&st.db)
            .await?;
    let hits: HashMap<String, i64> = hits.into_iter().collect();
    let mut out = vec![];
    for meta in Engine::catalog() {
        let mut v = serde_json::to_value(&meta)?;
        filter_references(&mut v);
        v["enabled_custom"] = false.into();
        v["hits_7d"] = hits.get(&meta.id).copied().unwrap_or(0).into();
        out.push(v);
    }
    let custom: Vec<(String, Value, String, bool, i64, i64)> = sqlx::query_as(
        "SELECT id, meta, source, enabled, created_at, updated_at FROM rules ORDER BY created_at",
    )
    .fetch_all(&st.db)
    .await?;
    for (id, meta, source, enabled, created_at, updated_at) in custom {
        let mut v = meta;
        // Rules stored before the filter existed: never hand the console a
        // non-http(s) reference to render as a link.
        filter_references(&mut v);
        v["enabled_custom"] = enabled.into();
        v["hits_7d"] = hits.get(&id).copied().unwrap_or(0).into();
        v["source"] = source.into();
        v["created_at"] = created_at.into();
        v["updated_at"] = updated_at.into();
        out.push(v);
    }
    Ok(Json(Value::Array(out)))
}

fn sigma_severity(level: Option<&str>) -> Severity {
    match level.unwrap_or("medium").to_ascii_lowercase().as_str() {
        "informational" | "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

/// A rule reference the console may render as a link: an absolute `http(s)://`
/// URL with a host and no whitespace or control characters (`javascript:`,
/// `data:` and relative URLs are dropped).
pub fn is_http_reference(r: &str) -> bool {
    let lower = r.trim().to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    rest.is_some_and(|h| !h.is_empty() && !h.starts_with('/') && !h.starts_with('@'))
        && r.len() <= 2048
        && !r
            .trim()
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

/// Keep only http(s) references in a serialised `RuleMeta`.
fn filter_references(v: &mut Value) {
    if let Some(Value::Array(a)) = v.get_mut("references") {
        a.retain(|x| x.as_str().is_some_and(is_http_reference));
    }
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

/// Parse Sigma YAML into rule metadata (id `SIG-<uuid8>`).
pub fn sigma_meta(source: &str, id: Option<&str>) -> ApiResult<RuleMeta> {
    if source.len() > MAX_RULE_SOURCE {
        return Err(ApiError::bad_request("rule source too large"));
    }
    let y: Value = yaml_serde::from_str(source)
        .map_err(|e| ApiError::bad_request(format!("invalid YAML: {e}")))?;
    let obj = y
        .as_object()
        .ok_or_else(|| ApiError::bad_request("Sigma rule must be a YAML mapping"))?;
    let title = obj
        .get("title")
        .and_then(|t| t.as_str())
        .ok_or_else(|| ApiError::bad_request("Sigma rule needs a title"))?;
    if obj.get("detection").is_none() {
        return Err(ApiError::bad_request(
            "Sigma rule needs a detection section",
        ));
    }
    if obj.get("logsource").is_none() {
        return Err(ApiError::bad_request(
            "Sigma rule needs a logsource section",
        ));
    }
    let rid = match id {
        Some(i) => i.to_string(),
        None => {
            let base = obj
                .get("id")
                .and_then(|i| i.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .unwrap_or_else(uuid::Uuid::new_v4);
            format!("SIG-{}", &base.simple().to_string()[..8])
        }
    };
    let tags = str_list(obj.get("tags"));
    let attack: Vec<String> = tags
        .iter()
        .filter_map(|t| t.strip_prefix("attack."))
        .filter(|t| {
            t.len() > 1 && t.starts_with(['t', 'T']) && t[1..2].chars().all(|c| c.is_ascii_digit())
        })
        .map(|t| t.to_ascii_uppercase())
        .collect();
    let author = obj.get("author").and_then(|a| a.as_str()).map(String::from);
    let is_sigmahq = obj
        .get("license")
        .and_then(|l| l.as_str())
        .map(|l| l.contains("DRL"))
        .unwrap_or(false)
        || str_list(obj.get("references"))
            .iter()
            .any(|r| r.contains("SigmaHQ"));
    Ok(RuleMeta {
        id: rid,
        name: title.chars().take(200).collect(),
        description: obj
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string(),
        kind: RuleKind::Sigma,
        category: RuleCategory::Custom,
        severity: sigma_severity(obj.get("level").and_then(|l| l.as_str())),
        attack,
        default_mode: RuleMode::Audit,
        protect_day_one: false,
        protect_action: String::new(),
        author,
        license: obj
            .get("license")
            .and_then(|l| l.as_str())
            .map(String::from)
            .or(if is_sigmahq {
                Some("DRL-1.1".into())
            } else {
                None
            }),
        references: str_list(obj.get("references"))
            .into_iter()
            .map(|r| r.trim().to_string())
            .filter(|r| is_http_reference(r))
            .collect(),
        false_positives: str_list(obj.get("falsepositives")),
    })
}

/// Compile with the detection engine; returns a 400 on failure.
pub fn validate_with_engine(def: &RuleDef) -> ApiResult<()> {
    let mut engine = Engine::new(
        HostContext::default(),
        Policy::default(),
        RuleBundle::default(),
    )
    .map_err(|e| ApiError::internal(format!("engine init: {e}")))?;
    engine
        .update_rules(RuleBundle {
            version: 1,
            rules: vec![def.clone()],
        })
        .map_err(|e| ApiError::bad_request(format!("rule does not compile: {e}")))
}

#[derive(Deserialize)]
pub struct CreateRule {
    source: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    default_mode: Option<RuleMode>,
}

pub async fn create(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreateRule>,
) -> ApiResult<Json<Value>> {
    p.require("rules.write")?;
    let mut meta = sigma_meta(&b.source, None)?;
    if let Some(m) = b.default_mode {
        meta.default_mode = m;
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM rules WHERE id = $1")
        .bind(&meta.id)
        .fetch_optional(&st.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::conflict(format!(
            "a rule with id {} already exists",
            meta.id
        )));
    }
    let def = RuleDef {
        meta: meta.clone(),
        source: b.source.clone(),
    };
    validate_with_engine(&def)?;
    let now = now_ms();
    let enabled = b.enabled.unwrap_or(true);
    sqlx::query("INSERT INTO rules (id, kind, meta, source, enabled, created_by, created_at, updated_at) VALUES ($1,'sigma',$2,$3,$4,$5,$6,$6)")
        .bind(&meta.id)
        .bind(serde_json::to_value(&meta)?)
        .bind(&b.source)
        .bind(enabled)
        .bind(p.user.id)
        .bind(now)
        .execute(&st.db)
        .await?;
    policy_svc::bump_rules_and_push(&st).await?;
    audit::log(
        &st.db,
        &p.actor(),
        "rule.create",
        &meta.id,
        json!({"name": meta.name, "enabled": enabled}),
    )
    .await;
    let mut v = serde_json::to_value(&meta)?;
    v["enabled_custom"] = enabled.into();
    v["hits_7d"] = 0.into();
    v["source"] = b.source.into();
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct PatchRule {
    #[serde(alias = "enabled_custom")]
    enabled: Option<bool>,
    source: Option<String>,
    default_mode: Option<RuleMode>,
}

pub async fn update(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<PatchRule>,
) -> ApiResult<Json<Value>> {
    p.require("rules.write")?;
    if Engine::catalog().iter().any(|m| m.id == id) {
        return Err(ApiError::bad_request(
            "builtin rules are configured per policy (Policy.rules)",
        ));
    }
    let (meta_v, source, enabled): (Value, String, bool) =
        sqlx::query_as("SELECT meta, source, enabled FROM rules WHERE id = $1")
            .bind(&id)
            .fetch_optional(&st.db)
            .await?
            .ok_or_else(|| ApiError::not_found("rule not found"))?;
    let mut meta: RuleMeta =
        serde_json::from_value(meta_v).map_err(|_| ApiError::internal("stored rule unreadable"))?;
    let mut source = source;
    if let Some(s) = &b.source {
        let mode = meta.default_mode;
        meta = sigma_meta(s, Some(&id))?;
        meta.default_mode = mode;
        source = s.clone();
    }
    if let Some(m) = b.default_mode {
        meta.default_mode = m;
    }
    validate_with_engine(&RuleDef {
        meta: meta.clone(),
        source: source.clone(),
    })?;
    let enabled = b.enabled.unwrap_or(enabled);
    sqlx::query(
        "UPDATE rules SET meta = $2, source = $3, enabled = $4, updated_at = $5 WHERE id = $1",
    )
    .bind(&id)
    .bind(serde_json::to_value(&meta)?)
    .bind(&source)
    .bind(enabled)
    .bind(now_ms())
    .execute(&st.db)
    .await?;
    policy_svc::bump_rules_and_push(&st).await?;
    audit::log(&st.db, &p.actor(), "rule.update", &id, json!({"enabled": b.enabled, "source_changed": b.source.is_some(), "default_mode": b.default_mode})).await;
    let mut v = serde_json::to_value(&meta)?;
    v["enabled_custom"] = enabled.into();
    v["source"] = source.into();
    Ok(Json(v))
}

pub async fn remove(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("rules.write")?;
    let r = sqlx::query("DELETE FROM rules WHERE id = $1")
        .bind(&id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("custom rule not found"));
    }
    policy_svc::bump_rules_and_push(&st).await?;
    audit::log(&st.db, &p.actor(), "rule.delete", &id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_sigma() {
        let src = r#"
title: Suspicious Chrome Login Data access
id: 5b1c6f0e-8a3e-4ec2-9d0f-0d8e2a1c9f11
status: experimental
description: test
author: Jane
level: high
tags: [attack.credential_access, attack.t1555.003]
logsource: {product: windows, category: file_access}
detection:
  sel: {TargetFilename|endswith: '\Login Data'}
  condition: sel
"#;
        let m = super::sigma_meta(src, None).unwrap();
        assert_eq!(m.id, "SIG-5b1c6f0e");
        assert_eq!(m.attack, vec!["T1555.003"]);
        assert_eq!(m.severity, kestrel_common::Severity::High);
        assert!(super::sigma_meta("title: x", None).is_err());
        assert!(super::sigma_meta(": : :", None).is_err());
    }
}

#[cfg(test)]
mod reference_tests {
    use super::*;

    #[test]
    fn only_http_references() {
        assert!(is_http_reference("https://github.com/SigmaHQ/sigma"));
        assert!(is_http_reference("http://example.com/x"));
        for bad in [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,x",
            "//evil.example",
            "https:///x",
            "https://a b",
            "mailto:x@y",
            "vbscript:x",
            "",
        ] {
            assert!(!is_http_reference(bad), "{bad}");
        }
        let m = sigma_meta(
            "title: t\nid: 0b4ed5f8-1111-2222-3333-444455556666\nreferences:\n  - javascript:alert(1)\n  - https://ok.example/r\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  sel:\n    Image|endswith: '\\\\x.exe'\n  condition: sel\n",
            None,
        )
        .unwrap();
        assert_eq!(m.references, vec!["https://ok.example/r".to_string()]);
        let mut v = serde_json::json!({"references": ["https://a.example", "javascript:x", 5]});
        filter_references(&mut v);
        assert_eq!(v["references"], serde_json::json!(["https://a.example"]));
    }
}
