//! Effective policy computation, version bumps and pushes to connected agents.

use crate::{settings, state::AppState};
use kestrel_common::{now_ms, wire::ServerPayload, Exclusion, Ioc, Policy, RuleBundle, RuleDef};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub struct ExclusionRow {
    pub id: String,
    pub policy_id: Option<String>,
    pub kind: String,
    pub value: String,
    pub rule_id: Option<String>,
    pub expires_at: Option<i64>,
    pub reason: String,
    pub created_by: Option<Uuid>,
    pub created_at: i64,
}

impl ExclusionRow {
    pub fn to_exclusion(&self) -> Option<Exclusion> {
        Some(Exclusion {
            id: self.id.clone(),
            kind: serde_json::from_value(serde_json::Value::String(self.kind.clone())).ok()?,
            value: self.value.clone(),
            rule_id: self.rule_id.clone(),
            expires_at: self.expires_at,
            reason: self.reason.clone(),
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct IocRow {
    pub id: String,
    pub policy_id: Option<String>,
    pub kind: String,
    pub value: String,
    pub action: String,
    pub description: String,
    pub created_by: Option<Uuid>,
    pub created_at: i64,
    pub hits: i64,
}

impl IocRow {
    pub fn to_ioc(&self) -> Option<Ioc> {
        Some(Ioc {
            id: self.id.clone(),
            kind: serde_json::from_value(serde_json::Value::String(self.kind.clone())).ok()?,
            value: self.value.clone(),
            action: serde_json::from_value(serde_json::Value::String(self.action.clone())).ok()?,
            description: self.description.clone(),
        })
    }
}

pub const DEVICE_POLICY_SQL: &str =
    "SELECT COALESCE(g.policy_id, (SELECT policy_id FROM groups WHERE is_default LIMIT 1)) \
     FROM devices d LEFT JOIN groups g ON g.id = d.group_id WHERE d.id = $1";

pub async fn device_policy_id(db: &PgPool, device_id: Uuid) -> anyhow::Result<String> {
    let (pid,): (Option<String>,) = sqlx::query_as(DEVICE_POLICY_SQL)
        .bind(device_id)
        .fetch_one(db)
        .await?;
    Ok(pid.unwrap_or_else(|| crate::db::DEFAULT_POLICY_ID.to_string()))
}

/// Stored policy body (without merged exclusions/IOCs).
pub async fn load_stored(db: &PgPool, policy_id: &str) -> anyhow::Result<Option<Policy>> {
    let row: Option<(serde_json::Value, i64, String)> =
        sqlx::query_as("SELECT body, version, name FROM policies WHERE id = $1")
            .bind(policy_id)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(body, version, name)| {
        let mut p: Policy = serde_json::from_value(body).unwrap_or_default();
        p.id = policy_id.to_string();
        p.version = version as u64;
        p.name = name;
        p
    }))
}

/// Policy as delivered to agents: stored body + policy-scoped and global
/// exclusions/IOCs (unexpired) + org branding from Settings.
pub async fn effective(db: &PgPool, policy_id: &str) -> anyhow::Result<Option<Policy>> {
    let Some(mut p) = load_stored(db, policy_id).await? else {
        return Ok(None);
    };
    let now = now_ms();
    let excl: Vec<ExclusionRow> = sqlx::query_as(
        "SELECT * FROM exclusions WHERE (policy_id = $1 OR policy_id IS NULL) AND (expires_at IS NULL OR expires_at > $2) ORDER BY created_at",
    )
    .bind(policy_id)
    .bind(now)
    .fetch_all(db)
    .await?;
    p.exclusions = excl.iter().filter_map(|e| e.to_exclusion()).collect();
    let iocs: Vec<IocRow> = sqlx::query_as(
        "SELECT * FROM iocs WHERE policy_id = $1 OR policy_id IS NULL ORDER BY created_at",
    )
    .bind(policy_id)
    .fetch_all(db)
    .await?;
    p.iocs = iocs.iter().filter_map(|i| i.to_ioc()).collect();
    let s = settings::load(db).await?;
    p.branding = s.branding.clone();
    if p.branding.org_name.is_empty() {
        p.branding.org_name = s.org_name.clone();
    }
    Ok(Some(p))
}

/// Largest forward jump a single agent report may cause (see [`catch_up_versions`]).
pub const MAX_VERSION_CATCH_UP: i64 = 1_000_000;

/// Agents apply only *newer* policy / rule versions. After the server database
/// is restored from a backup, the sequences are behind what agents already
/// applied, and every agent would silently ignore every later change. When an
/// agent reports a version above what the server holds for it, move the
/// server's counters past the agent's and re-version its policy so the next
/// push is accepted. A jump larger than [`MAX_VERSION_CATCH_UP`] is refused
/// (a compromised agent must not be able to run the counters up), logged and
/// reported as `false`.
pub async fn catch_up_versions(
    db: &PgPool,
    policy_id: &str,
    agent_policy: u64,
    agent_rules: u64,
) -> anyhow::Result<bool> {
    let mut ok = true;
    let agent_policy = i64::try_from(agent_policy).unwrap_or(i64::MAX);
    let agent_rules = i64::try_from(agent_rules).unwrap_or(i64::MAX);
    let cur: Option<(i64,)> = sqlx::query_as("SELECT version FROM policies WHERE id = $1")
        .bind(policy_id)
        .fetch_optional(db)
        .await?;
    if let Some((cur,)) = cur {
        if agent_policy > cur {
            let (seq_last,): (i64,) = sqlx::query_as("SELECT last_value FROM policy_version_seq")
                .fetch_one(db)
                .await?;
            if agent_policy.saturating_sub(seq_last.max(cur)) > MAX_VERSION_CATCH_UP {
                tracing::warn!(
                    policy_id,
                    agent_policy,
                    server = cur,
                    "agent reports an implausible policy version; not catching up"
                );
                ok = false;
            } else {
                // Move the global sequence past the agent, then re-version.
                sqlx::query("SELECT setval('policy_version_seq', GREATEST($1, (SELECT last_value FROM policy_version_seq)))")
                    .bind(agent_policy)
                    .execute(db)
                    .await?;
                let v = next_version(db).await?;
                sqlx::query("UPDATE policies SET version = GREATEST(version, $2), updated_at = $3 WHERE id = $1")
                    .bind(policy_id)
                    .bind(v)
                    .bind(kestrel_common::now_ms())
                    .execute(db)
                    .await?;
                tracing::warn!(
                    policy_id,
                    agent_policy,
                    server = cur,
                    new = v,
                    "policy version was behind an agent (database restored?); re-versioned"
                );
            }
        }
    }
    let (rules,): (i64,) = sqlx::query_as("SELECT rules_version FROM settings WHERE id = 1")
        .fetch_one(db)
        .await?;
    if agent_rules > rules {
        if agent_rules - rules > MAX_VERSION_CATCH_UP {
            tracing::warn!(
                agent_rules,
                server = rules,
                "agent reports an implausible rules version; not catching up"
            );
            ok = false;
        } else {
            sqlx::query(
                "UPDATE settings SET rules_version = GREATEST(rules_version, $1 + 1) WHERE id = 1",
            )
            .bind(agent_rules)
            .execute(db)
            .await?;
            tracing::warn!(
                agent_rules,
                server = rules,
                "rules version was behind an agent (database restored?); re-versioned"
            );
        }
    }
    Ok(ok)
}

pub async fn next_version(db: &PgPool) -> anyhow::Result<i64> {
    let (v,): (i64,) = sqlx::query_as("SELECT nextval('policy_version_seq')")
        .fetch_one(db)
        .await?;
    Ok(v)
}

/// Bump the version of one policy (`Some`) or all policies (`None`, for global
/// exclusions/IOCs/branding), then push to connected agents.
pub async fn bump_and_push(state: &AppState, policy_id: Option<&str>) -> anyhow::Result<()> {
    let ids: Vec<String> = match policy_id {
        Some(id) => vec![id.to_string()],
        None => sqlx::query_as::<_, (String,)>("SELECT id FROM policies")
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .map(|r| r.0)
            .collect(),
    };
    for id in &ids {
        let v = next_version(&state.db).await?;
        sqlx::query("UPDATE policies SET version = $2, updated_at = $3 WHERE id = $1")
            .bind(id)
            .bind(v)
            .bind(now_ms())
            .execute(&state.db)
            .await?;
    }
    for id in &ids {
        push_policy(state, id).await?;
    }
    Ok(())
}

/// Push a policy to every connected agent whose group uses it.
pub async fn push_policy(state: &AppState, policy_id: &str) -> anyhow::Result<usize> {
    let Some(p) = effective(&state.db, policy_id).await? else {
        return Ok(0);
    };
    let devices: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT d.id FROM devices d LEFT JOIN groups g ON g.id = d.group_id \
         WHERE d.decommissioned_at IS NULL AND COALESCE(g.policy_id, (SELECT policy_id FROM groups WHERE is_default LIMIT 1)) = $1",
    )
    .bind(policy_id)
    .fetch_all(&state.db)
    .await?;
    let mut n = 0;
    for (id,) in devices {
        if state
            .agents
            .send(&id, ServerPayload::Policy(Box::new(p.clone())))
        {
            n += 1;
        }
    }
    Ok(n)
}

/// Push a device's current effective policy (after it moved groups).
pub async fn push_device_policy(state: &AppState, device_id: Uuid) -> anyhow::Result<()> {
    let pid = device_policy_id(&state.db, device_id).await?;
    if let Some(p) = effective(&state.db, &pid).await? {
        state
            .agents
            .send(&device_id, ServerPayload::Policy(Box::new(p)));
    }
    Ok(())
}

pub async fn rules_bundle(db: &PgPool) -> anyhow::Result<RuleBundle> {
    let (version,): (i64,) = sqlx::query_as("SELECT rules_version FROM settings WHERE id = 1")
        .fetch_one(db)
        .await?;
    let rows: Vec<(serde_json::Value, String)> =
        sqlx::query_as("SELECT meta, source FROM rules WHERE enabled ORDER BY created_at")
            .fetch_all(db)
            .await?;
    let rules = rows
        .into_iter()
        .filter_map(|(meta, source)| {
            Some(RuleDef {
                meta: serde_json::from_value(meta).ok()?,
                source,
            })
        })
        .collect();
    Ok(RuleBundle {
        version: version as u64,
        rules,
    })
}

pub async fn bump_rules_and_push(state: &AppState) -> anyhow::Result<()> {
    sqlx::query("UPDATE settings SET rules_version = rules_version + 1 WHERE id = 1")
        .execute(&state.db)
        .await?;
    let bundle = rules_bundle(&state.db).await?;
    for (id, _) in state.agents.connected() {
        state.agents.send(&id, ServerPayload::Rules(bundle.clone()));
    }
    Ok(())
}
