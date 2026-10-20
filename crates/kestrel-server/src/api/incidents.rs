use super::{
    csv, double_option, list_response, page, parse_uuid, ApiJson, ApiPath, ApiQuery, Arg, Filter,
};
use crate::{
    api::devices::like_escape,
    audit,
    auth::Principal,
    crypto::canonical_json,
    error::{ApiError, ApiResult},
    incidents::{describe_action, recompute_incident},
    ingest,
    models::{
        self, action_select, incident_select, user_cols, ActionRow, AlertRow, IncidentRow,
        JoinedUser, ALERT_SELECT,
    },
    state::AppState,
    telemetry::EventQuery,
};
use axum::{extract::State, Json};
use kestrel_common::{now_ms, Alert, EventData, ProcessInfo, ResponseAction};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

#[derive(Deserialize, Default)]
pub struct IncidentFilters {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub assignee: Option<String>,
    pub device_id: Option<String>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<IncidentFilters>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let pg = page(q.limit, q.cursor.as_deref())?;
    let mut f = Filter::default();
    let statuses = csv(&q.status);
    if !statuses.is_empty() {
        f.push("i.status = ANY(?)", vec![Arg::Strs(statuses)]);
    }
    let sevs = csv(&q.severity);
    if !sevs.is_empty() {
        f.push("i.severity = ANY(?)", vec![Arg::Strs(sevs)]);
    }
    match q.assignee.as_deref() {
        None | Some("") => {}
        Some("me") => f.push("i.assignee_id = ?", vec![Arg::Uuid(p.user.id)]),
        Some("none") | Some("unassigned") => f.push("i.assignee_id IS NULL", vec![]),
        Some(id) => f.push("i.assignee_id = ?", vec![Arg::Uuid(parse_uuid(id)?)]),
    }
    if let Some(d) = q.device_id.as_ref().filter(|s| !s.is_empty()) {
        f.push("i.device_id = ?", vec![Arg::Uuid(parse_uuid(d)?)]);
    }
    if let Some(text) = q.q.as_ref().filter(|s| !s.trim().is_empty()) {
        let pat = format!("%{}%", like_escape(text.trim()));
        f.push(
            "(i.title ILIKE ? OR d.hostname ILIKE ? OR COALESCE(i.user_name,'') ILIKE ? OR array_to_string(i.rule_ids,' ') ILIKE ?)",
            vec![Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat)],
        );
    }
    let order = match q.sort.as_deref() {
        Some("created") => "i.created_at DESC, i.id",
        _ => "i.priority DESC, i.updated_at DESC, i.id",
    };
    let w = f.where_sql();
    let base = incident_select();
    let total: i64 = f
        .bind_scalar(sqlx::query_scalar(&format!(
            "SELECT count(*) FROM ({base} WHERE {w}) x"
        )))
        .fetch_one(&st.db)
        .await?;
    let rows: Vec<IncidentRow> = f
        .bind(sqlx::query_as(&format!(
            "{base} WHERE {w} ORDER BY {order} LIMIT {} OFFSET {}",
            pg.limit, pg.offset
        )))
        .fetch_all(&st.db)
        .await?;
    Ok(Json(list_response(
        rows.iter().map(|i| i.to_api()).collect(),
        total,
        &pg,
    )))
}

#[derive(sqlx::FromRow)]
struct ChecklistRow {
    id: Uuid,
    kind: String,
    text: String,
    done: bool,
    action: Option<Value>,
    response_action_id: Option<Uuid>,
    done_at: Option<i64>,
}

impl ChecklistRow {
    fn to_api(&self) -> Value {
        let mut v = json!({"id": self.id, "text": self.text, "kind": self.kind, "done": self.done,
                           "response_action_id": self.response_action_id, "done_at": self.done_at});
        if let Some(a) = &self.action {
            v["action"] = a.clone();
        }
        v
    }
}

const CHECKLIST_SELECT: &str =
    "SELECT id, kind, text, done, action, response_action_id, done_at FROM incident_checklist";
const CHECKLIST_ORDER: &str =
    "ORDER BY CASE kind WHEN 'done' THEN 0 WHEN 'approve' THEN 1 ELSE 2 END, position";

#[derive(sqlx::FromRow)]
struct CommentRow {
    id: Uuid,
    body: String,
    ts: i64,
    a_id: Option<Uuid>,
    a_email: Option<String>,
    a_name: Option<String>,
    a_role: Option<String>,
    a_last_login: Option<i64>,
    a_created_at: Option<i64>,
    a_disabled: Option<bool>,
    a_mfa_enabled: Option<bool>,
}

impl CommentRow {
    fn author(&self) -> JoinedUser {
        models::joined_user!(self)
    }
    fn to_api(&self) -> Value {
        json!({"id": self.id, "author": self.author().to_api(), "body": self.body, "ts": self.ts})
    }
}

#[derive(sqlx::FromRow)]
struct ActivityRow {
    ts: i64,
    kind: String,
    title: String,
    detail: String,
    a_id: Option<Uuid>,
    a_email: Option<String>,
    a_name: Option<String>,
    a_role: Option<String>,
    a_last_login: Option<i64>,
    a_created_at: Option<i64>,
    a_disabled: Option<bool>,
    a_mfa_enabled: Option<bool>,
}

fn node_json(pi: &ProcessInfo, rules: &[String], root: &str) -> Value {
    json!({
        "guid": pi.guid,
        "parent_guid": pi.parent_guid,
        "pid": pi.pid,
        "image": pi.image,
        "cmdline": pi.cmdline,
        "user": pi.user,
        "start_ts": pi.start_ts,
        "exit_ts": pi.exit_ts,
        "signer": pi.signer,
        "signed": pi.signed,
        "sha256": pi.sha256,
        "path_class": pi.path_class,
        "alert_rule_ids": rules,
        "is_root": pi.guid.0 == root,
    })
}

pub async fn detail(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    let inc = models::load_incident(&st.db, id).await?;
    let alert_rows: Vec<AlertRow> = sqlx::query_as(&format!(
        "{ALERT_SELECT} WHERE a.incident_id = $1 ORDER BY a.ts"
    ))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let bodies: Vec<(Value,)> =
        sqlx::query_as("SELECT body FROM alerts WHERE incident_id = $1 ORDER BY ts")
            .bind(id)
            .fetch_all(&st.db)
            .await?;
    let alerts: Vec<Alert> = bodies
        .into_iter()
        .filter_map(|(b,)| serde_json::from_value(b).ok())
        .collect();

    // ---- process tree: alert chains + descendants of the root from telemetry
    let mut nodes: BTreeMap<String, ProcessInfo> = BTreeMap::new();
    let mut rules: HashMap<String, Vec<String>> = HashMap::new();
    for a in &alerts {
        for pi in std::iter::once(&a.process).chain(a.ancestry.iter()) {
            nodes.entry(pi.guid.0.clone()).or_insert_with(|| pi.clone());
        }
        let r = rules.entry(a.process.guid.0.clone()).or_default();
        if !r.contains(&a.rule_id) {
            r.push(a.rule_id.clone());
        }
    }
    let window = crate::incidents::GROUP_WINDOW_MS;
    let telemetry_q = EventQuery {
        device_id: Some(inc.device_id),
        kinds: vec![
            "process_start".into(),
            "process_stop".into(),
            "net_connect".into(),
        ],
        from: Some(inc.first_alert_at - window),
        to: Some(inc.last_alert_at + window),
        limit: 5000,
        ascending: true,
        ..Default::default()
    };
    let telemetry = match st.events.query(&telemetry_q).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "incident telemetry lookup failed");
            vec![]
        }
    };
    let mut children: HashMap<String, Vec<ProcessInfo>> = HashMap::new();
    let mut stops: HashMap<String, i64> = HashMap::new();
    let mut net_events = vec![];
    for se in &telemetry {
        let Some(e) = se.event() else { continue };
        match &e.data {
            EventData::ProcessStart(ps) => {
                if let Some(parent) = &ps.parent_guid {
                    let pi =
                        crate::telemetry::reconstruct_processes(std::slice::from_ref(se), i64::MAX);
                    if let Some(pi) = pi.into_iter().next() {
                        children.entry(parent.0.clone()).or_default().push(pi);
                    }
                }
            }
            EventData::ProcessStop { .. } => {
                stops.insert(e.guid.0.clone(), e.ts);
            }
            EventData::NetConnect { .. } => net_events.push(e),
            _ => {}
        }
    }
    let mut queue: Vec<String> = vec![inc.root_guid.clone()];
    let mut seen: HashSet<String> = HashSet::new();
    while let Some(g) = queue.pop() {
        if !seen.insert(g.clone()) || nodes.len() > 500 {
            continue;
        }
        if let Some(kids) = children.get(&g) {
            for k in kids {
                nodes.entry(k.guid.0.clone()).or_insert_with(|| k.clone());
                queue.push(k.guid.0.clone());
            }
        }
    }
    for (g, ts) in &stops {
        if let Some(n) = nodes.get_mut(g) {
            if n.exit_ts.is_none() {
                n.exit_ts = Some(*ts);
            }
        }
    }
    let mut tree: Vec<&ProcessInfo> = nodes.values().collect();
    tree.sort_by_key(|p| p.start_ts);
    let process_tree: Vec<Value> = tree
        .iter()
        .map(|pi| {
            node_json(
                pi,
                rules.get(&pi.guid.0).map(|v| v.as_slice()).unwrap_or(&[]),
                &inc.root_guid,
            )
        })
        .collect();

    // ---- evidence (merged, dedup, ≤200)
    let mut ev_seen = HashSet::new();
    let mut evidence: Vec<kestrel_common::Event> = vec![];
    for a in &alerts {
        for e in &a.evidence {
            let key = canonical_json(&serde_json::to_value(e).unwrap_or_default());
            if ev_seen.insert(key) {
                evidence.push(e.clone());
            }
        }
    }
    evidence.sort_by_key(|e| e.ts);
    evidence.truncate(200);

    // ---- actions
    let actions: Vec<ActionRow> = sqlx::query_as(&format!(
        "{} WHERE r.incident_id = $1 ORDER BY r.created_at",
        action_select()
    ))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let blocked: HashSet<String> = actions
        .iter()
        .filter(|a| a.status == "succeeded")
        .filter_map(|a| serde_json::from_value::<ResponseAction>(a.action.clone()).ok())
        .filter_map(|a| match a {
            ResponseAction::BlockDestination { ip, .. } => Some(ip),
            _ => None,
        })
        .collect();

    // ---- network: evidence + telemetry for processes in the tree
    let mut net = vec![];
    let mut net_seen = HashSet::new();
    for e in evidence
        .iter()
        .chain(net_events.iter().filter(|e| nodes.contains_key(&e.guid.0)))
    {
        if let EventData::NetConnect {
            dst_ip,
            dst_port,
            dst_host,
            ..
        } = &e.data
        {
            if !net_seen.insert((e.ts, e.guid.0.clone(), dst_ip.clone(), *dst_port)) {
                continue;
            }
            net.push((
                e.ts,
                json!({
                    "ts": e.ts,
                    "process_guid": e.guid,
                    "image": nodes.get(&e.guid.0).map(|n| n.image.clone()).unwrap_or_default(),
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "dst_host": dst_host,
                    "blocked": blocked.contains(dst_ip),
                }),
            ));
        }
    }
    net.sort_by_key(|(ts, _)| *ts);
    let network: Vec<Value> = net.into_iter().map(|(_, v)| v).take(500).collect();

    // ---- checklist, comments, timeline
    let checklist: Vec<ChecklistRow> = sqlx::query_as(&format!(
        "{CHECKLIST_SELECT} WHERE incident_id = $1 {CHECKLIST_ORDER}"
    ))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let comments: Vec<CommentRow> = sqlx::query_as(&format!(
        "SELECT c.id, c.body, c.ts, {} FROM incident_comments c LEFT JOIN users u ON u.id = c.author_id WHERE c.incident_id = $1 ORDER BY c.ts",
        user_cols("u", "a_")
    ))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let activity: Vec<ActivityRow> = sqlx::query_as(&format!(
        "SELECT x.ts, x.kind, x.title, x.detail, {} FROM incident_activity x LEFT JOIN users u ON u.id = x.actor_id WHERE x.incident_id = $1 ORDER BY x.ts, x.id",
        user_cols("u", "a_")
    ))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let mut timeline: Vec<(i64, Value)> = activity
        .iter()
        .map(|a| (a.ts, json!({"ts": a.ts, "kind": a.kind, "title": a.title, "detail": a.detail, "actor": models::joined_user!(a).to_api()})))
        .collect();
    for c in &comments {
        timeline.push((c.ts, json!({"ts": c.ts, "kind": "comment", "title": "Comment", "detail": c.body, "actor": c.author().to_api()})));
    }
    timeline.sort_by_key(|(ts, _)| *ts);

    let mut v = inc.to_api();
    let o = v.as_object_mut().expect("object");
    o.insert("storyline".into(), inc.storyline.clone().into());
    o.insert(
        "alerts".into(),
        alert_rows
            .iter()
            .map(|a| a.to_api())
            .collect::<Vec<_>>()
            .into(),
    );
    o.insert("process_tree".into(), process_tree.into());
    o.insert(
        "timeline".into(),
        timeline
            .into_iter()
            .map(|(_, v)| v)
            .collect::<Vec<_>>()
            .into(),
    );
    o.insert("evidence".into(), serde_json::to_value(&evidence)?);
    o.insert("network".into(), network.into());
    o.insert(
        "actions".into(),
        actions
            .iter()
            .map(|a| a.to_api())
            .collect::<Vec<_>>()
            .into(),
    );
    o.insert(
        "checklist".into(),
        checklist
            .iter()
            .map(|c| c.to_api())
            .collect::<Vec<_>>()
            .into(),
    );
    o.insert(
        "comments".into(),
        comments
            .iter()
            .map(|c| c.to_api())
            .collect::<Vec<_>>()
            .into(),
    );
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct PatchIncident {
    status: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    assignee_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double_option")]
    classification: Option<Option<String>>,
}

pub async fn update(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<PatchIncident>,
) -> ApiResult<Json<Value>> {
    p.require("incidents.write")?;
    let id = parse_uuid(&id)?;
    let before = models::load_incident(&st.db, id).await?;
    let now = now_ms();
    let mut tx = st.db.begin().await?;
    if let Some(s) = &b.status {
        if !["open", "in_progress", "resolved", "dismissed"].contains(&s.as_str()) {
            return Err(ApiError::bad_request("invalid status"));
        }
        if *s != before.status {
            let closed = s == "resolved" || s == "dismissed";
            sqlx::query("UPDATE incidents SET status = $2, resolved_at = CASE WHEN $3 THEN $4 ELSE NULL END, updated_at = $4 WHERE id = $1")
                .bind(id)
                .bind(s)
                .bind(closed)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if closed {
                sqlx::query("UPDATE alerts SET status = 'closed' WHERE incident_id = $1 AND status != 'closed'").bind(id).execute(&mut *tx).await?;
            }
            activity(
                &mut tx,
                id,
                now,
                "status",
                &format!("Status changed to {s}"),
                &format!("from {}", before.status),
                Some(p.user.id),
            )
            .await?;
        }
    }
    if let Some(a) = &b.assignee_id {
        let mut label = "Unassigned".to_string();
        if let Some(uid) = a {
            let u: Option<(String,)> =
                sqlx::query_as("SELECT email FROM users WHERE id = $1 AND NOT disabled")
                    .bind(uid)
                    .fetch_optional(&mut *tx)
                    .await?;
            let u = u.ok_or_else(|| ApiError::bad_request("assignee does not exist"))?;
            label = format!("Assigned to {}", u.0);
        }
        sqlx::query("UPDATE incidents SET assignee_id = $2, updated_at = $3 WHERE id = $1")
            .bind(id)
            .bind(*a)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        activity(&mut tx, id, now, "status", &label, "", Some(p.user.id)).await?;
    }
    if let Some(c) = &b.classification {
        if let Some(c) = c {
            if !["true_positive", "false_positive", "benign"].contains(&c.as_str()) {
                return Err(ApiError::bad_request("invalid classification"));
            }
        }
        sqlx::query("UPDATE incidents SET classification = $2, updated_at = $3 WHERE id = $1")
            .bind(id)
            .bind(c.as_deref())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        activity(
            &mut tx,
            id,
            now,
            "status",
            &format!("Classified as {}", c.as_deref().unwrap_or("unclassified")),
            "",
            Some(p.user.id),
        )
        .await?;
    }
    tx.commit().await?;
    audit::log(&st.db, &p.actor(), "incident.update", id.to_string(), json!({"status": b.status, "assignee_id": b.assignee_id, "classification": b.classification})).await;
    st.publish("incident", id, "updated");
    Ok(Json(models::load_incident(&st.db, id).await?.to_api()))
}

async fn activity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    incident: Uuid,
    ts: i64,
    kind: &str,
    title: &str,
    detail: &str,
    actor: Option<Uuid>,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO incident_activity (incident_id, ts, kind, title, detail, actor_id) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(incident)
        .bind(ts)
        .bind(kind)
        .bind(title)
        .bind(detail)
        .bind(actor)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct CommentBody {
    body: String,
}

pub async fn comment(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<CommentBody>,
) -> ApiResult<Json<Value>> {
    p.require("incidents.write")?;
    let id = parse_uuid(&id)?;
    models::load_incident(&st.db, id).await?;
    let body = b.body.trim();
    if body.is_empty() || body.len() > 20_000 {
        return Err(ApiError::bad_request(
            "comment body must be 1-20000 characters",
        ));
    }
    let cid = Uuid::new_v4();
    let now = now_ms();
    sqlx::query("INSERT INTO incident_comments (id, incident_id, author_id, body, ts) VALUES ($1,$2,$3,$4,$5)")
        .bind(cid)
        .bind(id)
        .bind(p.user.id)
        .bind(body)
        .bind(now)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE incidents SET updated_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "incident.comment",
        id.to_string(),
        json!({"comment_id": cid}),
    )
    .await;
    st.publish("incident", id, "updated");
    Ok(Json(
        json!({"id": cid, "author": p.user.to_api(), "body": body, "ts": now}),
    ))
}

#[derive(Deserialize)]
pub struct ChecklistBody {
    done: bool,
}

pub async fn checklist(
    State(st): State<AppState>,
    p: Principal,
    ApiPath((id, item_id)): ApiPath<(String, String)>,
    ApiJson(b): ApiJson<ChecklistBody>,
) -> ApiResult<Json<Value>> {
    p.require("incidents.write")?;
    let id = parse_uuid(&id)?;
    let item_id = parse_uuid(&item_id)?;
    let inc = models::load_incident(&st.db, id).await?;
    let item: ChecklistRow = sqlx::query_as(&format!(
        "{CHECKLIST_SELECT} WHERE id = $1 AND incident_id = $2"
    ))
    .bind(item_id)
    .bind(id)
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::not_found("checklist item not found"))?;
    let now = now_ms();
    let mut response_action_id = item.response_action_id;
    if b.done && item.kind == "approve" && item.response_action_id.is_none() {
        if let Some(action) = item
            .action
            .clone()
            .and_then(|a| serde_json::from_value::<ResponseAction>(a).ok())
        {
            p.require(action.privilege())?;
            let comment = format!("Approved from incident checklist: {}", item.text);
            let aid = ingest::enqueue_command(
                &st,
                inc.device_id,
                Some(id),
                &action,
                Some(p.user.id),
                &comment,
            )
            .await?;
            response_action_id = Some(aid);
            audit::log(&st.db, &p.actor(), "device.action", inc.device_id.to_string(), json!({"action": action, "incident_id": id, "action_id": aid, "via": "checklist", "description": describe_action(&action)})).await;
        }
    }
    sqlx::query("UPDATE incident_checklist SET done = $2, done_by = $3, done_at = $4, response_action_id = $5 WHERE id = $1")
        .bind(item_id)
        .bind(b.done)
        .bind(if b.done { Some(p.user.id) } else { None })
        .bind(if b.done { Some(now) } else { None })
        .bind(response_action_id)
        .execute(&st.db)
        .await?;
    let mut tx = st.db.begin().await?;
    activity(
        &mut tx,
        id,
        now,
        "status",
        &format!(
            "{} checklist item",
            if b.done { "Completed" } else { "Reopened" }
        ),
        &item.text,
        Some(p.user.id),
    )
    .await?;
    recompute_incident(&mut tx, id).await?;
    tx.commit().await?;
    audit::log(
        &st.db,
        &p.actor(),
        "incident.checklist",
        id.to_string(),
        json!({"item_id": item_id, "done": b.done, "text": item.text}),
    )
    .await;
    st.publish("incident", id, "updated");
    let row: ChecklistRow = sqlx::query_as(&format!("{CHECKLIST_SELECT} WHERE id = $1"))
        .bind(item_id)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(row.to_api()))
}
