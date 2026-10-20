use super::ApiJson;
use crate::{
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    state::AppState,
    telemetry::{events_to_api, hunt, EventQuery},
};
use axum::{extract::State, Json};
use kestrel_common::now_ms;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct HuntBody {
    #[serde(default)]
    query: String,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<u32>,
}

pub async fn hunt(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<HuntBody>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let filter =
        hunt::parse(&b.query).map_err(|e| ApiError::bad_request(format!("invalid query: {e}")))?;
    let to = b.to.unwrap_or_else(now_ms);
    let from = b.from.unwrap_or(to - 86_400_000);
    if from > to {
        return Err(ApiError::bad_request("from must be before to"));
    }
    let limit = b.limit.unwrap_or(500).clamp(1, 5000);
    let started = std::time::Instant::now();
    let q = EventQuery {
        filter,
        from: Some(from),
        to: Some(to),
        limit,
        ..Default::default()
    };
    let rows = st.events.query(&q).await.map_err(|e| {
        tracing::error!(error = %e, "hunt query failed");
        ApiError::internal("telemetry query failed")
    })?;
    let items = events_to_api(st.events.as_ref(), &rows, true).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // Analyst access to employee telemetry is itself audited (privacy).
    audit::log(
        &st.db,
        &p.actor(),
        "hunt.query",
        "events",
        json!({"query": b.query, "from": from, "to": to, "results": items.len()}),
    )
    .await;
    Ok(Json(
        json!({"items": items, "elapsed_ms": elapsed_ms, "backend": st.events.backend()}),
    ))
}
