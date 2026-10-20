use crate::{
    auth::{session_still_valid, Principal, Via},
    error::ApiResult,
    state::AppState,
};
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::Stream;
use std::{convert::Infallible, time::Duration};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

/// How often a live stream re-checks its session (logout, disable, role change, expiry).
pub const REVALIDATE_EVERY: Duration = Duration::from_secs(60);

/// `GET /api/events/stream`: `event: incident|alert|device|action`, data `{id, type}`.
/// The stream ends (after an `event: session` message) once the session that
/// opened it is no longer valid or no longer has `read` (L5).
pub async fn stream(
    State(st): State<AppState>,
    p: Principal,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    p.require("read")?;
    let session = match &p.via {
        Via::Session { token_hash, .. } => Some(token_hash.clone()),
        Via::Token { .. } => None,
    };
    let token_id = match &p.via {
        Via::Token { id, .. } => Some(*id),
        Via::Session { .. } => None,
    };
    let mut rx = BroadcastStream::new(st.live.subscribe());
    let s = async_stream::stream! {
        let mut tick = tokio::time::interval(REVALIDATE_EVERY);
        tick.tick().await; // first tick is immediate
        loop {
            tokio::select! {
                msg = rx.next() => match msg {
                    Some(Ok(ev)) => yield Ok(Event::default()
                        .event(ev.entity)
                        .data(serde_json::to_string(&ev).unwrap_or_default())),
                    // Lagged consumer: tell the console to resync.
                    Some(Err(_)) => yield Ok(Event::default().event("resync").data("{}")),
                    None => break,
                },
                _ = tick.tick() => {
                    let ok = match (&session, token_id) {
                        (Some(th), _) => session_still_valid(&st, th, "read").await.unwrap_or(false),
                        (None, Some(id)) => token_still_valid(&st, id).await.unwrap_or(false),
                        _ => false,
                    };
                    if !ok {
                        yield Ok(Event::default().event("session").data(r#"{"type":"expired"}"#));
                        break;
                    }
                }
            }
        }
    };
    Ok(Sse::new(s).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(20))
            .text("ping"),
    ))
}

async fn token_still_valid(st: &AppState, id: uuid::Uuid) -> anyhow::Result<bool> {
    let row: Option<(Option<i64>, bool)> = sqlx::query_as(
        "SELECT t.expires_at, u.disabled FROM api_tokens t JOIN users u ON u.id = t.created_by WHERE t.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    Ok(
        matches!(row, Some((exp, false)) if exp.map(|e| e > kestrel_common::now_ms()).unwrap_or(true)),
    )
}
