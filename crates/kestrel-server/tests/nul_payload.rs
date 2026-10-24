//! Lab VM regression (2026-10-21): an event whose command line contained a
//! NUL character made PostgreSQL reject the insert ("unsupported Unicode escape
//! sequence"); the server closed the stream and the agent re-sent the same
//! message forever, so no later alert ever arrived. The message must be
//! stored (NUL replaced) and acked, and the stream must keep working.

mod common;

use common::*;
use kestrel_common::{
    wire::{AgentPayload, ServerPayload},
    Event, EventData, ProcessGuid, ProcessStart,
};
use serde_json::json;

#[tokio::test]
async fn nul_in_event_does_not_wedge_the_stream() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca_pem = inst["ca_pem"].as_str().unwrap().to_string();
    let (_, groups) = ts.get("/api/groups").await;
    let gid = groups[0]["id"].as_str().unwrap().to_string();
    let (_, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"group_id": gid, "expires_in_days": 1, "max_uses": 1}),
        )
        .await;
    let agent = enroll(
        ts.grpc_port,
        &ca_pem,
        tok["token"].as_str().unwrap(),
        "NUL-PC",
    )
    .await
    .expect("enroll");
    let mut st = connect(ts.grpc_port, &agent, hello(&agent, "NUL-PC"))
        .await
        .unwrap();
    let ev = |pid: u32, cmd: &str| Event {
        ts: kestrel_common::now_ms(),
        pid,
        guid: ProcessGuid(format!("g{pid}")),
        data: EventData::ProcessStart(ProcessStart {
            image: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: cmd.into(),
            ..Default::default()
        }),
    };
    let bad = st
        .send(&AgentPayload::Events {
            events: vec![ev(10, "cmd.exe /c echo a\u{0}b")],
            repeats: vec![],
        })
        .await;
    let good = st
        .send(&AgentPayload::Events {
            events: vec![ev(11, "cmd.exe /c echo after")],
            repeats: vec![],
        })
        .await;
    let mut acked = 0;
    while acked < good {
        let (_, p, _) = st
            .recv_until(|p| matches!(p, ServerPayload::Ack { .. }))
            .await;
        if let ServerPayload::Ack { seq } = p {
            acked = seq;
        }
    }
    assert!(acked >= bad && acked >= good, "both batches acked");
    ts.cleanup().await;
}
