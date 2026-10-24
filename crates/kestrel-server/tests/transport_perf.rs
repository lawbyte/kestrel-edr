//! Endpoint footprint (2026-10-25): plain frames from every agent keep
//! working; an agent that advertises `grpc-accept-encoding: zstd` gets
//! compressed responses; compressed *requests* are refused (unbounded
//! inflation in tonic 0.12, review H1); repeat summaries
//! (`AgentPayload::Events.repeats`) are stored on the event row
//! (`repeat_count`, `repeat_first_ts`).

mod common;

use common::*;
use kestrel_common::{
    wire::{AgentPayload, EventRepeat},
    Event, EventData, ProcessGuid,
};
use kestrel_server::grpc::pb::{agent_service_client::AgentServiceClient, AgentEnvelope};
use serde_json::json;
use tokio::sync::mpsc;
use tonic::codec::CompressionEncoding;

/// Connect like `common::connect`, accepting zstd responses and optionally
/// compressing requests.
async fn connect_with(
    port: u16,
    agent: &TestAgent,
    host: &str,
    send: Option<CompressionEncoding>,
) -> Result<AgentStream, tonic::Code> {
    let ch = channel(port, &agent.ca_pem, Some((&agent.cert_pem, &agent.key_pem)))
        .await
        .unwrap();
    let mut client = AgentServiceClient::new(ch).accept_compressed(CompressionEncoding::Zstd);
    if let Some(enc) = send {
        client = client.send_compressed(enc);
    }
    let (tx, rx) = mpsc::channel::<AgentEnvelope>(64);
    tx.send(AgentEnvelope {
        seq: 0,
        compressed: false,
        payload: serde_json::to_vec(&AgentPayload::Hello(hello(agent, host))).unwrap(),
    })
    .await
    .unwrap();
    let resp = client
        .connect(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .map_err(|s| s.code())?;
    let mut rx = resp.into_inner();
    // The first frame decides: a refused encoding fails here.
    match tokio::time::timeout(std::time::Duration::from_secs(15), rx.message()).await {
        Ok(Ok(Some(_welcome))) => {}
        Ok(Ok(None)) => return Err(tonic::Code::Unavailable),
        Ok(Err(s)) => return Err(s.code()),
        Err(_) => return Err(tonic::Code::DeadlineExceeded),
    }
    Ok(AgentStream { tx, rx, seq: 0 })
}

fn dpapi(ts: i64) -> Event {
    Event {
        ts,
        pid: 77,
        guid: ProcessGuid("g-vpn".into()),
        data: EventData::DpapiUnprotect {
            description: "NordVPN".into(),
        },
    }
}

async fn new_agent(ts: &TestServer, host: &str) -> TestAgent {
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
    enroll(ts.grpc_port, &ca_pem, tok["token"].as_str().unwrap(), host)
        .await
        .expect("enroll")
}

#[tokio::test]
async fn plain_and_zstd_response_agents_work_compressed_requests_refused() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;

    // Plain frames (every agent up to 1.1.6).
    let old = new_agent(&ts, "PLAIN-PC").await;
    let mut st = connect(ts.grpc_port, &old, hello(&old, "PLAIN-PC"))
        .await
        .unwrap();
    let s = st
        .send(&AgentPayload::Events {
            events: vec![dpapi(kestrel_common::now_ms())],
            repeats: vec![],
        })
        .await;
    st.wait_ack(s).await;

    // zstd responses for an agent that accepts them; plain requests.
    let agent = new_agent(&ts, "ZSTD-PC").await;
    let mut st = connect_with(ts.grpc_port, &agent, "ZSTD-PC", None)
        .await
        .expect("plain requests with zstd responses");
    let now = kestrel_common::now_ms();
    let s = st
        .send(&AgentPayload::Events {
            events: vec![dpapi(now - 60_000), dpapi(now)],
            repeats: vec![EventRepeat {
                index: 1,
                count: 25_999,
                first_ts: now - 59_000,
            }],
        })
        .await;
    st.wait_ack(s).await;
    let (code, evs) = ts
        .get(&format!(
            "/api/devices/{}/events?kinds=dpapi_unprotect",
            agent.device_id
        ))
        .await;
    assert_eq!(code, 200);
    let items = evs["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{evs}");
    let counts: Vec<i64> = items
        .iter()
        .filter_map(|i| i["repeat_count"].as_i64())
        .collect();
    assert_eq!(counts, vec![25_999], "{evs}");

    // Compressed requests are refused before anything is inflated.
    // (gzip is not even compiled in.)
    let agent = new_agent(&ts, "ZREQ-PC").await;
    let r = connect_with(
        ts.grpc_port,
        &agent,
        "ZREQ-PC",
        Some(CompressionEncoding::Zstd),
    )
    .await;
    assert_eq!(r.err(), Some(tonic::Code::Unimplemented));
    ts.cleanup().await;
}
