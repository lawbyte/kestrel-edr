//! Server database restored from a backup: agents hold policy / rules
//! versions above the server's counters. The server must re-version so the
//! next push is accepted (agents only apply newer versions), and must refuse
//! implausible jumps from a hostile agent.

mod common;

use common::*;
use kestrel_common::wire::ServerPayload;
use serde_json::json;

async fn first_policy_and_rules(st: &mut AgentStream) -> (Option<u64>, Option<u64>) {
    let (_, w) = st.recv().await.unwrap();
    assert!(matches!(w, ServerPayload::Welcome { .. }), "{w:?}");
    let mut pol = None;
    let mut rules = None;
    // Policy and Rules (if any) follow the Welcome before pending commands.
    for _ in 0..2 {
        let next = tokio::time::timeout(std::time::Duration::from_secs(3), st.recv()).await;
        match next {
            Ok(Some((_, ServerPayload::Policy(p)))) => pol = Some(p.version),
            Ok(Some((_, ServerPayload::Rules(b)))) => rules = Some(b.version),
            _ => break,
        }
    }
    (pol, rules)
}

#[tokio::test]
async fn versions_catch_up_after_restore() {
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
            json!({"group_id": gid, "expires_in_days": 1, "max_uses": 5}),
        )
        .await;
    let token = tok["token"].as_str().unwrap().to_string();
    let agent = enroll(ts.grpc_port, &ca_pem, &token, "RESTORED-PC")
        .await
        .expect("enroll");

    // Fresh agent: learn the server's current versions.
    let mut st = connect(ts.grpc_port, &agent, hello(&agent, "RESTORED-PC"))
        .await
        .unwrap();
    let (p0, r0) = first_policy_and_rules(&mut st).await;
    let (p0, r0) = (p0.expect("policy pushed"), r0.expect("rules pushed"));
    drop(st);

    // The agent applied versions the (restored) server no longer knows about.
    let mut h = hello(&agent, "RESTORED-PC");
    h.policy_version = p0 + 500;
    h.rules_version = r0 + 40;
    let mut st = connect(ts.grpc_port, &agent, h).await.unwrap();
    let (p1, r1) = first_policy_and_rules(&mut st).await;
    assert!(
        p1.expect("policy re-pushed") > p0 + 500,
        "policy must be re-versioned above the agent's"
    );
    assert!(
        r1.expect("rules re-pushed") > r0 + 40,
        "rules must be re-versioned above the agent's"
    );
    drop(st);

    // A hostile agent cannot run the counters up arbitrarily.
    let mut h = hello(&agent, "RESTORED-PC");
    h.policy_version = p1.unwrap() + 50_000_000;
    h.rules_version = r1.unwrap() + 50_000_000;
    let mut st = connect(ts.grpc_port, &agent, h).await.unwrap();
    let (p2, r2) = first_policy_and_rules(&mut st).await;
    assert_eq!(
        p2, p1,
        "implausible jump ignored (policy pushed at the old version)"
    );
    assert_eq!(
        r2, r1,
        "implausible jump ignored (rules pushed at the old version)"
    );
    drop(st);
    ts.cleanup().await;
}
