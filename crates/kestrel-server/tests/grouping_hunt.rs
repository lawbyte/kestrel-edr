//! Incident grouping rules and the hunt endpoint (parser → parameterised SQL)
//! on Postgres, and on ClickHouse when `KESTREL_TEST_CLICKHOUSE_URL` is set.

mod common;

use common::TestServer;
use kestrel_common::{
    now_ms, Alert, Event, EventData, NetProto, PathClass, ProcessGuid, ProcessInfo, ProcessStart,
    RuleMode, Severity, SignatureState,
};
use kestrel_server::{incidents::ingest_alert, telemetry::EventRow};
use serde_json::{json, Value};
use uuid::Uuid;

async fn device(ts: &TestServer, hostname: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices (id, hostname, first_seen, last_seen, group_id) VALUES ($1, $2, $3, $3, (SELECT id FROM groups WHERE is_default))")
        .bind(id)
        .bind(hostname)
        .bind(now_ms())
        .execute(&ts.state.db)
        .await
        .unwrap();
    id
}

fn pi(guid: &str, image: &str, parent: Option<&str>) -> ProcessInfo {
    ProcessInfo {
        guid: ProcessGuid(guid.into()),
        pid: 10,
        ppid: 1,
        parent_guid: parent.map(|p| ProcessGuid(p.into())),
        image: image.into(),
        cmdline: image.into(),
        user: None,
        integrity: None,
        start_ts: 0,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unsigned,
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: PathClass::of(image),
    }
}

fn alert(ts: i64, proc_guid: &str, root_guid: &str, rule: &str) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        ts,
        rule_id: rule.into(),
        rule_name: format!("Rule {rule}"),
        rule_author: None,
        severity: Severity::Medium,
        attack: vec![],
        mode: RuleMode::Audit,
        summary: "test".into(),
        // child runs from System32 (e.g. cmd.exe) under a user-path root
        process: pi(proc_guid, r"C:\Windows\System32\cmd.exe", Some(root_guid)),
        ancestry: vec![
            pi(
                root_guid,
                r"C:\Users\bob\AppData\Local\Temp\drop.exe",
                Some("explorer"),
            ),
            pi("explorer", r"C:\Windows\explorer.exe", None),
        ],
        data_at_risk: vec![],
        evidence: vec![],
        actions: vec![],
    }
}

#[tokio::test]
async fn incident_grouping() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let d1 = device(&ts, "HOST-A").await;
    let d2 = device(&ts, "HOST-B").await;
    let t0 = now_ms() - 3 * 3_600_000;

    let a = ingest_alert(&ts.state, d1, alert(t0, "c1", "root-1", "ST-01"))
        .await
        .unwrap();
    assert!(a.incident_created);
    // Same device, same root, 10 min later, different child process → same incident.
    let b = ingest_alert(
        &ts.state,
        d1,
        alert(t0 + 10 * 60_000, "c2", "root-1", "ST-02"),
    )
    .await
    .unwrap();
    assert!(!b.incident_created);
    assert_eq!(a.incident_id, b.incident_id);
    // Out-of-order alert slightly before the first one still groups.
    let b2 = ingest_alert(
        &ts.state,
        d1,
        alert(t0 - 5 * 60_000, "c0", "root-1", "ST-03"),
    )
    .await
    .unwrap();
    assert_eq!(a.incident_id, b2.incident_id);
    // Different root tree → new incident.
    let c = ingest_alert(
        &ts.state,
        d1,
        alert(t0 + 11 * 60_000, "c3", "root-2", "ST-01"),
    )
    .await
    .unwrap();
    assert!(c.incident_created);
    // Same root but > 30 min after the last alert → new incident.
    let d = ingest_alert(
        &ts.state,
        d1,
        alert(t0 + 41 * 60_000, "c4", "root-1", "ST-01"),
    )
    .await
    .unwrap();
    assert!(d.incident_created);
    assert_ne!(d.incident_id, a.incident_id);
    // Same root id on another device → new incident.
    let e = ingest_alert(&ts.state, d2, alert(t0, "c1", "root-1", "ST-01"))
        .await
        .unwrap();
    assert!(e.incident_created);
    // Duplicate alert id (agent outbox replay) is ignored.
    let dup = alert(t0 + 60_000, "c9", "root-1", "ST-01");
    ingest_alert(&ts.state, d1, dup.clone()).await.unwrap();
    let again = ingest_alert(&ts.state, d1, dup).await.unwrap();
    assert!(again.duplicate);
    // Resolved incidents are not reopened by new alerts.
    sqlx::query("UPDATE incidents SET status = 'resolved' WHERE id = ANY($1)")
        .bind(vec![a.incident_id.unwrap(), d.incident_id.unwrap()])
        .execute(&ts.state.db)
        .await
        .unwrap();
    let f = ingest_alert(
        &ts.state,
        d1,
        alert(t0 + 12 * 60_000, "c5", "root-1", "ST-01"),
    )
    .await
    .unwrap();
    assert!(f.incident_created);

    let (n,): (i64,) = sqlx::query_as("SELECT alert_count::bigint FROM incidents WHERE id = $1")
        .bind(a.incident_id)
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(n, 4);
    let (title, rules): (String, Vec<String>) =
        sqlx::query_as("SELECT title, rule_ids FROM incidents WHERE id = $1")
            .bind(a.incident_id)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert!(
        title.contains("drop.exe") && title.contains("HOST-A"),
        "{title}"
    );
    assert_eq!(rules, vec!["ST-01", "ST-02", "ST-03"]);
    ts.cleanup().await;
}

/// ClickFix: explorer.exe (RunMRU, ST-10) → powershell.exe (ST-11) → payload
/// in Temp (ST-04). explorer and powershell are system-path binaries, so each
/// alert's own root differs; the later alerts must still join the incident
/// rooted at their ancestor, and the title names the payload.
#[tokio::test]
async fn clickfix_chain_groups_under_ancestor_root() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    let d = device(&ts, "HOST-CF").await;
    let t0 = now_ms() - 3_600_000;
    let explorer = pi("exp", r"C:\Windows\explorer.exe", None);
    let ps = pi(
        "ps",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Some("exp"),
    );
    let payload = pi(
        "pay",
        r"C:\Users\bob\AppData\Local\Temp\vcredist.exe",
        Some("ps"),
    );
    let mk = |ts_: i64, rule: &str, process: ProcessInfo, ancestry: Vec<ProcessInfo>| Alert {
        id: Uuid::new_v4(),
        ts: ts_,
        rule_id: rule.into(),
        rule_name: format!("Rule {rule}"),
        rule_author: None,
        severity: Severity::High,
        attack: vec![],
        mode: RuleMode::Audit,
        summary: "test".into(),
        process,
        ancestry,
        data_at_risk: vec![],
        evidence: vec![],
        actions: vec![],
    };
    let a = ingest_alert(&ts.state, d, mk(t0, "ST-10", explorer.clone(), vec![]))
        .await
        .unwrap();
    assert!(a.incident_created);
    let b = ingest_alert(
        &ts.state,
        d,
        mk(t0 + 1000, "ST-11", ps.clone(), vec![explorer.clone()]),
    )
    .await
    .unwrap();
    assert_eq!(b.incident_id, a.incident_id);
    let c = ingest_alert(
        &ts.state,
        d,
        mk(t0 + 5000, "ST-04", payload, vec![ps, explorer]),
    )
    .await
    .unwrap();
    assert_eq!(c.incident_id, a.incident_id);
    let (title, rules): (String, Vec<String>) =
        sqlx::query_as("SELECT title, rule_ids FROM incidents WHERE id = $1")
            .bind(a.incident_id)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(rules, vec!["ST-04", "ST-10", "ST-11"]);
    assert!(title.contains("vcredist.exe"), "{title}");
    ts.cleanup().await;
}

fn sample_events(device: Uuid) -> Vec<EventRow> {
    let now = now_ms();
    let evs = [
        Event {
            ts: now - 10_000,
            pid: 100,
            guid: ProcessGuid("p-ps".into()),
            data: EventData::ProcessStart(ProcessStart {
                ppid: 1,
                image: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
                cmdline: "powershell -enc SQBFAFgA".into(),
                user: Some("ACME\\bob".into()),
                signer: Some("Microsoft Windows".into()),
                signed: SignatureState::Valid,
                ..Default::default()
            }),
        },
        Event {
            ts: now - 9_000,
            pid: 100,
            guid: ProcessGuid("p-ps".into()),
            data: EventData::NetConnect {
                proto: NetProto::Tcp,
                dst_ip: "198.51.100.9".into(),
                dst_port: 8545,
                src_port: 1,
                dst_host: None,
                bytes_sent: None,
            },
        },
        Event {
            ts: now - 8_000,
            pid: 200,
            guid: ProcessGuid("p-x".into()),
            data: EventData::ProcessStart(ProcessStart {
                ppid: 1,
                image: r"C:\Users\bob\Downloads\x'; DROP TABLE events; --.exe".into(),
                cmdline: "x".into(),
                ..Default::default()
            }),
        },
        Event {
            ts: now - 7_000,
            pid: 200,
            guid: ProcessGuid("p-x".into()),
            data: EventData::DnsQuery {
                qname: "api.telegram.org".into(),
                answers: vec![],
            },
        },
    ];
    evs.iter()
        .map(|e| EventRow::from_event(device, "HOST-H", e))
        .collect()
}

async fn hunt_checks(mut ts: TestServer) {
    ts.setup_admin().await;
    let d = device(&ts, "HOST-H").await;
    ts.state.events.insert(sample_events(d)).await.unwrap();
    let now = now_ms();
    let q = |query: &str| json!({"query": query, "from": now - 3_600_000, "to": now + 1000, "limit": 100});

    let (s, v) = ts
        .post(
            "/api/hunt",
            q(r#"image ~ "powershell" and cmdline ~ "-enc""#),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(v["items"][0]["hostname"], "HOST-H");
    assert_eq!(v["items"][0]["device_id"], d.to_string());
    assert!(v["elapsed_ms"].is_number());

    let (_, v) = ts
        .post("/api/hunt", q("dst_port > 8000 and dst_port < 9000"))
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(v["items"][0]["dst_ip"], "198.51.100.9");
    assert_eq!(
        v["items"][0]["process_image"],
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );

    let (_, v) = ts
        .post(
            "/api/hunt",
            q("dns_qname = API.TELEGRAM.ORG or signer = 'microsoft windows'"),
        )
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    let (_, v) = ts
        .post(
            "/api/hunt",
            q(&format!("device_id = {d} and event_type = process_start")),
        )
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    let (_, v) = ts.post("/api/hunt", q("user = 'ACME\\\\bob'")).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1, "{v}");

    // Injection attempts: either rejected by the parser or treated as literal values.
    for bad in [
        "1=1",
        "image = 'a' ; DROP TABLE events",
        "raw ~ x",
        "image = x) OR (1=1",
        "dst_port > '1 OR 1=1'",
        "image ~ x union select",
    ] {
        let (s, v) = ts.post("/api/hunt", q(bad)).await;
        assert_eq!(s, 400, "{bad} → {v}");
        assert_eq!(v["error"]["code"], "bad_request");
    }
    for literal in [
        r#"image = "x' OR '1'='1""#,
        r#"cmdline ~ "%' OR 1=1 --""#,
        r#"image ~ "'; DROP TABLE events; --""#,
    ] {
        let (s, v) = ts.post("/api/hunt", q(literal)).await;
        assert_eq!(s, 200, "{literal} → {v}");
        let n = v["items"].as_array().unwrap().len();
        assert!(n <= 1, "{literal} matched {n}");
    }
    // The literal file name containing SQL is matched exactly once, and the table survived.
    let (_, v) = ts
        .post("/api/hunt", q(r#"image ~ "'; DROP TABLE events; --""#))
        .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    let (_, v) = ts.post("/api/hunt", q("")).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 4);

    // Hunting is audited (access to employee telemetry).
    let (_, log) = ts.get("/api/audit-log?action=hunt.").await;
    assert!(log["total"].as_i64().unwrap() >= 10);
    let _: Value = Value::Null;
    ts.cleanup().await;
}

#[tokio::test]
async fn hunt_postgres() {
    let Some(ts) = TestServer::start().await else {
        return;
    };
    assert_eq!(ts.state.events.backend(), "postgres");
    hunt_checks(ts).await;
}

#[tokio::test]
async fn hunt_clickhouse() {
    let Some(ts) = TestServer::start_with(true).await else {
        return;
    };
    assert_eq!(ts.state.events.backend(), "clickhouse");
    hunt_checks(ts).await;
}
