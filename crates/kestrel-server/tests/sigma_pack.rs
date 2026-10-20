//! SigmaHQ Audit pack seeding: inserted at startup with DRL attribution,
//! idempotent, never overrides admin choices, updates unedited rules, removes
//! dropped ones, and bumps the rules version only on change.

mod common;

use common::*;
use kestrel_common::{RuleBundle, RuleMode};
use kestrel_detect::{Engine, HostContext};
use kestrel_server::{crypto::sha256_hex, policy_svc, sigmapack};
use reqwest::Method;
use serde_json::{json, Value};

async fn rules_version(ts: &TestServer) -> i64 {
    let (v,): (i64,) = sqlx::query_as("SELECT rules_version FROM settings WHERE id = 1")
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    v
}

async fn row(ts: &TestServer, id: &str) -> Option<(Value, String, bool)> {
    sqlx::query_as("SELECT meta, source, enabled FROM rules WHERE id = $1")
        .bind(id)
        .fetch_optional(&ts.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn sigma_pack_seeding() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let pack = sigmapack::pack().unwrap();
    let n = pack.rules.len();
    assert_eq!(n, 70);

    // ---- seeded at startup with attribution, Audit, enabled.
    let rows: Vec<(String, Value, bool)> =
        sqlx::query_as("SELECT id, meta, enabled FROM rules WHERE meta->>'license' = 'DRL-1.1'")
            .fetch_all(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(rows.len(), n);
    for (id, meta, enabled) in &rows {
        assert!(enabled, "{id}");
        assert!(id.starts_with("SIG-") && id.len() == 12, "{id}");
        assert_eq!(meta["default_mode"], "audit", "{id}");
        assert_eq!(meta["kind"], "sigma");
        let entry = pack.rules.iter().find(|r| &r.id == id).unwrap();
        assert_eq!(meta["author"], entry.author.as_str(), "{id}");
        assert_eq!(meta["references"][0], entry.upstream.as_str());
        assert!(entry.upstream.contains(&pack.commit));
    }
    let lsass = row(&ts, "SIG-9bd012ee").await.unwrap();
    assert_eq!(lsass.0["category"], "credential_dumping");
    assert!(lsass.0["false_positives"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f.as_str().unwrap().contains("requested")));

    // REST catalog shows them, with the author.
    let (s, list) = ts.get("/api/rules").await;
    assert_eq!(s, 200);
    let vss = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "SIG-c947b146")
        .expect("pack rule in /api/rules");
    assert_eq!(vss["enabled_custom"], true);
    assert_eq!(vss["license"], "DRL-1.1");
    assert!(vss["author"].as_str().unwrap().contains("Florian Roth"));

    // The bundle pushed to agents compiles as a whole.
    let bundle = policy_svc::rules_bundle(&ts.state.db).await.unwrap();
    assert!(bundle.rules.len() >= n);
    Engine::new(HostContext::default(), Default::default(), bundle).unwrap();

    // ---- idempotent: second run changes nothing, no version bump.
    let v0 = rules_version(&ts).await;
    let rep = sigmapack::seed(&ts.state.db).await.unwrap();
    assert_eq!(rep.unchanged, n, "{rep:?}");
    assert!(!rep.rules_version_bumped);
    assert_eq!(rules_version(&ts).await, v0);

    // ---- admin choices survive a re-seed.
    let (s, _) = ts
        .send(
            Method::PATCH,
            "/api/rules/SIG-cc9cbe82",
            json!({"enabled": false}),
        )
        .await;
    assert_eq!(s, 200);
    let (s, _) = ts
        .send(
            Method::PATCH,
            "/api/rules/SIG-c947b146",
            json!({"default_mode": "protect"}),
        )
        .await;
    assert_eq!(s, 200);
    let (s, _) = ts
        .send(Method::DELETE, "/api/rules/SIG-e218595b", json!({}))
        .await;
    assert!(s == 204 || s == 200, "{s}");
    let v1 = rules_version(&ts).await;
    let rep = sigmapack::seed(&ts.state.db).await.unwrap();
    assert!(!rep.rules_version_bumped, "{rep:?}");
    assert_eq!(rep.kept_admin, 1, "deleted rule is respected: {rep:?}");
    assert_eq!(rules_version(&ts).await, v1);
    assert!(!row(&ts, "SIG-cc9cbe82").await.unwrap().2, "stays disabled");
    assert_eq!(
        row(&ts, "SIG-c947b146").await.unwrap().0["default_mode"],
        "protect"
    );
    assert!(row(&ts, "SIG-e218595b").await.is_none(), "not re-created");

    // ---- an unedited rule seeded from an older pack is updated in place,
    // keeping enabled/mode; the version is bumped once.
    let (meta, src, _) = row(&ts, "SIG-c947b146").await.unwrap();
    let old_src = format!("{src}\n# older pack revision\n");
    let mut old_meta = meta.clone();
    old_meta["description"] = "old description".into();
    sqlx::query("UPDATE rules SET source = $2, meta = $3, enabled = false WHERE id = $1")
        .bind("SIG-c947b146")
        .bind(&old_src)
        .bind(&old_meta)
        .execute(&ts.state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE sigma_pack_rules SET source_sha256 = $2 WHERE id = $1")
        .bind("SIG-c947b146")
        .bind(sha256_hex(&old_src))
        .execute(&ts.state.db)
        .await
        .unwrap();
    // ---- an admin-edited rule is left alone.
    let (_, src2, _) = row(&ts, "SIG-1444443e").await.unwrap();
    let edited = src2.replace("level: high", "level: medium");
    assert_ne!(edited, src2);
    sqlx::query("UPDATE rules SET source = $2 WHERE id = $1")
        .bind("SIG-1444443e")
        .bind(&edited)
        .execute(&ts.state.db)
        .await
        .unwrap();
    // ---- a rule dropped from the pack (seeded, unedited) is removed.
    let dropped_src = "title: dropped\nlogsource: {category: process_creation}\ndetection:\n  sel:\n    Image|endswith: '\\x.exe'\n  condition: sel\n";
    let mut dropped_meta = meta.clone();
    dropped_meta["id"] = "SIG-deadbeef".into();
    sqlx::query("INSERT INTO rules (id, kind, meta, source, enabled, created_at, updated_at) VALUES ('SIG-deadbeef','sigma',$1,$2,true,0,0)")
        .bind(&dropped_meta)
        .bind(dropped_src)
        .execute(&ts.state.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sigma_pack_rules (id, sigma_id, source_sha256, pack_commit, seeded_at) VALUES ('SIG-deadbeef','deadbeef-0000-0000-0000-000000000000',$1,'old',0)")
        .bind(sha256_hex(dropped_src))
        .execute(&ts.state.db)
        .await
        .unwrap();

    let v2 = rules_version(&ts).await;
    let rep = sigmapack::seed(&ts.state.db).await.unwrap();
    assert_eq!(rep.updated, 1, "{rep:?}");
    assert_eq!(rep.removed, 1, "{rep:?}");
    assert_eq!(rep.kept_admin, 2, "deleted + edited: {rep:?}");
    assert!(rep.rules_version_bumped);
    assert_eq!(rules_version(&ts).await, v2 + 1);
    let (meta, src, enabled) = row(&ts, "SIG-c947b146").await.unwrap();
    assert_eq!(
        src,
        sigmapack::source_of(
            &pack
                .rules
                .iter()
                .find(|r| r.id == "SIG-c947b146")
                .unwrap()
                .file
        )
        .unwrap()
    );
    assert_ne!(meta["description"], "old description");
    assert_eq!(meta["default_mode"], "protect", "mode kept");
    assert!(!enabled, "enabled flag kept");
    assert_eq!(row(&ts, "SIG-1444443e").await.unwrap().1, edited);
    assert!(row(&ts, "SIG-deadbeef").await.is_none());

    // ---- converged.
    let rep = sigmapack::seed(&ts.state.db).await.unwrap();
    assert!(!rep.rules_version_bumped, "{rep:?}");
    let bundle: RuleBundle = policy_svc::rules_bundle(&ts.state.db).await.unwrap();
    assert!(bundle
        .rules
        .iter()
        .filter(|r| r.meta.license.as_deref() == Some("DRL-1.1"))
        .all(|r| r.meta.author.is_some() && r.meta.default_mode != RuleMode::Off));
    ts.cleanup().await;
}

#[tokio::test]
async fn sigma_pack_adopts_identical_admin_import() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let pack = sigmapack::pack().unwrap();
    let entry = pack.rules.iter().find(|r| r.id == "SIG-646ea171").unwrap();
    let src = sigmapack::source_of(&entry.file).unwrap();
    // Simulate a pre-pack server where the admin imported the same rule.
    sqlx::query("DELETE FROM sigma_pack_rules WHERE id = $1")
        .bind(&entry.id)
        .execute(&ts.state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE rules SET enabled = false WHERE id = $1")
        .bind(&entry.id)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let rep = sigmapack::seed(&ts.state.db).await.unwrap();
    assert_eq!(rep.adopted, 1, "{rep:?}");
    assert!(!rep.rules_version_bumped);
    let (_, s, enabled) = row(&ts, &entry.id).await.unwrap();
    assert_eq!(s, src);
    assert!(!enabled);
    ts.cleanup().await;
}
