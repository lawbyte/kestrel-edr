//! The owner's offline release-signing commands (`update-keygen`,
//! `update-sign`) produce a manifest the agent's verifier accepts.

use kestrel_common::wire::UpdateManifest;
use std::process::Command;

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kestrel-agent"))
}

#[test]
fn keygen_then_sign_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let out = agent()
        .args(["update-keygen", "--out"])
        .arg(&keys)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let public_key = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let key_file = keys.join(kestrel_agent::update::KEY_FILE);
    assert!(key_file.is_file());
    // The private key is never printed.
    let secret = std::fs::read_to_string(&key_file).unwrap();
    let secret_line = secret.lines().last().unwrap();
    assert!(!String::from_utf8_lossy(&out.stderr).contains(secret_line));

    // A second keygen into the same directory is refused.
    let again = agent()
        .args(["update-keygen", "--out"])
        .arg(&keys)
        .output()
        .unwrap();
    assert!(!again.status.success());

    let msi = dir.path().join("KestrelAgent-9.9.9.msi");
    std::fs::write(&msi, vec![0x42u8; 100_000]).unwrap();
    let url = "https://kestrel.acme.sg:8443/downloads/updates/KestrelAgent-9.9.9.msi";
    let out = agent()
        .args(["update-sign", "--key"])
        .arg(&key_file)
        .args(["--version", "9.9.9", "--url", url, "--file"])
        .arg(&msi)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let m: UpdateManifest = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m.version, "9.9.9");
    assert_eq!(m.url, url);
    assert_eq!(m.sha256, kestrel_agent::update::sha256_file(&msi).unwrap());
    let vk = kestrel_agent::update::verifying_key(Some(&public_key)).unwrap();
    kestrel_agent::update::verify_manifest(&vk, &m).unwrap();

    // Non-https URLs are refused by the signing tool.
    let bad = agent()
        .args(["update-sign", "--key"])
        .arg(&key_file)
        .args(["--version", "9.9.9", "--url", "http://x/y.msi", "--file"])
        .arg(&msi)
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
