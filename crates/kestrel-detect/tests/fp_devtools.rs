//! Owner's PC 2026-10-22 (real install, default policy, ST-04 Protect):
//! Docker Desktop's `com.docker.build.exe` read `.kube\config` (ST-01) and
//! 5.6 s later its parent `com.docker.backend.exe` contacted
//! desktop.docker.com. ST-04 killed the reader, the backend and its whole
//! tree (wslhost, wsl, Docker Desktop) and blocked the CloudFront address
//! for 24 h. Fixed per rule (see `docs/DECISIONS.md`): developer-tool
//! credential stores read by signed Program Files developer tools are Low
//! Audit (ST-04 Audit); a same-vendor Program Files backend that sent for
//! its child is not killed and its destination is not blocked.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

const KUBE: &str = r"C:\Users\azka\.kube\config";
const AWS_CREDS: &str = r"C:\Users\azka\.aws\credentials";
const DOCKER_CFG: &str = r"C:\Users\azka\.docker\config.json";
const BUILD: &str = r"C:\Program Files\Docker\Docker\resources\com.docker.build.exe";
const BACKEND: &str = r"C:\Program Files\Docker\Docker\resources\com.docker.backend.exe";
const DOCKER: Option<&str> = Some("Docker Inc");
const CDN_IP: &str = "3.165.102.21";

fn run_all(name: &str, mode: RuleMode) -> Vec<Output> {
    let mut e = engine(policy_all(mode));
    replay(&mut e, &fixture(name))
}

fn blocks(actions: &[ResponseAction]) -> Vec<(String, Option<String>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::BlockDestination { ip, image, .. } => Some((ip.clone(), image.clone())),
            _ => None,
        })
        .collect()
}

/// `reader` (image, cmdline, signature, signer) reads `store`, then
/// `connector` connects (`"self"` = the reader itself).
fn read_then_send(
    reader: (&str, &str, SignatureState, Option<&str>),
    parent: Option<(&str, &str, SignatureState, Option<&str>)>,
    store: &str,
    sender_is_parent: bool,
) -> Vec<Output> {
    let mut e = engine(policy_all(RuleMode::Protect));
    if let Some((img, cmd, sig, signer)) = parent {
        e.process(&start(0, "parent", 80, img, cmd, None, sig, signer));
    }
    let (img, cmd, sig, signer) = reader;
    e.process(&start(
        1,
        "reader",
        90,
        img,
        cmd,
        parent.map(|_| ("parent", 80)),
        sig,
        signer,
    ));
    let mut out = e.process(&read(10, "reader", 90, store));
    if sender_is_parent {
        out.extend(e.process(&connect(5_600, "parent", 80, CDN_IP, 443)));
    } else {
        out.extend(e.process(&connect(5_600, "reader", 90, CDN_IP, 443)));
    }
    out
}

/// Every destination block (the ST-04 block and the port-specific one from
/// the suspend-window escalation) has exactly this ip and scope.
fn assert_blocks(b: &[(String, Option<String>)], want: (String, Option<String>), out: &[Output]) {
    assert!(!b.is_empty(), "{}", dump(out));
    assert!(b.iter().all(|x| *x == want), "{}", dump(out));
}

fn assert_full_st04(out: &[Output], reader: &str) {
    assert!(
        rule_ids(out).contains(&"ST-04".to_string()),
        "no ST-04: {}",
        dump(out)
    );
    let st04 = first(out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(out));
    assert!(
        kills(&st04.actions).contains(&(reader.to_string(), true)),
        "{}",
        dump(out)
    );
    assert!(!blocks(&st04.actions).is_empty(), "{}", dump(out));
}

// ------------------------------------------------- the lab event, verbatim

#[test]
fn docker_desktop_kubeconfig_then_backend_send_is_audit_only() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("lab_docker_desktop_kubeconfig.jsonl", mode);
        let st01 = first(&out, "ST-01");
        assert_eq!(st01.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st01.alert.mode, RuleMode::Audit);
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.mode, RuleMode::Audit, "{}", dump(&out));
        for d in alerts(&out) {
            assert!(d.actions.is_empty(), "{mode:?}: {}", dump(&out));
        }
        assert!(standalone(&out).is_empty(), "{mode:?}: {}", dump(&out));
    }
}

// ---------------------------------------------------- dev-tool reader scope

#[test]
fn signed_program_files_dev_tools_reading_dev_stores_are_audit() {
    for (img, cmd, signer, store) in [
        (
            BUILD,
            "com.docker.build.exe --log-no-timestamp",
            DOCKER,
            KUBE,
        ),
        (
            r"C:\Program Files\JetBrains\IntelliJ IDEA 2025.2\bin\idea64.exe",
            "idea64.exe",
            Some("JetBrains s.r.o."),
            DOCKER_CFG,
        ),
        (
            r"C:\Program Files\Rancher Desktop\resources\resources\win32\bin\rdctl.exe",
            "rdctl.exe list-settings",
            Some("SUSE LLC"),
            KUBE,
        ),
        (
            r"C:\Program Files\WindowsApps\Some.DevTool_1.0.0.0_x64__abc\devtool.exe",
            "devtool.exe",
            Some("Some Vendor Inc"),
            AWS_CREDS,
        ),
    ] {
        let out = read_then_send(
            (img, cmd, SignatureState::Valid, signer),
            None,
            store,
            false,
        );
        assert_eq!(
            first(&out, "ST-01").alert.severity,
            Severity::Low,
            "{img}: {}",
            dump(&out)
        );
        assert_eq!(first(&out, "ST-04").alert.mode, RuleMode::Audit, "{img}");
        for d in alerts(&out) {
            assert!(d.actions.is_empty(), "{img}: {}", dump(&out));
        }
        assert!(standalone(&out).is_empty(), "{img}: {}", dump(&out));
    }
}

/// Positive: an unsigned binary in Temp reading kubeconfig and connecting is
/// killed and the destination is blocked host-wide.
#[test]
fn unsigned_temp_reader_of_kubeconfig_is_killed_and_blocked() {
    let out = read_then_send(
        (
            r"C:\Users\x\AppData\Local\Temp\k.exe",
            "k.exe",
            SignatureState::Unsigned,
            None,
        ),
        None,
        r"C:\Users\x\.kube\config",
        false,
    );
    assert_ne!(first(&out, "ST-01").alert.severity, Severity::Low);
    assert_full_st04(&out, "reader");
    assert_blocks(
        &blocks(&first(&out, "ST-04").actions),
        (CDN_IP.to_string(), None),
        &out,
    );
}

/// Positive: a validly signed python.exe under Program Files reading the
/// AWS credentials and posting is a script host, not a developer tool: full
/// ST-01 and ST-04 (no longer a silent "owner" by file name).
#[test]
fn signed_python_reading_aws_credentials_then_posting_is_full_response() {
    for img in [
        r"C:\Program Files\Python312\python.exe",
        r"C:\Program Files\Python312\pythonw.exe",
        r"C:\Program Files\Python313\python3.13.exe",
    ] {
        let out = read_then_send(
            (
                img,
                "python.exe upload.py",
                SignatureState::Valid,
                Some("Python Software Foundation"),
            ),
            None,
            AWS_CREDS,
            false,
        );
        assert_ne!(first(&out, "ST-01").alert.severity, Severity::Low, "{img}");
        assert_full_st04(&out, "reader");
        // Signed Program Files sender: the block is scoped to its image.
        assert_blocks(
            &blocks(&first(&out, "ST-04").actions),
            (CDN_IP.to_string(), Some(img.to_string())),
            &out,
        );
    }
}

/// The dev-tool path stays narrow: per-user installs, interpreters, script /
/// inspector arguments, Electron hosts with a positional argument, invalid
/// signatures and non-dev stores all keep the full ST-04 response.
#[test]
fn dev_tool_reader_is_narrow() {
    let cases: &[(&str, &str, SignatureState, Option<&str>, &str)] = &[
        // per-user install (user-writable)
        (
            r"C:\Users\azka\AppData\Local\Programs\kubetool\kubetool.exe",
            "kubetool.exe",
            SignatureState::Valid,
            Some("Mirantis, Inc."),
            KUBE,
        ),
        // interpreters / script hosts, even signed in Program Files
        (
            r"C:\Program Files\nodejs\node.exe",
            "node.exe x",
            SignatureState::Valid,
            Some("OpenJS Foundation"),
            KUBE,
        ),
        (
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            "pwsh.exe",
            SignatureState::Valid,
            Some("Microsoft Corporation"),
            KUBE,
        ),
        (
            r"C:\Program Files\Java\jdk-21\bin\javaw.exe",
            "javaw.exe -jar x.jar",
            SignatureState::Valid,
            Some("Oracle America, Inc."),
            KUBE,
        ),
        (
            r"C:\Program Files\Ruby33-x64\bin\ruby.exe",
            "ruby.exe x.rb",
            SignatureState::Valid,
            Some("Some Vendor"),
            DOCKER_CFG,
        ),
        // LOLBin
        (
            r"C:\Program Files\x\rundll32.exe",
            "rundll32.exe x.dll,y",
            SignatureState::Valid,
            Some("Microsoft Windows"),
            KUBE,
        ),
        // Electron host running a script / with a positional argument
        // (Docker Desktop.exe itself is a kubeconfig owner by name)
        (
            r"C:\Program Files\Postman\Postman.exe",
            r#""Postman.exe" C:\Users\azka\x.js"#,
            SignatureState::Valid,
            Some("Postman, Inc."),
            KUBE,
        ),
        (
            r"C:\Program Files\Postman\Postman.exe",
            r#""Postman.exe" payload"#,
            SignatureState::Valid,
            Some("Postman, Inc."),
            KUBE,
        ),
        // inspector / eval
        (
            BUILD,
            "com.docker.build.exe --inspect=9229",
            SignatureState::Valid,
            DOCKER,
            KUBE,
        ),
        (
            BUILD,
            "com.docker.build.exe -e x",
            SignatureState::Valid,
            DOCKER,
            KUBE,
        ),
        // invalid / unsigned / no signer
        (
            BUILD,
            "com.docker.build.exe",
            SignatureState::Invalid,
            DOCKER,
            KUBE,
        ),
        (
            BUILD,
            "com.docker.build.exe",
            SignatureState::Unsigned,
            None,
            KUBE,
        ),
        (
            BUILD,
            "com.docker.build.exe",
            SignatureState::Valid,
            None,
            KUBE,
        ),
        // another drive's "Program Files"
        (
            r"D:\Program Files\Docker\Docker\resources\com.docker.build.exe",
            "com.docker.build.exe",
            SignatureState::Valid,
            DOCKER,
            KUBE,
        ),
        // a browser store is never a developer-tool store
        (
            BUILD,
            "com.docker.build.exe",
            SignatureState::Valid,
            DOCKER,
            CHROME_LOGIN,
        ),
    ];
    for (img, cmd, sig, signer, store) in cases {
        let out = read_then_send((img, cmd, *sig, *signer), None, store, false);
        assert_full_st04(&out, "reader");
        assert_ne!(
            first(&out, "ST-01").alert.severity,
            Severity::Low,
            "{img} {cmd}: {}",
            dump(&out)
        );
    }
}

/// An injected developer tool is not a developer tool any more.
#[test]
fn tampered_dev_tool_is_full_response() {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "inj",
        71,
        r"C:\Users\azka\AppData\Local\Temp\inj.exe",
        "inj.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        1,
        "reader",
        90,
        BUILD,
        "com.docker.build.exe",
        None,
        SignatureState::Valid,
        DOCKER,
    ));
    e.process(&ev(
        5,
        "inj",
        71,
        EventData::RemoteThread(TargetProcess {
            target_pid: 90,
            target_guid: Some(g("reader")),
            target_image: BUILD.into(),
            ..Default::default()
        }),
    ));
    let mut out = e.process(&read(10, "reader", 90, KUBE));
    out.extend(e.process(&connect(5_600, "reader", 90, CDN_IP, 443)));
    assert_ne!(first(&out, "ST-01").alert.severity, Severity::Low);
    assert_full_st04(&out, "reader");
}

/// After a non-dev store read (here a browser store), the same process gets
/// the full ST-04 response even if it had read kubeconfig first.
#[test]
fn dev_tool_that_also_reads_a_browser_store_is_full_response() {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        1,
        "reader",
        90,
        BUILD,
        "com.docker.build.exe",
        None,
        SignatureState::Valid,
        DOCKER,
    ));
    e.process(&read(10, "reader", 90, KUBE));
    e.process(&read(20, "reader", 90, CHROME_COOKIES));
    let out = e.process(&connect(5_600, "reader", 90, CDN_IP, 443));
    assert_full_st04(&out, "reader");
}

// --------------------------------------------- ST-04 "parent sent" scope

const BACKEND_CMD: &str =
    r#""C:\Program Files\Docker\Docker\resources\com.docker.backend.exe" run"#;

/// A non-exempt read (a browser store) by a Docker-signed child whose parent
/// is Docker's own signed Program Files backend: only the reader is killed;
/// the backend and its tree survive and the destination is not blocked.
#[test]
fn same_vendor_backend_parent_is_not_killed_or_blocked() {
    let out = read_then_send(
        (BUILD, "com.docker.build.exe", SignatureState::Valid, DOCKER),
        Some((BACKEND, BACKEND_CMD, SignatureState::Valid, DOCKER)),
        CHROME_LOGIN,
        true,
    );
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(&out));
    assert_eq!(
        kills(&st04.actions),
        [("reader".to_string(), true)],
        "{}",
        dump(&out)
    );
    assert!(blocks(&st04.actions).is_empty(), "{}", dump(&out));
    for a in standalone(&out) {
        assert!(
            !matches!(a, ResponseAction::BlockDestination { .. }),
            "{}",
            dump(&out)
        );
        if let ResponseAction::KillProcess { guid, .. } = a {
            assert_ne!(guid.as_ref().map(|g| g.0.as_str()), Some("parent"));
        }
    }
}

/// Positive: the parent that sent is unsigned, user-writable, a script host
/// or signed by someone else: it is still killed with its tree.
#[test]
fn parent_sender_outside_the_vendor_backend_rule_is_still_killed() {
    for parent in [
        (
            r"C:\Users\azka\AppData\Local\Temp\com.docker.backend.exe",
            "com.docker.backend.exe",
            SignatureState::Unsigned,
            None,
        ),
        (
            r"C:\Users\azka\AppData\Local\Programs\Docker\com.docker.backend.exe",
            "com.docker.backend.exe",
            SignatureState::Valid,
            DOCKER,
        ),
        (
            r"C:\Program Files\nodejs\node.exe",
            "node.exe x.js",
            SignatureState::Valid,
            DOCKER,
        ),
        (
            BACKEND,
            BACKEND_CMD,
            SignatureState::Valid,
            Some("Other Vendor Ltd"),
        ),
        (BACKEND, BACKEND_CMD, SignatureState::Invalid, DOCKER),
    ] {
        let out = read_then_send(
            (BUILD, "com.docker.build.exe", SignatureState::Valid, DOCKER),
            Some(parent),
            CHROME_LOGIN,
            true,
        );
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(&out));
        let k = kills(&st04.actions);
        assert!(k.contains(&("reader".to_string(), true)), "{}", dump(&out));
        assert!(
            k.contains(&("parent".to_string(), true)),
            "{:?}: {}",
            parent,
            dump(&out)
        );
        assert!(!blocks(&st04.actions).is_empty(), "{}", dump(&out));
    }
}

/// Positive: a Docker-signed child whose parent (the sender) is an unsigned
/// Temp binary. The child read kubeconfig and a browser store, so ST-04 is
/// a full response and the parent is killed with its tree; the block is
/// host-wide because the sender is unsigned.
#[test]
fn docker_signed_child_with_unsigned_parent_kills_the_parent() {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "parent",
        80,
        r"C:\Users\azka\AppData\Local\Temp\loader.exe",
        "loader.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        1,
        "reader",
        90,
        BUILD,
        "com.docker.build.exe",
        Some(("parent", 80)),
        SignatureState::Valid,
        DOCKER,
    ));
    e.process(&read(10, "reader", 90, KUBE));
    e.process(&read(20, "reader", 90, CHROME_COOKIES));
    let out = e.process(&connect(5_600, "parent", 80, CDN_IP, 443));
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(&out));
    let k = kills(&st04.actions);
    assert!(k.contains(&("reader".to_string(), true)), "{}", dump(&out));
    assert!(k.contains(&("parent".to_string(), true)), "{}", dump(&out));
    assert_blocks(&blocks(&st04.actions), (CDN_IP.to_string(), None), &out);
}

// ------------------- ST-04 destination-aware for one provider's own stores

const PYTHON: &str = r"C:\Program Files\Python312\python.exe";
const PSF: Option<&str> = Some("Python Software Foundation");
const AZ_CACHE: &str = r"C:\Users\azka\.azure\msal_token_cache.json";
const GCLOUD_CREDS: &str =
    r"C:\Users\azka\AppData\Roaming\gcloud\application_default_credentials.json";

fn connect_host(ts: i64, guid: &str, pid: u32, ip: &str, host: Option<&str>) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::NetConnect {
            proto: NetProto::Tcp,
            dst_ip: ip.into(),
            dst_port: 443,
            src_port: 50123,
            dst_host: host.map(Into::into),
            bytes_sent: None,
        },
    )
}

/// `image` (signature, signer) reads `stores`, then connects to `ip` / `host`.
fn reads_then_host(
    image: &str,
    cmdline: &str,
    sig: SignatureState,
    signer: Option<&str>,
    stores: &[&str],
    ip: &str,
    host: Option<&str>,
) -> Vec<Output> {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(1, "reader", 90, image, cmdline, None, sig, signer));
    let mut out = Vec::new();
    for (i, s) in stores.iter().enumerate() {
        out.extend(e.process(&read(10 + i as i64, "reader", 90, s)));
    }
    out.extend(e.process(&connect_host(5_600, "reader", 90, ip, host)));
    out
}

fn assert_no_kill_or_block(out: &[Output]) {
    let bad = |a: &ResponseAction| {
        matches!(
            a,
            ResponseAction::KillProcess { .. }
                | ResponseAction::BlockDestination { .. }
                | ResponseAction::QuarantineFile { .. }
        )
    };
    for d in alerts(out) {
        assert!(!d.actions.iter().any(bad), "{}", dump(out));
    }
    assert!(!standalone(out).into_iter().any(bad), "{}", dump(out));
}

fn assert_provider_audit(out: &[Output], provider: &str, host: &str) {
    let st04 = first(out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Audit, "{}", dump(out));
    assert_eq!(st04.alert.severity, Severity::High, "{}", dump(out));
    assert!(st04.actions.is_empty(), "{}", dump(out));
    let s = &st04.alert.summary;
    assert!(
        s.contains(&format!("{provider} ({host})")) && s.contains("review"),
        "{s}"
    );
    assert_no_kill_or_block(out);
}

/// boto3 style: signed python reads the AWS credentials and calls S3 (and
/// other AWS endpoints, any case, trailing dot): High Audit, no kill.
#[test]
fn python_aws_credentials_then_aws_endpoint_is_high_audit() {
    for host in [
        "s3.ap-southeast-1.amazonaws.com",
        "STS.AMAZONAWS.COM.",
        "portal.sso.ap-southeast-1.amazonaws.com",
        "signin.aws.amazon.com",
        "s3.cn-north-1.amazonaws.com.cn",
    ] {
        let out = reads_then_host(
            PYTHON,
            "python.exe sync.py",
            SignatureState::Valid,
            PSF,
            &[AWS_CREDS],
            "52.219.36.10",
            Some(host),
        );
        let want = host.to_ascii_lowercase();
        assert_provider_audit(&out, "AWS", want.trim_end_matches('.'));
        // The read itself is still an ST-01 (not silent, not Low).
        assert_ne!(first(&out, "ST-01").alert.severity, Severity::Low);
    }
    // The name the engine correlated from DNS counts the same way.
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        1,
        "reader",
        90,
        PYTHON,
        "python.exe x.py",
        None,
        SignatureState::Valid,
        PSF,
    ));
    e.process(&read(10, "reader", 90, AWS_CREDS));
    e.process(&ev(
        20,
        "reader",
        90,
        EventData::DnsQuery {
            qname: "s3.ap-southeast-1.amazonaws.com".into(),
            answers: vec!["52.219.36.10".into()],
        },
    ));
    let out = e.process(&connect(5_600, "reader", 90, "52.219.36.10", 443));
    assert_provider_audit(&out, "AWS", "s3.ap-southeast-1.amazonaws.com");
    // A later send of the same process to anywhere else is the full ST-04,
    // with its own alert (not swallowed by the provider alert's dedup).
    let out = e.process(&connect_host(
        6_000,
        "reader",
        90,
        "149.154.167.220",
        Some("api.telegram.org"),
    ));
    assert_full_st04(&out, "reader");
}

/// Python sending elsewhere after reading AWS credentials: Telegram,
/// Discord, a paste site, a raw IP with or without a name, look-alike
/// names, another provider.
#[test]
fn python_aws_credentials_then_elsewhere_is_full_response() {
    for (ip, host) in [
        ("149.154.167.220", Some("api.telegram.org")),
        ("162.159.135.232", Some("discord.com")),
        ("104.20.10.10", Some("pastebin.com")),
        ("45.61.136.10", None),
        ("45.61.136.10", Some("45.61.136.10")),
        ("45.61.136.10", Some("amazonaws.com.evil.net")),
        ("45.61.136.10", Some("evilamazonaws.com")),
        ("20.190.151.1", Some("login.microsoftonline.com")),
    ] {
        let out = reads_then_host(
            PYTHON,
            "python.exe x.py",
            SignatureState::Valid,
            PSF,
            &[AWS_CREDS],
            ip,
            host,
        );
        assert_full_st04(&out, "reader");
    }
}

/// Unsigned readers (and readers in Temp / Downloads) never get the
/// allowance, even towards the provider's endpoint.
#[test]
fn unsigned_or_temp_reader_to_provider_is_still_killed() {
    for (img, sig, signer) in [
        (
            r"C:\Users\x\AppData\Local\Temp\k.exe",
            SignatureState::Unsigned,
            None,
        ),
        (
            r"C:\Users\x\AppData\Local\Programs\x\x.exe",
            SignatureState::Unsigned,
            None,
        ),
        (
            r"C:\Users\x\Downloads\python.exe",
            SignatureState::Valid,
            PSF,
        ),
        (PYTHON, SignatureState::Invalid, PSF),
    ] {
        let out = reads_then_host(
            img,
            "x.exe",
            sig,
            signer,
            &[AWS_CREDS],
            "52.219.36.10",
            Some("s3.amazonaws.com"),
        );
        assert_full_st04(&out, "reader");
    }
}

/// The allowance needs every credential read to be one provider's store:
/// AWS + a browser store, AWS + Azure, kubeconfig (no provider) all keep
/// the full response.
#[test]
fn provider_allowance_needs_one_provider_only() {
    for (stores, host) in [
        (&[AWS_CREDS, CHROME_COOKIES][..], "s3.amazonaws.com"),
        (&[AWS_CREDS, AZ_CACHE][..], "s3.amazonaws.com"),
        (&[AWS_CREDS, AZ_CACHE][..], "management.azure.com"),
        (&[KUBE][..], "s3.amazonaws.com"),
        (&[KUBE][..], "kubernetes.docker.internal"),
    ] {
        let out = reads_then_host(
            PYTHON,
            "python.exe x.py",
            SignatureState::Valid,
            PSF,
            stores,
            "52.219.36.10",
            Some(host),
        );
        assert_full_st04(&out, "reader");
    }
    // Two AWS stores are still one provider.
    let out = reads_then_host(
        PYTHON,
        "python.exe x.py",
        SignatureState::Valid,
        PSF,
        &[AWS_CREDS, r"C:\Users\azka\.aws\sso\cache\abc.json"],
        "52.219.36.10",
        Some("sts.amazonaws.com"),
    );
    assert_provider_audit(&out, "AWS", "sts.amazonaws.com");
}

/// Python reading the Azure CLI / gcloud / Docker stores is not a silent
/// owner; towards the provider it is High Audit, elsewhere the full response.
#[test]
fn generic_python_on_azure_gcloud_docker_stores_is_destination_aware() {
    for (store, ip, host, provider) in [
        (
            AZ_CACHE,
            "20.190.151.1",
            "login.microsoftonline.com",
            "Azure",
        ),
        (AZ_CACHE, "20.37.158.0", "myvault.vault.azure.net", "Azure"),
        (
            GCLOUD_CREDS,
            "142.250.4.95",
            "oauth2.googleapis.com",
            "Google Cloud",
        ),
        (
            DOCKER_CFG,
            "44.208.254.194",
            "registry-1.docker.io",
            "Docker",
        ),
    ] {
        let out = reads_then_host(
            PYTHON,
            "python.exe x.py",
            SignatureState::Valid,
            PSF,
            &[store],
            ip,
            Some(host),
        );
        assert_provider_audit(&out, provider, host);
    }
    for store in [AZ_CACHE, GCLOUD_CREDS, DOCKER_CFG] {
        let out = reads_then_host(
            PYTHON,
            "python.exe x.py",
            SignatureState::Valid,
            PSF,
            &[store],
            "149.154.167.220",
            Some("api.telegram.org"),
        );
        assert_full_st04(&out, "reader");
    }
}

/// The official CLI layouts' bundled interpreters own their CLI's store:
/// no alert at all. The same interpreter running another script, `-c`,
/// another module, another store, unsigned or a copy elsewhere is not.
#[test]
fn official_cli_bundled_python_owns_its_store() {
    let az_py = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe";
    let az_cmd =
        r#""C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe" -IBm azure.cli account show"#;
    let az86_py = r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\python.exe";
    let gc_py = r"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\platform\bundledpython\python.exe";
    let gc_cmd = r#""C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\platform\bundledpython\python.exe" -S "C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\..\lib\gcloud.py" auth list"#;
    for (img, cmd, store, ip, host) in [
        (
            az_py,
            az_cmd,
            AZ_CACHE,
            "20.190.151.1",
            "login.microsoftonline.com",
        ),
        (
            az86_py,
            r#""C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\python.exe" -m azure.cli login"#,
            AZ_CACHE,
            "20.190.151.1",
            "login.microsoftonline.com",
        ),
        (
            gc_py,
            gc_cmd,
            GCLOUD_CREDS,
            "142.250.4.95",
            "oauth2.googleapis.com",
        ),
    ] {
        let out = reads_then_host(
            img,
            cmd,
            SignatureState::Valid,
            PSF,
            &[store],
            ip,
            Some(host),
        );
        assert!(out.is_empty(), "{cmd}: {}", dump(&out));
    }
    for (img, cmd, sig, store) in [
        (
            az_py,
            r#""python.exe" evil.py"#,
            SignatureState::Valid,
            AZ_CACHE,
        ),
        (
            az_py,
            r#""python.exe" -c "import x" azure.cli"#,
            SignatureState::Valid,
            AZ_CACHE,
        ),
        (
            az_py,
            r#""python.exe" -cm azure.cli"#,
            SignatureState::Valid,
            AZ_CACHE,
        ),
        (
            az_py,
            r#""python.exe" -m azure.cli.evil"#,
            SignatureState::Valid,
            AZ_CACHE,
        ),
        (az_py, az_cmd, SignatureState::Valid, AWS_CREDS),
        (az_py, az_cmd, SignatureState::Unsigned, AZ_CACHE),
        (
            r"C:\Users\azka\AppData\Local\Microsoft SDKs\Azure\CLI2\python.exe",
            az_cmd,
            SignatureState::Valid,
            AZ_CACHE,
        ),
        (
            gc_py,
            r#""python.exe" evil.py"#,
            SignatureState::Valid,
            GCLOUD_CREDS,
        ),
        (
            gc_py,
            r#""python.exe" C:\Users\azka\lib\gcloud.py"#,
            SignatureState::Valid,
            GCLOUD_CREDS,
        ),
        (
            gc_py,
            r#""python.exe" D:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\lib\gcloud.py"#,
            SignatureState::Valid,
            GCLOUD_CREDS,
        ),
        (gc_py, gc_cmd, SignatureState::Valid, AZ_CACHE),
    ] {
        let out = reads_then_host(img, cmd, sig, PSF, &[store], "45.61.136.10", None);
        assert_full_st04(&out, "reader");
    }
}
