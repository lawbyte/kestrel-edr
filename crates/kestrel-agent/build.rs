fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Prefer an explicit PROTOC; otherwise use the vendored binary so the
    // build doesn't depend on a system protoc.
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(p) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", p);
        }
    }
    let proto_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let proto = proto_dir.join("kestrel.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    println!("cargo:rerun-if-env-changed=KESTREL_UPDATE_PUBKEY");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        // The `Connect` rpc would generate `connect()` and clash with the
        // transport constructor `Client::connect(dst)`; we build clients with `new(channel)`.
        .build_transport(false)
        .compile_protos(&[proto], &[proto_dir])?;
    Ok(())
}
