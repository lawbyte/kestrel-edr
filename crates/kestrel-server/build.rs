fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/kestrel.proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        // The rpc named `Connect` clashes with the generated `connect(dst)` constructor.
        .build_transport(false)
        .compile_protos(&["../../proto/kestrel.proto"], &["../../proto"])?;
    Ok(())
}
