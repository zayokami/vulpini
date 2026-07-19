fn main() -> std::io::Result<()> {
    // No system protoc required: use the vendored prebuilt binary.
    // Safe here: the build script is single-threaded at this point.
    unsafe {
        std::env::set_var(
            "PROTOC",
            protoc_bin_vendored::protoc_bin_path().expect("vendored protoc"),
        );
    }
    prost_build::Config::new().compile_protos(&["proto/geo.proto"], &["proto/"])?;
    println!("cargo:rerun-if-changed=proto/geo.proto");
    Ok(())
}
