fn main() {
    // Consumers that use this crate as an rlib (e.g. the Rust module port,
    // which stages a copy of this crate inside its nix sandbox) never need
    // the C header, and cbindgen would try to write into a read-only staged
    // source tree there. Env-gated skip; default behavior is unchanged.
    if std::env::var("LEZ_RLN_FFI_SKIP_CBINDGEN").is_ok() {
        return;
    }

    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let config =
        cbindgen::Config::from_file("cbindgen.toml").expect("Unable to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("lez_rln_ffi.h");
}
