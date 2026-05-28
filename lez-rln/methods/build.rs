use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};

fn main() {
    let docker = DockerOptionsBuilder::default()
        .root_dir("../..")
        .build()
        .unwrap();
    let opts = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .unwrap();
    let mut map = HashMap::new();
    map.insert("logos_lez_rln_guest", opts);
    risc0_build::embed_methods_with_options(map);

    // Post-build: strip non-loadable sections (symtab/strtab/eh_frame/etc.)
    // from the user ELF inside each R0BF .bin so the deploy tx fits under the
    // testnet's 511,800-byte per-tx cap. The on-chain image_id changes (the
    // ELF header bytes are part of the first PT_LOAD segment), but the lez-rln
    // host reads the .bin file fresh at runtime via `Program::new`, so the
    // expected program ID matches the deployed bytecode automatically.
    let strip = locate_llvm_strip()
        .expect("llvm-strip not found under ~/.risc0/toolchains/*/lib/rustlib/*/bin/");

    let bin_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("riscv-guest")
        .join("logos_lez_rln_methods")
        .join("logos_lez_rln_guest")
        .join("riscv32im-risc0-zkvm-elf")
        .join("docker");

    for name in ["rln_registration.bin", "incremental_merkle_tree.bin"] {
        let path = bin_dir.join(name);
        if path.exists() {
            strip_program_binary_user_elf(&path, &strip);
        }
    }
}

/// Find `llvm-strip` shipped with the risc0 rust toolchain. Search order:
/// 1. `$RISC0_LLVM_STRIP` if explicitly set.
/// 2. `~/.risc0/toolchains/v*-rust-*/lib/rustlib/<host-triple>/bin/llvm-strip`.
fn locate_llvm_strip() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("RISC0_LLVM_STRIP") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let host = std::env::var("HOST").ok()?;
    let toolchains = PathBuf::from(home).join(".risc0").join("toolchains");
    let entries = std::fs::read_dir(&toolchains).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with('v') || !name.contains("-rust-") {
            continue;
        }
        let candidate = entry
            .path()
            .join("lib")
            .join("rustlib")
            .join(&host)
            .join("bin")
            .join("llvm-strip");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Strip the user ELF inside a risc0 `R0BF` binary in place. Format is:
/// `b"R0BF" | u32 version | u32 header_len | header | u32 user_len | user_elf | kernel_elf`.
/// We unpack the user ELF, run `llvm-strip --strip-all` on it, and re-pack.
fn strip_program_binary_user_elf(path: &Path, strip: &Path) {
    let blob = std::fs::read(path).expect("read program binary");
    let mut cur = 0usize;
    let read_u32 = |b: &[u8], off: usize| -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    };

    assert_eq!(&blob[cur..cur + 4], b"R0BF", "expected R0BF magic in {path:?}");
    cur += 4;
    let _ver = read_u32(&blob, cur);
    cur += 4;
    let header_len = read_u32(&blob, cur) as usize;
    cur += 4;
    let header_end = cur + header_len;
    let header = &blob[cur..header_end];
    cur = header_end;
    let user_len = read_u32(&blob, cur) as usize;
    cur += 4;
    let user_elf = &blob[cur..cur + user_len];
    cur += user_len;
    let kernel_elf = &blob[cur..];

    let tmp = path.with_extension("user.elf.tmp");
    std::fs::write(&tmp, user_elf).expect("write tmp elf");
    let status = Command::new(strip)
        .args(["--strip-all", tmp.to_str().unwrap()])
        .status()
        .expect("invoke llvm-strip");
    assert!(status.success(), "llvm-strip failed on {tmp:?}");
    let stripped = std::fs::read(&tmp).expect("read stripped elf");
    std::fs::remove_file(&tmp).ok();

    let mut out: Vec<u8> = Vec::with_capacity(blob.len());
    out.extend_from_slice(b"R0BF");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header_len as u32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(&(stripped.len() as u32).to_le_bytes());
    out.extend_from_slice(&stripped);
    out.extend_from_slice(kernel_elf);
    std::fs::write(path, &out).expect("write stripped binary");
    println!(
        "cargo:warning=stripped {} : {} -> {} B",
        path.file_name().unwrap().to_string_lossy(),
        blob.len(),
        out.len(),
    );
}
