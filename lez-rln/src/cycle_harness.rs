//! Guest cycle-count measurement harness.
//!
//! Measures the RV32IM user-cycle cost of the merkle program's Initialize and
//! Insert paths — the two operations that press against the per-execution
//! session limit the sequencer enforces on every public transaction
//! (`MAX_NUM_CYCLES_PUBLIC_EXECUTION = 1 << 25`, lee `state_machine`
//! `program/mod.rs`). Provisioning drives one Initialize; every register and
//! renewal drives one merkle Insert. Both were previously unmeasured — the
//! "any opt-level/lto/strip change blows the cycle cap" note in
//! `methods/guest/Cargo.toml` was folklore with no number behind it. Freezing
//! these under an explicit budget turns that into an enforced invariant, so a
//! codegen change (profile flag, precompile swap, dependency bump) that
//! inflates cycles fails here instead of silently dropping deploys on testnet.
//!
//! Run:
//! ```bash
//! RISC0_DEV_MODE=1 cargo test -p logos-lez-rln --features rc5-state-tests \
//!   cycle_harness -- --nocapture
//! ```
//! `execute()` never proves, so dev mode is optional; it only speeds the run.
//! The `.bin`s must exist first (`cargo risczero build --manifest-path
//! methods/guest/Cargo.toml`); if they are absent the tests skip.

#[cfg(all(test, feature = "rc5-state-tests"))]
mod tests {
    use std::{fs, path::PathBuf};

    use nssa::program::Program;
    use nssa_core::{
        account::{Account, AccountWithMetadata},
        program::ProgramOutput,
    };
    use risc0_zkvm::{ExecutorEnv, default_executor};

    use crate::rln::{derive_config_account, derive_subtree_account};

    /// risc0's per-execution session limit. Still the ceiling a single guest
    /// may not cross, but no longer the binding one — see `MAX_GAS_EXEC`.
    const SESSION_LIMIT: u64 = 1 << 25; // 33,554,432

    /// What actually rejects a transaction (`fee_core::market::MAX_GAS_EXEC`).
    ///
    /// v0.2.5 meters a charged transaction by its declared `gas_limit` at one
    /// gas per cycle and refuses to include one that declares more than this,
    /// in any block. It is a *transaction* budget, so it covers every guest in
    /// a chained call together — which is why the number that decides the tree
    /// depth is measured in `state_tests`, over a whole register transaction,
    /// not here over one guest.
    const MAX_GAS_EXEC: u64 = 10_000_000;

    /// Early-warning budget, deliberately below `MAX_GAS_EXEC` so a regression
    /// that inflates cycles is caught with margin to react, rather than when
    /// transactions start being refused.
    const CYCLE_BUDGET: u64 = 9_000_000;

    /// Arbitrary tree id — the merkle guest reads its pre-states positionally
    /// and never checks account ids, so this only needs to be stable.
    const TREE_ID: [u8; 32] = [7u8; 32];

    fn merkle_binary_path() -> PathBuf {
        let dir = match std::env::var_os("LEZ_RLN_GUEST_DIR") {
            Some(d) => PathBuf::from(d),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("methods/guest/target/riscv32im-risc0-zkvm-elf/docker"),
        };
        dir.join("incremental_merkle_tree.bin")
    }

    fn load_merkle() -> Option<Program> {
        let bytes = fs::read(merkle_binary_path()).ok()?;
        Program::new(bytes.into()).ok()
    }

    /// Mirror lee `Program::execute` exactly: write the two length-prefixed
    /// borsh frames `read_lee_call` expects, run the executor under the
    /// production session limit, and return `(user_cycles, decoded_output)`. An
    /// execution that exceeds `SESSION_LIMIT` fails here just as it would
    /// on-chain.
    fn run(
        program: &Program,
        pre_states: Vec<AccountWithMetadata>,
        instruction: Vec<u8>,
    ) -> (u64, ProgramOutput) {
        let instruction_data =
            Program::serialize_instruction(instruction).expect("serialize instruction");
        let envelope: nssa_core::program::ProgramInput<nssa_core::program::InstructionData> =
            nssa_core::program::ProgramInput {
                self_account_id: crate::spel_seeds::program_account(&program.id()),
                caller_account_id: None,
                pre_states,
                instruction: instruction_data,
            };

        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(SESSION_LIMIT));
        env_builder.write_slice(&nssa_core::to_borsh_frame(
            &nssa_core::program::CallKind::Execute,
        ));
        env_builder.write_slice(&nssa_core::to_borsh_frame(&envelope));
        let env = env_builder.build().expect("build executor env");

        let session = default_executor()
            .execute(env, program.elf())
            .expect("guest execution trapped or exceeded the 2^25-cycle session limit");
        // The guest commits a framed borsh payload, not risc0-serde.
        let payload = nssa_core::from_frame(session.journal.as_ref())
            .expect("journal must be a length-prefixed frame");
        let output: ProgramOutput = borsh::from_slice(payload).expect("decode ProgramOutput");
        (session.cycles(), output)
    }

    /// An authorized, uninitialized `tree_main` — the sole Initialize pre-state
    /// (`merkle_tree::initialize_tree` requires `is_authorized` and a
    /// default-valued account).
    fn tree_main_default(program: &Program) -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: true,
            account_id: derive_config_account(
                &crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
            ),
        }
    }

    #[test]
    fn merkle_initialize_cycles_under_budget() {
        let Some(program) = load_merkle() else {
            eprintln!(
                "skipping cycle harness: merkle .bin not built \
                 (cargo risczero build --manifest-path methods/guest/Cargo.toml)"
            );
            return;
        };

        let (cycles, _out) = run(&program, vec![tree_main_default(&program)], vec![0u8]);
        println!(
            "merkle Initialize: {cycles} user cycles ({:.1}% of MAX_GAS_EXEC)",
            cycles as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            cycles < CYCLE_BUDGET,
            "merkle Initialize {cycles} cycles exceeds budget {CYCLE_BUDGET} \
             (transactions are refused above MAX_GAS_EXEC = {MAX_GAS_EXEC})"
        );
    }

    /// Locate the risc0-toolchain `llvm-strip` at test runtime. Unlike the
    /// build script we have no `HOST` env var here, so glob the host-triple dir.
    fn locate_llvm_strip() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("RISC0_LLVM_STRIP") {
            let p = PathBuf::from(p);
            if p.exists() {
                return Some(p);
            }
        }
        let home = std::env::var_os("HOME")?;
        let toolchains = PathBuf::from(home).join(".risc0").join("toolchains");
        for tc in fs::read_dir(&toolchains).ok()?.flatten() {
            let name = tc.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with('v') || !name.contains("-rust-") {
                continue;
            }
            let rustlib = tc.path().join("lib").join("rustlib");
            let Ok(triples) = fs::read_dir(&rustlib) else {
                continue;
            };
            for triple in triples.flatten() {
                let cand = triple.path().join("bin").join("llvm-strip");
                if cand.exists() {
                    return Some(cand);
                }
            }
        }
        None
    }

    /// Mirror of `build.rs`'s R0BF strip, in-memory: strip both the user and
    /// kernel ELFs and repack. Kept byte-for-byte equivalent to the build
    /// script so this test proves what the build script produces.
    fn strip_both_elfs(blob: &[u8], strip: &std::path::Path) -> Vec<u8> {
        let rd = |off: usize| u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        assert_eq!(&blob[0..4], b"R0BF");
        assert_eq!(rd(4), 1, "R0BF v1 expected");
        let header_len = rd(8) as usize;
        let header = &blob[12..12 + header_len];
        let ul_off = 12 + header_len;
        let user_len = rd(ul_off) as usize;
        let user_off = ul_off + 4;
        let user_elf = &blob[user_off..user_off + user_len];
        let kernel_elf = &blob[user_off + user_len..];

        let strip_one = |elf: &[u8], tag: &str| -> Vec<u8> {
            let tmp = std::env::temp_dir().join(format!("lezrln_strip_{tag}.elf"));
            fs::write(&tmp, elf).unwrap();
            let ok = std::process::Command::new(strip)
                .args(["--strip-all", tmp.to_str().unwrap()])
                .status()
                .unwrap()
                .success();
            assert!(ok, "llvm-strip failed");
            let out = fs::read(&tmp).unwrap();
            fs::remove_file(&tmp).ok();
            out
        };
        let su = strip_one(user_elf, "user");
        let sk = strip_one(kernel_elf, "kernel");

        let mut out = Vec::with_capacity(blob.len());
        out.extend_from_slice(b"R0BF");
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(header_len as u32).to_le_bytes());
        out.extend_from_slice(header);
        out.extend_from_slice(&(su.len() as u32).to_le_bytes());
        out.extend_from_slice(&su);
        out.extend_from_slice(&sk);
        out
    }

    /// Verifies the load-bearing assumption behind the build.rs kernel-strip:
    /// a `.bin` whose kernel ELF has been stripped still decodes via
    /// `ProgramBinary::decode` (inside `Program::new`) AND still executes.
    #[test]
    fn stripped_kernel_binary_still_loads_and_runs() {
        let path = merkle_binary_path();
        let Ok(blob) = fs::read(&path) else {
            eprintln!("skipping: merkle .bin not built");
            return;
        };
        let Some(strip) = locate_llvm_strip() else {
            eprintln!("skipping: llvm-strip not found under ~/.risc0/toolchains");
            return;
        };

        let stripped = strip_both_elfs(&blob, &strip);
        println!(
            "kernel-strip: {} -> {} B (saved {} B)",
            blob.len(),
            stripped.len(),
            blob.len() as i64 - stripped.len() as i64
        );
        // `<=`, not `<`: stripping is idempotent, and build.rs strips the
        // docker `.bin` in place on every `cargo build` of the methods crate.
        // So this test's input is already stripped except in the window between
        // a `cargo risczero build` and the next `cargo build` — a strict `<`
        // turns that normal state into a red test. Size is incidental here
        // anyway; what the test is for is that a stripped-kernel container
        // still decodes and still executes.
        assert!(
            stripped.len() <= blob.len(),
            "stripping must never grow the binary"
        );

        // Load-bearing: risc0 must still decode the stripped-kernel container.
        let program = Program::new(stripped.into())
            .expect("stripped-kernel .bin must decode via Program::new");

        // And it must still execute (the stripped kernel is what the sequencer runs).
        let (cycles, out) = run(&program, vec![tree_main_default(&program)], vec![0u8]);
        assert_eq!(out.state_diffs.len(), 1, "Initialize yields one diff");
        println!("stripped-kernel Initialize executed: {cycles} cycles");
    }

    #[test]
    fn merkle_insert_cycles_under_budget() {
        let Some(program) = load_merkle() else {
            eprintln!("skipping cycle harness: merkle .bin not built");
            return;
        };

        // Initialize first to obtain a live tree_main state to insert into.
        let (_init_cycles, init_out) = run(&program, vec![tree_main_default(&program)], vec![0u8]);
        let diff = init_out.state_diffs[0].clone();
        let mut main_initialized = diff.pre_state.account;
        if let Some(data) = diff.post_data {
            main_initialized.data = data;
        }

        let main_pre = AccountWithMetadata {
            account: main_initialized,
            is_authorized: true,
            account_id: derive_config_account(
                &crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
            ),
        };
        // Bottom subtree for leaf 0 — starts default; a distinct id from main.
        let subtree_pre = AccountWithMetadata {
            account: Account::default(),
            is_authorized: true,
            account_id: derive_subtree_account(
                &crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
                0,
            ),
        };

        // opcode 1 (insert) || expected_index=0 (u64 LE) || leaf (valid BN254 fe).
        let mut instruction = vec![1u8];
        instruction.extend_from_slice(&0u64.to_le_bytes());
        let mut leaf = [0u8; 32];
        leaf[0] = 1; // 1 < the BN254 scalar modulus, so a valid field element
        instruction.extend_from_slice(&leaf);

        let (cycles, _out) = run(&program, vec![main_pre, subtree_pre], instruction);
        println!(
            "merkle Insert: {cycles} user cycles ({:.1}% of MAX_GAS_EXEC)",
            cycles as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            cycles < CYCLE_BUDGET,
            "merkle Insert {cycles} cycles exceeds budget {CYCLE_BUDGET} \
             (transactions are refused above MAX_GAS_EXEC = {MAX_GAS_EXEC})"
        );
    }
}
