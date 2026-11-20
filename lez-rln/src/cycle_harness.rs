//! Guest cycle-count measurement harness.
//!
//! A public transaction runs one zkVM session per message delivered to a
//! guest actor, and its gas (`fee_core::market::MAX_GAS_EXEC = 10M`, one gas
//! per cycle) is the SUM over every session of every program the message
//! tree reaches. This harness replays the transactions that matter — merkle
//! Initialize (through `InitializeMerkleTree`), a full `Register` (whose
//! merkle Insert is the Poseidon-heavy session) and a `Slash` (the tightest
//! one) — one session at a time, framing each delivery with
//! `Program::write_receive_input` exactly as lee does, and prints every
//! session's cycles next to the whole-transaction count lee's own metering
//! reports for the same transaction.
//!
//! Run:
//! ```bash
//! RISC0_DEV_MODE=1 cargo test --release --features rc5-state-tests \
//!   cycle_harness -- --nocapture
//! ```
//! `execute()` never proves, so dev mode is optional. The `.bin`s must be
//! staged (see `lez-rln/CLAUDE.md`); if they are absent the tests fail.

#[cfg(all(test, feature = "rc5-state-tests"))]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use nssa::{
        AccountId, Actor, ActorState, PublicTransaction, ValidatedStateDiff,
        program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program},
    };
    use nssa_core::{
        native_token::NATIVE_TOKEN_PROGRAM_ID,
        program::{PdaSeed, ReceiveInput, Transition},
    };
    use risc0_zkvm::{ExecutorEnv, default_executor};

    use crate::state_tests::fixtures::{
        DEFAULT_ACTIVE_DURATION_SEC, DEFAULT_GRACE_PERIOD_DURATION_SEC,
        DEFAULT_MAX_TOTAL_RATE_LIMIT, MERKLE_ID, REG_ID, TREE_ID, TestSetup, init_tree_tx,
        load_merkle, load_registration, register, register_msg, register_tx, setup,
        setup_config_only, slash_msg, slash_tx,
    };

    /// risc0's per-session limit; no single delivery may cross it.
    const SESSION_LIMIT: u64 = 1 << 25;

    /// What rejects a transaction: the summed cycles of all its sessions.
    const MAX_GAS_EXEC: u64 = 10_000_000;

    /// Early-warning budget for the single heaviest session (the merkle
    /// insert), below `MAX_GAS_EXEC` so a codegen or dependency change that
    /// inflates cycles is caught with margin to react.
    const SESSION_EARLY_WARNING: u64 = 9_000_000;

    fn programs() -> HashMap<AccountId, Program> {
        HashMap::from([
            (
                REG_ID,
                load_registration().expect("registration .bin staged"),
            ),
            (MERKLE_ID, load_merkle().expect("merkle .bin staged")),
        ])
    }

    /// One zkVM session delivering `input`, under the session limit.
    fn session(program: &Program, input: &ReceiveInput) -> (u64, Transition) {
        let mut builder = ExecutorEnv::builder();
        builder.session_limit(Some(DEFAULT_PUBLIC_CYCLE_BUDGET.min(SESSION_LIMIT)));
        Program::write_receive_input(input, &mut builder).expect("frame receive input");
        let env = builder.build().expect("build executor env");
        let info = default_executor()
            .execute(env, program.elf())
            .expect("guest trapped or exceeded the session limit");
        let payload = nssa_core::from_frame(&info.journal.bytes).expect("framed journal");
        (
            info.cycles(),
            borsh::from_slice(payload).expect("journal decodes as Transition"),
        )
    }

    /// Actor states keyed by actor, seeded from a state.
    type States = HashMap<Actor, ActorState>;

    /// Deliver one message to `to`, then its sync messages depth-first in
    /// emission order, recording every session. `is_authorized` is what lee
    /// grants: the receiver signed, or the sender issued one of its PDA
    /// seeds. Native actors run as Rust in lee — no session — and are
    /// skipped.
    #[allow(clippy::too_many_arguments)]
    fn deliver(
        programs: &HashMap<AccountId, Program>,
        states: &mut States,
        signers: &BTreeSet<AccountId>,
        to: Actor,
        from: Option<Actor>,
        seeds: &BTreeSet<PdaSeed>,
        message: Vec<u8>,
        log: &mut Vec<(String, u64)>,
    ) {
        if to.program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            return;
        }
        let program = &programs[&to.program_account_id];
        let name = if to.program_account_id == REG_ID {
            "registration"
        } else {
            "merkle"
        };
        let is_authorized = signers.contains(&to.account_id)
            || from.is_some_and(|from| {
                seeds.iter().any(|seed| {
                    AccountId::for_public_pda(&from.program_account_id, seed) == to.account_id
                })
            });
        let input = ReceiveInput {
            receiver: to,
            from,
            is_authorized,
            pre_state: states.get(&to).cloned().unwrap_or_default(),
            message,
        };
        let (cycles, transition) = session(program, &input);
        log.push((format!("{name} @{}", short(&to.account_id)), cycles));
        if let Some(post) = transition.response.post_state {
            states.insert(to, post);
        }
        for next in transition.response.sync_messages {
            deliver(
                programs,
                states,
                signers,
                next.to,
                Some(to),
                &next.pda_seeds,
                next.message,
                log,
            );
        }
    }

    fn short(id: &AccountId) -> String {
        hex::encode(&id.value()[..4])
    }

    /// Every declared actor's state, from `setup`.
    fn states_of(setup: &TestSetup, tx: &PublicTransaction) -> States {
        tx.message()
            .public_context
            .actors
            .iter()
            .map(|actor| {
                (
                    *actor,
                    setup
                        .state
                        .get_account_by_id(actor.account_id)
                        .data
                        .actor_state(actor.program_account_id)
                        .clone(),
                )
            })
            .collect()
    }

    fn whole_tx_cycles(setup: &TestSetup, tx: &PublicTransaction) -> u64 {
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            &setup.state,
            1,
            setup.now_ms,
            MAX_GAS_EXEC,
        )
        .expect("transaction executes within MAX_GAS_EXEC")
        .1
        .cycles
    }

    /// Replay `tx` session by session, print the table, and check it against
    /// lee's whole-transaction count.
    fn measure(label: &str, setup: &TestSetup, tx: &PublicTransaction) -> Vec<(String, u64)> {
        let programs = programs();
        let mut states = states_of(setup, tx);
        let message = tx.message();
        let signers = message.public_context.authorized_accounts.clone();
        let root = &message.execution.root;
        let mut log = Vec::new();
        deliver(
            &programs,
            &mut states,
            &signers,
            root.to,
            None,
            &BTreeSet::new(),
            root.message.clone(),
            &mut log,
        );

        let sum: u64 = log.iter().map(|(_, c)| c).sum();
        let whole = whole_tx_cycles(setup, tx);
        println!("── {label} ──");
        for (what, cycles) in &log {
            println!("  {what:<32} {cycles:>10}");
        }
        println!(
            "  {:<32} {sum:>10}\n  {:<32} {whole:>10} ({:.1}% of MAX_GAS_EXEC)",
            "sum of sessions",
            "whole tx (lee metering)",
            whole as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert_eq!(
            sum, whole,
            "{label}: the session replay must account for every metered cycle"
        );
        for (what, cycles) in &log {
            assert!(
                *cycles < SESSION_LIMIT,
                "{label}: {what} crosses the session limit"
            );
        }
        assert!(
            whole <= MAX_GAS_EXEC,
            "{label}: {whole} cycles over MAX_GAS_EXEC"
        );
        log
    }

    #[test]
    fn merkle_initialize_cycles_under_budget() {
        let setup = setup_config_only(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
        .expect("guest .bins staged");
        let tx = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        let log = measure("InitializeMerkleTree", &setup, &tx);
        assert!(log.iter().any(|(w, _)| w.starts_with("merkle")));
    }

    #[test]
    fn register_and_merkle_insert_cycles_under_budget() {
        let setup: TestSetup = setup().expect("guest .bins staged");
        let mut id_commitment = [0u8; 32];
        id_commitment[0] = 0x42;
        let tx = register_tx(&setup, register_msg(&setup, id_commitment, 100));
        let log = measure("Register (incl. merkle Insert)", &setup, &tx);

        let (_, insert) = log
            .iter()
            .rev()
            .find(|(w, _)| w.starts_with("merkle"))
            .expect("the register tree ends in a merkle insert");
        assert!(
            *insert < SESSION_EARLY_WARNING,
            "merkle Insert {insert} cycles exceeds the early-warning budget \
             {SESSION_EARLY_WARNING}"
        );
    }

    /// Slash is the tightest transaction: the membership session hashes the
    /// secret and the leaf, then the merkle Remove runs nine Poseidons.
    #[test]
    fn slash_cycles_under_budget() {
        let mut setup: TestSetup = setup().expect("guest .bins staged");
        let mut secret = [0u8; 32];
        secret[0] = 0x42;
        let secret_fr = crate::fr_bytes::bytes_le_to_fr(&secret).expect("valid secret");
        let idc = crate::fr_bytes::fr_to_bytes_le(&rln::prelude::Hasher::<
            rln::prelude::PoseidonHash,
        >::hash_single(secret_fr));
        register(&mut setup, idc, 100);
        let tx = slash_tx(&setup.state, slash_msg(&setup.state, secret, idc));
        let log = measure("Slash (incl. merkle Remove)", &setup, &tx);
        assert_eq!(log.len(), 3, "membership, config, merkle");
    }

    /// The deploy path uploads only the user ELF and re-attaches the
    /// protocol's kernel; the loader refuses a `.bin` whose kernel is anything
    /// but `V1COMPAT_ELF`. A staged `.bin` must pass that check as-is.
    #[test]
    fn staged_bins_carry_the_canonical_kernel() {
        for name in ["rln_registration", "incremental_merkle_tree"] {
            let path = crate::state_tests::fixtures::guest_binary_dir().join(format!("{name}.bin"));
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            let segments = crate::rln::client::deploy_segment_count(&bytes)
                .unwrap_or_else(|e| panic!("{name}.bin is not deployable: {e}"));
            println!(
                "{name}.bin: {} B, {segments} deploy segment(s)",
                bytes.len()
            );
        }
    }
}
