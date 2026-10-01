//! State-level tests for the RLN registration and merkle programs.
//!
//! Every test drives the real guest `.bin`s through `V03State`, the same state
//! machine the sequencer runs, so a transaction here plans and applies exactly
//! as it would on chain.
//!
//! The programs sit at fixed header accounts (`REG_ID`, `MERKLE_ID`), seeded
//! with `V03State::with_named_programs` the way a deployer's `CreateHeader`
//! would place them; every PDA hangs off `REG_ID`. Instruction claims (clock
//! timestamp, config price and callee, membership rate limit) are read from
//! the state just before a transaction is built, as the host client does, and
//! the wrong-claim tests below mutate one claim at a time. Leaf indices are
//! not claims: the tree assigns them, and slash/erase find theirs by scanning
//! the tree, as the host client does.
//!
//! Run (the suite is feature-gated; see `lez-rln/CLAUDE.md`):
//! ```bash
//! RISC0_DEV_MODE=1 cargo test --release --features rc5-state-tests
//! ```
//!
//! TODO(v0.3.0 privacy port): the `rc5-state-tests-privacy` tests
//! (`register_from_a_private_payer`, `tokens_survive_a_shield_transfer_deshield_round_trip`)
//! were written against the rc6 account model (`AccountWithMetadata`,
//! `balance` field, token program payment) and are not ported yet. They need
//! `ProvingInput { shard_selectors, .. }`, the new `PrivateWitness` shape and
//! a private payer whose native shard is paid through the chained native
//! transfer. The feature still builds and runs the public suite.

/// Fixtures shared by `state_tests` and `cycle_harness`.
pub(crate) mod fixtures {
    use std::{fs, path::PathBuf};

    use borsh::BorshSerialize;
    use nssa::{
        AccountId, PrivateKey, ProgramShardSelector, PublicKey, PublicTransaction, V03State,
        program::Program,
        public_transaction::{Message, WitnessSet},
    };
    use nssa_core::account::Account;
    use rln_layouts::{ConfigState, Instruction, MembershipState};

    use crate::{
        merkle_tree::{ParsedTreeMain, find_leaf_index},
        rln::{
            CLOCK_50_ACCOUNT_ID_BYTES,
            client::{clock_selector, registration_leaf},
            derive_config_account, derive_membership_account, derive_tree_main_account,
        },
    };

    // ── deployment ─────────────────────────────────────────────────────

    /// Header account of the registration program.
    pub const REG_ID: AccountId = AccountId::new([0xA1; 32]);
    /// Header account of the merkle program.
    pub const MERKLE_ID: AccountId = AccountId::new([0xB2; 32]);
    /// A second copy of the merkle program, deployed where the config does
    /// not point: a caller naming it must be refused by the claim check, not
    /// by a missing program.
    pub const ROGUE_MERKLE_ID: AccountId = AccountId::new([0xC3; 32]);

    /// Test tree ID (first 24 bytes carry data, last 8 zero).
    pub const TREE_ID: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    pub const PRICE_PER_UNIT: u128 = 10_000;
    pub const DEFAULT_MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

    /// Non-zero so time-travel tests can reason about past and future.
    pub const GENESIS_TIMESTAMP_MS: u64 = 1_700_000_000_000;

    /// Compressed durations (1 h active, 10 min grace) for expiration tests.
    pub const DEFAULT_ACTIVE_DURATION_SEC: u32 = 3_600;
    pub const DEFAULT_GRACE_PERIOD_DURATION_SEC: u32 = 600;
    pub const ACTIVE_MS: u64 = rln_layouts::secs_to_millis(DEFAULT_ACTIVE_DURATION_SEC);
    pub const GRACE_MS: u64 = rln_layouts::secs_to_millis(DEFAULT_GRACE_PERIOD_DURATION_SEC);

    /// Covers a registration at the default rate limit plus a renewal, with
    /// room left over so a debit is observable.
    pub const DEFAULT_PAYER_BALANCE: u128 = 10_000_000;

    // ── guest binaries ─────────────────────────────────────────────────

    /// Directory holding the guest `.bin`s under test: the `docker/` dir the
    /// deploy host reads, or `LEZ_RLN_GUEST_DIR` to test a fresh build without
    /// overwriting the artifacts `verify.sh` compares against.
    pub fn guest_binary_dir() -> PathBuf {
        match std::env::var_os("LEZ_RLN_GUEST_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("methods/guest/target/riscv32im-risc0-zkvm-elf/docker"),
        }
    }

    pub fn load_program(name: &str) -> Option<Program> {
        let bytes = fs::read(guest_binary_dir().join(format!("{name}.bin"))).ok()?;
        Program::new(bytes.into()).ok()
    }

    pub fn load_registration() -> Option<Program> {
        load_program("rln_registration")
    }

    pub fn load_merkle() -> Option<Program> {
        load_program("incremental_merkle_tree")
    }

    /// Fresh state with both programs at their header accounts (and the
    /// merkle program again at `ROGUE_MERKLE_ID`), `CLOCK_50` at genesis time.
    pub fn state_with_programs() -> Option<V03State> {
        let registration = load_registration()?;
        let merkle = load_merkle()?;
        let mut state = V03State::new().with_named_programs([
            (REG_ID, registration),
            (MERKLE_ID, merkle.clone()),
            (ROGUE_MERKLE_ID, merkle),
        ]);
        set_clock_50(&mut state, GENESIS_TIMESTAMP_MS, 0);
        Some(state)
    }

    /// Overwrite `CLOCK_50`'s clock shard. The sequencer refreshes it only
    /// every 50 blocks, so tests time-travel through the `test-utils` hatch.
    pub fn set_clock_50(state: &mut V03State, timestamp_ms: u64, block_id: u64) {
        let data = clock_core::ClockAccountData {
            block_id,
            timestamp: timestamp_ms,
        }
        .to_bytes();
        state.force_insert_account(
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            Account::default().with_shard(
                clock_core::clock_account_id(),
                data.try_into().expect("clock data fits"),
            ),
        );
    }

    // ── keys and balances ──────────────────────────────────────────────

    pub fn keypair(seed: u8) -> (PrivateKey, AccountId) {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let key = PrivateKey::try_new(bytes).unwrap();
        let id = AccountId::from(&PublicKey::new_from_private_key(&key));
        (key, id)
    }

    /// A funded wallet account: a native shard and nothing else. No program
    /// can mint native balance, hence the escape hatch. Keeps the nonce.
    pub fn fund_native(state: &mut V03State, account_id: &AccountId, balance: u128) {
        let nonce = state.get_account_by_id(*account_id).nonce;
        state.force_insert_account(
            *account_id,
            Account {
                nonce,
                ..Account::funded(balance)
            },
        );
    }

    pub fn native_balance(state: &V03State, account_id: &AccountId) -> u128 {
        state
            .get_account_by_id(*account_id)
            .data
            .native_balance()
            .expect("native shard decodes")
    }

    // ── selectors ──────────────────────────────────────────────────────

    pub fn config_selector(tree_id: &[u8; 32]) -> ProgramShardSelector {
        ProgramShardSelector::new(derive_config_account(&REG_ID, tree_id), REG_ID)
    }

    /// `merkle` is whichever program the instruction claims; the plan
    /// requires the tree selector to name it.
    pub fn tree_selector(tree_id: &[u8; 32], merkle: AccountId) -> ProgramShardSelector {
        ProgramShardSelector::new(derive_tree_main_account(&REG_ID, tree_id), merkle)
    }

    pub fn membership_selector(
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> ProgramShardSelector {
        ProgramShardSelector::new(
            derive_membership_account(&REG_ID, tree_id, id_commitment),
            REG_ID,
        )
    }

    // ── readers ────────────────────────────────────────────────────────

    pub fn shard(state: &V03State, selector: ProgramShardSelector) -> Vec<u8> {
        state
            .get_account_by_id(selector.account_id)
            .data
            .shard(selector.program_account_id)
            .as_ref()
            .to_vec()
    }

    pub fn config_bytes(state: &V03State) -> Vec<u8> {
        shard(state, config_selector(&TREE_ID))
    }

    pub fn config(state: &V03State) -> ConfigState {
        borsh::from_slice(&config_bytes(state)).expect("config shard decodes")
    }

    pub fn membership(state: &V03State, id_commitment: &[u8; 32]) -> Option<MembershipState> {
        let bytes = shard(state, membership_selector(&TREE_ID, id_commitment));
        (!bytes.is_empty()).then(|| borsh::from_slice(&bytes).expect("membership shard decodes"))
    }

    pub fn tree_shard(state: &V03State) -> Vec<u8> {
        shard(state, tree_selector(&TREE_ID, MERKLE_ID))
    }

    pub fn tree_header(state: &V03State) -> ParsedTreeMain {
        ParsedTreeMain::from_bytes(&tree_shard(state))
    }

    /// Where the live membership of `id_commitment` sits in the tree, found
    /// by scanning for its leaf.
    pub fn leaf_index_of(state: &V03State, id_commitment: &[u8; 32]) -> Option<u64> {
        let rate_limit = membership(state, id_commitment)?.rate_limit;
        find_leaf_index(
            &tree_shard(state),
            &registration_leaf(id_commitment, rate_limit),
        )
    }

    pub fn clock_ms(state: &V03State) -> u64 {
        clock_core::ClockAccountData::from_bytes(&shard(state, clock_selector())).timestamp
    }

    // ── transactions ───────────────────────────────────────────────────

    /// A public transaction signed by `signers`, each at its current nonce.
    pub fn public_tx(
        state: &V03State,
        selectors: Vec<ProgramShardSelector>,
        instruction: impl BorshSerialize,
        program: AccountId,
        signers: &[&PrivateKey],
    ) -> PublicTransaction {
        let nonces = signers
            .iter()
            .map(|key| {
                let id = AccountId::from(&PublicKey::new_from_private_key(key));
                state.get_account_by_id(id).nonce
            })
            .collect();
        let message =
            Message::try_new(program, selectors, nonces, instruction).expect("valid message");
        let witness = WitnessSet::for_message(&message, signers);
        PublicTransaction::new(message, witness)
    }

    pub fn registration_tx(
        state: &V03State,
        selectors: Vec<ProgramShardSelector>,
        instruction: Instruction,
        signers: &[&PrivateKey],
    ) -> PublicTransaction {
        public_tx(state, selectors, instruction, REG_ID, signers)
    }

    pub fn init_config_tx(
        state: &V03State,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> PublicTransaction {
        registration_tx(
            state,
            vec![config_selector(&TREE_ID)],
            Instruction::Initialize {
                merkle_program_id: *MERKLE_ID.value(),
                tree_id: TREE_ID,
                price_per_unit: PRICE_PER_UNIT,
                treasury_account_id: *treasury_id.value(),
                max_total_rate_limit,
                active_duration_for_new_memberships_sec: active_duration_sec,
                grace_period_duration_for_new_memberships_sec: grace_period_duration_sec,
            },
            &[],
        )
    }

    /// `InitializeMerkleTree` for `tree_id`, claiming `merkle` as the callee.
    pub fn init_tree_tx(
        state: &V03State,
        tree_id: &[u8; 32],
        merkle: AccountId,
    ) -> PublicTransaction {
        registration_tx(
            state,
            vec![config_selector(tree_id), tree_selector(tree_id, merkle)],
            Instruction::InitializeMerkleTree {
                tree_id: *tree_id,
                merkle_program_id: *merkle.value(),
            },
            &[],
        )
    }

    pub struct TestSetup {
        pub state: V03State,
        /// Where the price is credited. Deliberately never seeded: a native
        /// credit lands on an account that has never been written to, which
        /// is what `run_setup` relies on in a real deployment.
        pub treasury_id: AccountId,
        /// Signs register/extend and pays the price from its native shard.
        pub payer_id: AccountId,
        pub payer_key: PrivateKey,
    }

    /// Programs deployed, payer funded, config written — tree NOT initialized.
    pub fn setup_config_only(
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> Option<TestSetup> {
        let mut state = state_with_programs()?;
        let (_, treasury_id) = keypair(1);
        let (payer_key, payer_id) = keypair(2);
        fund_native(&mut state, &payer_id, DEFAULT_PAYER_BALANCE);
        let tx = init_config_tx(
            &state,
            &treasury_id,
            max_total_rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
        );
        state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("Initialize should succeed");
        Some(TestSetup {
            state,
            treasury_id,
            payer_id,
            payer_key,
        })
    }

    /// Programs deployed, payer funded, config and tree initialized.
    pub fn setup_with(
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> Option<TestSetup> {
        let mut setup = setup_config_only(
            max_total_rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
        )?;
        let tx = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("InitializeMerkleTree should succeed");
        Some(setup)
    }

    pub fn setup() -> Option<TestSetup> {
        setup_with(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
    }

    /// `Register` with every claim read from `state`, as the host client does.
    pub fn register_ix(state: &V03State, id_commitment: [u8; 32], rate_limit: u64) -> Instruction {
        let config = config(state);
        Instruction::Register {
            tree_id: TREE_ID,
            id_commitment,
            rate_limit,
            merkle_program_id: config.merkle_program_id,
            now_ms: clock_ms(state),
            price_per_unit: config.price_per_unit,
            active_duration_sec: config.active_duration_for_new_memberships_sec,
            grace_period_duration_sec: config.grace_period_duration_for_new_memberships_sec,
        }
    }

    /// A `Register` transaction paying `treasury`; accounts follow the claims.
    pub fn register_tx_to(
        state: &V03State,
        payer_key: &PrivateKey,
        payer_id: &AccountId,
        treasury: &AccountId,
        ix: Instruction,
    ) -> PublicTransaction {
        let Instruction::Register {
            tree_id,
            id_commitment,
            merkle_program_id,
            ..
        } = ix
        else {
            panic!("not a Register instruction");
        };
        let selectors = vec![
            config_selector(&tree_id),
            tree_selector(&tree_id, AccountId::new(merkle_program_id)),
            ProgramShardSelector::native_balance(*payer_id),
            ProgramShardSelector::native_balance(*treasury),
            clock_selector(),
            membership_selector(&tree_id, &id_commitment),
        ];
        registration_tx(state, selectors, ix, &[payer_key])
    }

    pub fn register_tx(setup: &TestSetup, ix: Instruction) -> PublicTransaction {
        register_tx_to(
            &setup.state,
            &setup.payer_key,
            &setup.payer_id,
            &setup.treasury_id,
            ix,
        )
    }

    /// Register `id_commitment` with correct claims; panics on failure.
    pub fn register(setup: &mut TestSetup, id_commitment: [u8; 32], rate_limit: u64) {
        let tx = register_tx(setup, register_ix(&setup.state, id_commitment, rate_limit));
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("Register should succeed");
    }

    pub fn slash_ix(
        state: &V03State,
        identity_secret: [u8; 32],
        id_commitment: [u8; 32],
    ) -> Instruction {
        Instruction::Slash {
            tree_id: TREE_ID,
            id_commitment,
            identity_secret,
            merkle_program_id: config(state).merkle_program_id,
            leaf_index: leaf_index_of(state, &id_commitment).unwrap_or(0),
            rate_limit: membership(state, &id_commitment).map_or(0, |m| m.rate_limit),
        }
    }

    /// Slash needs no signer: the identity secret is the authorization.
    pub fn slash_tx(state: &V03State, ix: Instruction) -> PublicTransaction {
        let Instruction::Slash {
            tree_id,
            id_commitment,
            merkle_program_id,
            ..
        } = ix
        else {
            panic!("not a Slash instruction");
        };
        let selectors = vec![
            config_selector(&tree_id),
            tree_selector(&tree_id, AccountId::new(merkle_program_id)),
            membership_selector(&tree_id, &id_commitment),
        ];
        registration_tx(state, selectors, ix, &[])
    }

    pub fn extend_ix(state: &V03State, id_commitment: [u8; 32]) -> Instruction {
        Instruction::Extend {
            tree_id: TREE_ID,
            id_commitment,
            now_ms: clock_ms(state),
            price_per_unit: config(state).price_per_unit,
            rate_limit: membership(state, &id_commitment).map_or(0, |m| m.rate_limit),
        }
    }

    /// Renewal is paid, so `payer_key` signs and is debited.
    pub fn extend_tx(
        setup: &TestSetup,
        payer_key: &PrivateKey,
        ix: Instruction,
    ) -> PublicTransaction {
        let Instruction::Extend {
            tree_id,
            id_commitment,
            ..
        } = ix
        else {
            panic!("not an Extend instruction");
        };
        let payer_id = AccountId::from(&PublicKey::new_from_private_key(payer_key));
        let selectors = vec![
            config_selector(&tree_id),
            membership_selector(&tree_id, &id_commitment),
            ProgramShardSelector::native_balance(payer_id),
            ProgramShardSelector::native_balance(setup.treasury_id),
            clock_selector(),
        ];
        registration_tx(&setup.state, selectors, ix, &[payer_key])
    }

    pub fn erase_ix(state: &V03State, id_commitment: [u8; 32]) -> Instruction {
        Instruction::Erase {
            tree_id: TREE_ID,
            id_commitment,
            merkle_program_id: config(state).merkle_program_id,
            leaf_index: leaf_index_of(state, &id_commitment).unwrap_or(0),
            rate_limit: membership(state, &id_commitment).map_or(0, |m| m.rate_limit),
            now_ms: clock_ms(state),
        }
    }

    pub fn erase_tx(state: &V03State, ix: Instruction) -> PublicTransaction {
        let Instruction::Erase {
            tree_id,
            id_commitment,
            merkle_program_id,
            ..
        } = ix
        else {
            panic!("not an Erase instruction");
        };
        let selectors = vec![
            config_selector(&tree_id),
            tree_selector(&tree_id, AccountId::new(merkle_program_id)),
            membership_selector(&tree_id, &id_commitment),
            clock_selector(),
        ];
        registration_tx(state, selectors, ix, &[])
    }
}

#[cfg(test)]
mod tests {
    use nssa::{AccountId, ProgramShardSelector, PublicTransaction, V03State, error::LeeError};
    use rand_chacha::ChaCha20Rng;
    use rln::prelude::{
        Fr, Hasher, IdentityKeys, PoseidonHash, RLNMerkleProof, RLNWitnessInput, hash_to_field_le,
    };
    use rln_layouts::{
        Instruction, MerkleInstruction, OFFSET_NEXT_INDEX, OFFSET_TREE_DATA, SPARSE_ENTRY_LEN,
        TREE_LEAVES, TREE_SHARD_MAX_BYTES,
        exit::{
            EXIT_LEAF_MISMATCH, EXIT_STALE_CLOCK, EXIT_STALE_RATE_LIMIT, EXIT_TREE_FULL,
            exit_code_name,
        },
    };

    use super::fixtures::*;
    use crate::{
        fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
        merkle_tree::{MerkleProof, cached_defaults, find_leaf_index, merkle_proof, node_hash},
        rln::{
            CONFIG_OFFSET_ACTIVE_DURATION, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT,
            CONFIG_OFFSET_GRACE_PERIOD_DURATION, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT,
            CONFIG_OFFSET_MERKLE_PROGRAM_ID, CONFIG_OFFSET_PRICE_PER_UNIT,
            CONFIG_OFFSET_TOTAL_REGISTRATIONS, CONFIG_OFFSET_TREASURY_ACCOUNT_ID,
            CONFIG_OFFSET_TREE_ID, CONFIG_SIZE, MEMBERSHIP_SIZE, TREE_DEPTH,
            client::{clock_selector, registration_leaf},
            derive_config_account, derive_membership_account, derive_tree_main_account,
        },
    };

    /// `fee_core::market::MAX_GAS_EXEC`: one gas per cycle, summed over every
    /// plan and apply session of a transaction.
    const MAX_GAS_EXEC: u64 = 10_000_000;

    /// Cycles a whole transaction costs against `state`, all sessions summed.
    fn whole_tx_cycles(state: &V03State, tx: &PublicTransaction) -> u64 {
        let (_diff, charge) = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            state,
            1,
            0,
            MAX_GAS_EXEC,
        )
        .expect("the transaction should execute within the ceiling");
        charge.cycles
    }

    /// A valid BN254 field element with `seed` in the lowest byte.
    fn valid_field_element(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = seed;
        out
    }

    /// `(identity_secret, id_commitment)` with the commitment derived the way
    /// the slash path checks it: `id_commitment = Poseidon(identity_secret)`.
    fn slashable_identity(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = valid_field_element(seed);
        let secret_fr = bytes_le_to_fr(&secret).expect("valid secret");
        (
            secret,
            fr_to_bytes_le(&Hasher::<PoseidonHash>::hash_single(secret_fr)),
        )
    }

    fn setup_or_skip() -> TestSetup {
        setup().expect(
            "guest .bins must be built and staged in methods/guest/target/riscv32im-risc0-zkvm-elf/docker/",
        )
    }

    fn apply(
        state: &mut V03State,
        tx: &nssa::PublicTransaction,
    ) -> Result<(), nssa::error::LeeError> {
        state.transition_from_public_transaction(tx, 1, 0).map(drop)
    }

    /// `result` is a guest halting with exit `code`.
    fn assert_exit(result: Result<(), LeeError>, code: u8, what: &str) {
        match result {
            Err(LeeError::ProgramExitedWithCode { code: got, .. }) => assert_eq!(
                got,
                u32::from(code),
                "{what}: exit {got} ({:?}), expected {:?}",
                exit_code_name(got),
                exit_code_name(u32::from(code))
            ),
            other => panic!("{what}: expected exit {code}, got {other:?}"),
        }
    }

    /// Replace one field of an instruction, keeping every other claim.
    macro_rules! with_claim {
        ($ix:expr, $variant:ident { $field:ident : $value:expr }) => {{
            let mut ix = $ix;
            match &mut ix {
                Instruction::$variant { $field, .. } => *$field = $value,
                _ => panic!(concat!("not a ", stringify!($variant), " instruction")),
            }
            ix
        }};
    }

    // ====================================================================
    // Program loading and PDAs
    // ====================================================================

    #[test]
    fn test_merkle_tree_program_loads() {
        assert!(
            load_merkle().is_some(),
            "merkle .bin must be built and staged in {:?}",
            guest_binary_dir()
        );
    }

    #[test]
    fn test_rln_registration_program_loads() {
        assert!(
            load_registration().is_some(),
            "registration .bin must be built and staged in {:?}",
            guest_binary_dir()
        );
    }

    #[test]
    fn test_all_registration_pdas_are_distinct() {
        let config = derive_config_account(&REG_ID, &TREE_ID);
        let tree_main = derive_tree_main_account(&REG_ID, &TREE_ID);
        let membership = derive_membership_account(&REG_ID, &TREE_ID, &valid_field_element(0x42));
        assert_ne!(tree_main, config);
        assert_ne!(tree_main, membership);
        assert_ne!(config, membership);
        for id in [config, tree_main, membership] {
            assert_ne!(id, REG_ID);
            assert_ne!(id, MERKLE_ID);
        }
    }

    // ====================================================================
    // Direct merkle calls: only the registration program's PDA grant
    // authorizes the tree account.
    // ====================================================================

    #[test]
    fn test_direct_merkle_init_blocked_by_authorization() {
        let mut state = state_with_programs().expect("programs should load");
        let tx = public_tx(
            &state,
            vec![tree_selector(&TREE_ID, MERKLE_ID)],
            MerkleInstruction::Initialize,
            MERKLE_ID,
            &[],
        );
        assert!(
            apply(&mut state, &tx).is_err(),
            "direct merkle init must fail: tree_main is not authorized"
        );
        assert!(tree_shard(&state).is_empty());
    }

    #[test]
    fn test_direct_merkle_insert_blocked_by_authorization() {
        let mut setup = setup_or_skip();
        let before = tree_shard(&setup.state);
        let tx = public_tx(
            &setup.state,
            vec![tree_selector(&TREE_ID, MERKLE_ID)],
            MerkleInstruction::Insert {
                leaf: valid_field_element(0x42),
            },
            MERKLE_ID,
            &[],
        );
        assert!(
            apply(&mut setup.state, &tx).is_err(),
            "direct merkle insert must fail: tree_main is not authorized"
        );
        assert_eq!(tree_shard(&setup.state), before);
    }

    // ====================================================================
    // Initialization
    // ====================================================================

    #[test]
    fn test_registration_init_succeeds() {
        let setup = setup_or_skip();
        assert!(!config_bytes(&setup.state).is_empty());
        assert!(!tree_shard(&setup.state).is_empty());
    }

    #[test]
    fn test_registration_init_creates_config() {
        let setup = setup_or_skip();
        let data = config_bytes(&setup.state);

        // Exact length first: ConfigState carries no version discriminator,
        // so its size is what tells this layout from any older one, and every
        // offset below is meaningless unless it holds.
        assert_eq!(
            data.len(),
            CONFIG_SIZE,
            "config shard must be exactly CONFIG_SIZE bytes"
        );

        let u64_at = |off: usize| u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let u32_at = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());

        assert_eq!(
            &data[CONFIG_OFFSET_MERKLE_PROGRAM_ID..CONFIG_OFFSET_MERKLE_PROGRAM_ID + 32],
            MERKLE_ID.value()
        );
        assert_eq!(
            &data[CONFIG_OFFSET_TREE_ID..CONFIG_OFFSET_TREE_ID + 32],
            &TREE_ID
        );
        assert_eq!(
            u128::from_le_bytes(
                data[CONFIG_OFFSET_PRICE_PER_UNIT..CONFIG_OFFSET_PRICE_PER_UNIT + 16]
                    .try_into()
                    .unwrap()
            ),
            PRICE_PER_UNIT
        );
        assert_eq!(
            &data[CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32],
            setup.treasury_id.value()
        );
        assert_eq!(u64_at(CONFIG_OFFSET_TOTAL_REGISTRATIONS), 0);
        assert_eq!(
            u64_at(CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT),
            DEFAULT_MAX_TOTAL_RATE_LIMIT
        );
        assert_eq!(u64_at(CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT), 0);
        assert_eq!(
            u32_at(CONFIG_OFFSET_ACTIVE_DURATION),
            DEFAULT_ACTIVE_DURATION_SEC
        );
        assert_eq!(
            u32_at(CONFIG_OFFSET_GRACE_PERIOD_DURATION),
            DEFAULT_GRACE_PERIOD_DURATION_SEC
        );
    }

    #[test]
    fn test_registration_init_creates_tree_main() {
        let setup = setup_or_skip();
        let shard = tree_shard(&setup.state);

        assert_eq!(
            shard.len(),
            OFFSET_TREE_DATA,
            "a fresh tree is the header plus cached defaults, with no sparse map yet"
        );
        let header = tree_header(&setup.state);
        assert_eq!(header.depth as usize, TREE_DEPTH);
        assert_eq!(header.next_index, 0);
        assert_eq!(
            header.root,
            cached_defaults(&shard)[0],
            "an empty tree's root is the root level's default"
        );
    }

    #[test]
    fn test_registration_init_prevents_reinit() {
        let mut setup = setup_or_skip();
        let config_before = config_bytes(&setup.state);

        let (_, other_treasury) = keypair(9);
        let reinit = init_config_tx(
            &setup.state,
            &other_treasury,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        );
        assert!(
            apply(&mut setup.state, &reinit).is_err(),
            "Initialize must refuse a config shard that already holds data"
        );
        assert_eq!(config_bytes(&setup.state), config_before);
    }

    /// SECURITY (callee substitution): the program an init chained call
    /// targets must be the one the config names. `merkle_program_id` is a
    /// claim, asserted by the config apply before the chained call — which
    /// carries this program's `main` PDA seed — runs.
    #[test]
    fn test_init_merkle_refuses_a_merkle_program_the_config_does_not_name() {
        let mut setup = setup_config_only(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
        .expect("programs should load");

        // A tree_id whose config was never initialized has nothing to check
        // the claim against.
        let orphan_tree = [0x99u8; 32];
        let orphan = init_tree_tx(&setup.state, &orphan_tree, MERKLE_ID);
        assert!(
            apply(&mut setup.state, &orphan).is_err(),
            "InitializeMerkleTree without an initialized config must fail"
        );

        // A real merkle program, deployed, but not the configured one.
        let rogue = init_tree_tx(&setup.state, &TREE_ID, ROGUE_MERKLE_ID);
        assert!(
            apply(&mut setup.state, &rogue).is_err(),
            "InitializeMerkleTree claiming an unconfigured merkle program must fail"
        );
        assert!(
            shard(&setup.state, tree_selector(&TREE_ID, ROGUE_MERKLE_ID)).is_empty(),
            "the rogue program must not have been granted the tree account"
        );

        // Positive control: the configured program is accepted.
        let honest = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        apply(&mut setup.state, &honest).expect("the configured merkle program is accepted");
        assert_eq!(tree_header(&setup.state).next_index, 0);
    }

    /// SECURITY (tree reset): replaying InitializeMerkleTree must not reset a
    /// live tree. Public transactions need no signature, so the merkle apply's
    /// empty-shard check is the only thing between anyone and a tree wipe that
    /// would invalidate every member's proof while their memberships survive.
    #[test]
    fn test_initialize_merkle_tree_cannot_reset_a_live_tree() {
        let mut setup = setup_or_skip();
        register(&mut setup, valid_field_element(0x42), 300);

        let before = tree_shard(&setup.state);
        assert_eq!(tree_header(&setup.state).next_index, 1);

        let attack = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        let result = apply(&mut setup.state, &attack);
        assert!(
            result.is_err(),
            "re-initializing a live tree must fail, got {result:?}"
        );
        assert_eq!(
            tree_shard(&setup.state),
            before,
            "the rejected reset must leave the tree byte-identical"
        );
    }

    // ====================================================================
    // Register
    // ====================================================================

    #[test]
    fn test_register_succeeds() {
        let mut setup = setup_or_skip();
        let tx = register_tx(
            &setup,
            register_ix(&setup.state, valid_field_element(0x42), 300),
        );
        let result = apply(&mut setup.state, &tx);
        assert!(result.is_ok(), "Register should succeed: {result:?}");
    }

    #[test]
    fn test_register_increments_total_registrations() {
        let mut setup = setup_or_skip();
        assert_eq!(config(&setup.state).total_registrations, 0);
        register(&mut setup, valid_field_element(0x42), 300);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    #[test]
    fn test_register_inserts_leaf() {
        let mut setup = setup_or_skip();
        let root_before = tree_header(&setup.state).root;
        register(&mut setup, valid_field_element(0x42), 300);

        let header = tree_header(&setup.state);
        assert_eq!(header.next_index, 1);
        assert_ne!(header.root, root_before, "the root must move");
        assert_eq!(
            header.root_history[0], root_before,
            "the replaced root heads the root history"
        );
    }

    #[test]
    fn test_register_creates_membership_pda() {
        let mut setup = setup_or_skip();
        let id_commitment = valid_field_element(0x42);
        register(&mut setup, id_commitment, 300);

        assert_eq!(
            shard(&setup.state, membership_selector(&TREE_ID, &id_commitment)).len(),
            MEMBERSHIP_SIZE
        );
        let m = membership(&setup.state, &id_commitment).expect("membership shard exists");
        assert_eq!(leaf_index_of(&setup.state, &id_commitment), Some(0));
        assert_eq!(m.rate_limit, 300);
        assert_eq!(m.id_commitment, id_commitment);
        assert_eq!(
            m.grace_period_start_timestamp_ms,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS
        );
        assert_eq!(m.active_duration_sec, DEFAULT_ACTIVE_DURATION_SEC);
        assert_eq!(
            m.grace_period_duration_sec,
            DEFAULT_GRACE_PERIOD_DURATION_SEC
        );
    }

    /// The shard stores one sparse entry per populated node and nothing else,
    /// so a full tree is `TREE_SHARD_MAX_BYTES`, which `rln_layouts`
    /// const-asserts under the protocol's `SHARD_MAX_BYTES`.
    #[test]
    fn merkle_shard_stores_exactly_the_populated_nodes() {
        let mut setup = setup_or_skip();
        let size = |nodes: usize| OFFSET_TREE_DATA + 2 + nodes * SPARSE_ENTRY_LEN;

        register(&mut setup, valid_field_element(0x41), 100);
        assert_eq!(
            tree_shard(&setup.state).len(),
            size(TREE_DEPTH + 1),
            "one leaf stores exactly its root-to-leaf path"
        );

        // Leaf 1 shares every ancestor with leaf 0: one new node.
        register(&mut setup, valid_field_element(0x42), 100);
        assert_eq!(tree_shard(&setup.state).len(), size(TREE_DEPTH + 2));
        assert_eq!(size(rln_layouts::TREE_NODES), TREE_SHARD_MAX_BYTES);
    }

    /// `next_index` only advances, and an index past the last leaf aliases
    /// live nodes and produces a wrong root without failing. The merkle insert
    /// refuses it, and the whole registration with it.
    #[test]
    fn register_is_refused_once_every_leaf_index_is_used() {
        let mut setup = setup_or_skip();

        let tree = tree_selector(&TREE_ID, MERKLE_ID);
        let mut data = tree_shard(&setup.state);
        data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&TREE_LEAVES.to_le_bytes());
        let account = setup
            .state
            .get_account_by_id(tree.account_id)
            .with_shard(MERKLE_ID, data.try_into().unwrap());
        setup.state.force_insert_account(tree.account_id, account);

        let idc = valid_field_element(0xC2);
        let tx = register_tx(&setup, register_ix(&setup.state, idc, 100));
        assert_exit(
            apply(&mut setup.state, &tx),
            EXIT_TREE_FULL,
            "a registration past the last leaf",
        );
        assert!(membership(&setup.state, &idc).is_none());
        assert_eq!(config(&setup.state).total_registrations, 0);
    }

    /// The membership init guard is the ONLY duplicate check: neither the
    /// register plan nor the merkle insert dedupes.
    #[test]
    fn test_register_same_commitment_twice_fails() {
        let mut setup = setup_or_skip();
        let id_commitment = valid_field_element(0x42);
        register(&mut setup, id_commitment, 300);

        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let tree_before = tree_shard(&setup.state);
        let tx = register_tx(&setup, register_ix(&setup.state, id_commitment, 300));
        assert!(
            apply(&mut setup.state, &tx).is_err(),
            "a second registration of the same id_commitment must fail"
        );
        assert_eq!(tree_shard(&setup.state), tree_before, "no second leaf");
        assert_eq!(native_balance(&setup.state, &setup.payer_id), payer_before);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    // ── wrong claims ────────────────────────────────────────────────────
    //
    // Plan sees no account data, so each of these values is a claim that an
    // apply asserts against the stored bytes. Every one must fail the whole
    // transaction and leave no trace.

    fn assert_register_refused(setup: &mut TestSetup, ix: Instruction, what: &str) {
        let Instruction::Register { id_commitment, .. } = ix else {
            unreachable!()
        };
        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let tree_before = tree_shard(&setup.state);
        let config_before = config_bytes(&setup.state);

        let tx = register_tx(setup, ix);
        let result = apply(&mut setup.state, &tx);
        assert!(
            result.is_err(),
            "register with {what} must fail, got {result:?}"
        );

        assert!(
            membership(&setup.state, &id_commitment).is_none(),
            "{what}: no membership"
        );
        assert_eq!(
            tree_shard(&setup.state),
            tree_before,
            "{what}: tree untouched"
        );
        assert_eq!(
            config_bytes(&setup.state),
            config_before,
            "{what}: config untouched"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            payer_before,
            "{what}: payer not charged"
        );
    }

    /// Two registrations built from the SAME pre-state — as two clients
    /// reading the chain at the same height would build them — both land when
    /// a block applies them back to back. Nothing in either names an index, so
    /// neither can go stale because of the other: the tree gives the first
    /// index 0 and the second index 1.
    #[test]
    fn same_block_registrations_compose() {
        let mut setup = setup_or_skip();
        let (key_b, payer_b) = keypair(3);
        fund_native(&mut setup.state, &payer_b, DEFAULT_PAYER_BALANCE);
        let (idc_a, idc_b) = (valid_field_element(0x0A), valid_field_element(0x0B));

        let snapshot = &setup.state;
        let tx_a = register_tx(&setup, register_ix(snapshot, idc_a, 100));
        let tx_b = register_tx_to(
            snapshot,
            &key_b,
            &payer_b,
            &setup.treasury_id,
            register_ix(snapshot, idc_b, 200),
        );

        apply(&mut setup.state, &tx_a).expect("first registration of the block");
        apply(&mut setup.state, &tx_b).expect("second registration, built from the same state");

        let shard = tree_shard(&setup.state);
        assert_eq!(tree_header(&setup.state).next_index, 2);
        assert_eq!(
            node_hash(&shard, TREE_DEPTH, 0),
            registration_leaf(&idc_a, 100)
        );
        assert_eq!(
            node_hash(&shard, TREE_DEPTH, 1),
            registration_leaf(&idc_b, 200)
        );
        assert_eq!(
            find_leaf_index(&shard, &registration_leaf(&idc_a, 100)),
            Some(0)
        );
        assert_eq!(
            find_leaf_index(&shard, &registration_leaf(&idc_b, 200)),
            Some(1)
        );
        assert_eq!(membership(&setup.state, &idc_a).unwrap().rate_limit, 100);
        assert_eq!(membership(&setup.state, &idc_b).unwrap().rate_limit, 200);
        let config = config(&setup.state);
        assert_eq!(config.total_registrations, 2);
        assert_eq!(config.current_total_rate_limit, 300);
    }

    #[test]
    fn register_rejects_a_wrong_price_claim() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix.clone(),
                Register {
                    price_per_unit: PRICE_PER_UNIT - 1
                }
            ),
            "an under-priced claim",
        );
        assert_register_refused(
            &mut setup,
            with_claim!(ix, Register { price_per_unit: 0 }),
            "a zero price claim",
        );
    }

    #[test]
    fn register_rejects_a_wrong_merkle_program_claim() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix,
                Register {
                    merkle_program_id: *ROGUE_MERKLE_ID.value()
                }
            ),
            "an unconfigured merkle program",
        );
        assert!(
            shard(&setup.state, tree_selector(&TREE_ID, ROGUE_MERKLE_ID)).is_empty(),
            "the rogue program must not have written the tree account"
        );
    }

    #[test]
    fn register_rejects_a_wrong_now_ms_claim() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        // A backdated clock would shorten nothing, a future one would extend
        // the membership for free: both are refused.
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix.clone(),
                Register {
                    now_ms: GENESIS_TIMESTAMP_MS + ACTIVE_MS
                }
            ),
            "a future now_ms",
        );
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix,
                Register {
                    now_ms: GENESIS_TIMESTAMP_MS - 1
                }
            ),
            "a past now_ms",
        );
    }

    #[test]
    fn register_rejects_wrong_duration_claims() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix.clone(),
                Register {
                    active_duration_sec: DEFAULT_ACTIVE_DURATION_SEC * 10
                }
            ),
            "an inflated active duration",
        );
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix,
                Register {
                    grace_period_duration_sec: DEFAULT_GRACE_PERIOD_DURATION_SEC * 10
                }
            ),
            "an inflated grace duration",
        );
    }

    // ====================================================================
    // Slash
    // ====================================================================

    fn registered_slashable(setup: &mut TestSetup, seed: u8) -> ([u8; 32], [u8; 32]) {
        let (secret, idc) = slashable_identity(seed);
        register(setup, idc, 300);
        assert!(membership(&setup.state, &idc).is_some());
        (secret, idc)
    }

    fn slash(
        setup: &mut TestSetup,
        secret: [u8; 32],
        idc: [u8; 32],
    ) -> Result<(), nssa::error::LeeError> {
        let tx = slash_tx(&setup.state, slash_ix(&setup.state, secret, idc));
        apply(&mut setup.state, &tx)
    }

    #[test]
    fn test_slash_succeeds() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let result = slash(&mut setup, secret, idc);
        assert!(result.is_ok(), "Slash should succeed: {result:?}");
    }

    #[test]
    fn test_slash_zeros_membership_pda() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        slash(&mut setup, secret, idc).expect("slash");
        assert!(
            shard(&setup.state, membership_selector(&TREE_ID, &idc)).is_empty(),
            "the membership shard is cleared"
        );
    }

    #[test]
    fn test_slash_decrements_total_registrations() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        assert_eq!(config(&setup.state).total_registrations, 1);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(config(&setup.state).total_registrations, 0);
    }

    #[test]
    fn test_slash_updates_merkle_root() {
        let mut setup = setup_or_skip();
        let empty_root = tree_header(&setup.state).root;
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        assert_ne!(tree_header(&setup.state).root, empty_root);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(
            tree_header(&setup.state).root,
            empty_root,
            "removing the only leaf returns the empty root"
        );
    }

    #[test]
    fn test_slash_does_not_change_next_index() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(
            tree_header(&setup.state).next_index,
            1,
            "indices are never reused"
        );
    }

    #[test]
    fn test_slash_invalid_secret_fails() {
        let mut setup = setup_or_skip();
        let (_, idc) = registered_slashable(&mut setup, 0x42);
        let (wrong_secret, _) = slashable_identity(0x99);
        assert!(slash(&mut setup, wrong_secret, idc).is_err());
        assert!(membership(&setup.state, &idc).is_some());
    }

    #[test]
    fn test_slash_double_slash_fails() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        slash(&mut setup, secret, idc).expect("first slash");
        // Claims as a slasher would guess them (the membership is gone).
        let ix = Instruction::Slash {
            tree_id: TREE_ID,
            id_commitment: idc,
            identity_secret: secret,
            merkle_program_id: *MERKLE_ID.value(),
            leaf_index: 0,
            rate_limit: 300,
        };
        let tx = slash_tx(&setup.state, ix);
        assert!(
            apply(&mut setup.state, &tx).is_err(),
            "double slash must fail"
        );
    }

    /// The leaf a slash removes is the membership's, not the caller's pick:
    /// naming another member's leaf index must not evict that member. The
    /// index is a hint the merkle apply checks by content.
    #[test]
    fn slash_rejects_wrong_leaf_index_and_rate_limit_claims() {
        let mut setup = setup_or_skip();
        register(&mut setup, valid_field_element(0x01), 100);
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let tree_before = tree_shard(&setup.state);
        let ix = slash_ix(&setup.state, secret, idc);

        for (what, bad) in [
            (
                "another member's leaf",
                with_claim!(ix.clone(), Slash { leaf_index: 0 }),
            ),
            (
                "a lower rate limit",
                with_claim!(ix.clone(), Slash { rate_limit: 100 }),
            ),
            (
                "an unconfigured merkle program",
                with_claim!(
                    ix,
                    Slash {
                        merkle_program_id: *ROGUE_MERKLE_ID.value()
                    }
                ),
            ),
        ] {
            let tx = slash_tx(&setup.state, bad);
            assert!(
                apply(&mut setup.state, &tx).is_err(),
                "slash with {what} must fail"
            );
            assert_eq!(
                tree_shard(&setup.state),
                tree_before,
                "{what}: tree untouched"
            );
            assert!(
                membership(&setup.state, &idc).is_some(),
                "{what}: membership kept"
            );
        }
    }

    /// Slashing clears the membership shard, so the init guard no longer
    /// stands in the way: the commitment can register again, at a new leaf.
    #[test]
    fn a_slashed_commitment_can_register_again() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        slash(&mut setup, secret, idc).expect("slash");

        register(&mut setup, idc, 300);
        assert!(membership(&setup.state, &idc).is_some(), "re-registered");
        assert_eq!(
            leaf_index_of(&setup.state, &idc),
            Some(1),
            "the old leaf index is never reused"
        );
        assert_eq!(
            node_hash(&tree_shard(&setup.state), TREE_DEPTH, 0),
            [0; 32],
            "the old leaf stays zeroed"
        );
        assert_eq!(tree_header(&setup.state).next_index, 2);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    /// Slash and erase name a leaf index the caller found by scanning; the
    /// merkle apply removes it only if it holds `H(id_commitment,
    /// rate_limit)`, and the membership apply has already pinned
    /// `rate_limit`. Any other index, or the right index with the wrong rate
    /// limit, fails the whole transaction and changes nothing.
    #[test]
    fn remove_refuses_a_wrong_index_or_leaf() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let (_, idc_a) = slashable_identity(0x41);
        let (secret_b, idc_b) = slashable_identity(0x42);
        register(&mut setup, idc_a, 100);
        register(&mut setup, idc_b, 300);
        assert_eq!(leaf_index_of(&setup.state, &idc_a), Some(0));
        assert_eq!(leaf_index_of(&setup.state, &idc_b), Some(1));
        let leaf_a = registration_leaf(&idc_a, 100);

        // Erase becomes legal once both have expired; slash is always legal.
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );

        let tree_before = tree_shard(&setup.state);
        let config_before = config_bytes(&setup.state);
        let membership_a_before = shard(&setup.state, membership_selector(&TREE_ID, &idc_a));
        let membership_b_before = shard(&setup.state, membership_selector(&TREE_ID, &idc_b));

        let slash_b = slash_ix(&setup.state, secret_b, idc_b);
        let erase_b = erase_ix(&setup.state, idc_b);
        let bad: Vec<(&str, PublicTransaction, u8)> = vec![
            (
                "slash at A's index",
                slash_tx(
                    &setup.state,
                    with_claim!(slash_b.clone(), Slash { leaf_index: 0 }),
                ),
                EXIT_LEAF_MISMATCH,
            ),
            (
                "slash past next_index",
                slash_tx(
                    &setup.state,
                    with_claim!(slash_b.clone(), Slash { leaf_index: 2 }),
                ),
                EXIT_LEAF_MISMATCH,
            ),
            (
                "slash at B's index with A's rate limit",
                slash_tx(
                    &setup.state,
                    with_claim!(slash_b.clone(), Slash { rate_limit: 100 }),
                ),
                EXIT_STALE_RATE_LIMIT,
            ),
            (
                "erase at A's index",
                erase_tx(
                    &setup.state,
                    with_claim!(erase_b.clone(), Erase { leaf_index: 0 }),
                ),
                EXIT_LEAF_MISMATCH,
            ),
            (
                "erase at B's index with A's rate limit",
                erase_tx(
                    &setup.state,
                    with_claim!(erase_b, Erase { rate_limit: 100 }),
                ),
                EXIT_STALE_RATE_LIMIT,
            ),
        ];
        for (what, tx, code) in bad {
            assert_exit(apply(&mut setup.state, &tx), code, what);
            assert_eq!(
                tree_shard(&setup.state),
                tree_before,
                "{what}: tree untouched"
            );
            assert_eq!(
                config_bytes(&setup.state),
                config_before,
                "{what}: config untouched"
            );
            assert_eq!(
                shard(&setup.state, membership_selector(&TREE_ID, &idc_a)),
                membership_a_before,
                "{what}: A untouched"
            );
            assert_eq!(
                shard(&setup.state, membership_selector(&TREE_ID, &idc_b)),
                membership_b_before,
                "{what}: B untouched"
            );
        }

        // The right index: exactly B's leaf is zeroed.
        let tx = slash_tx(&setup.state, slash_b);
        apply(&mut setup.state, &tx).expect("slash at B's index");
        let shard_after = tree_shard(&setup.state);
        assert_eq!(
            node_hash(&shard_after, TREE_DEPTH, 0),
            leaf_a,
            "A's leaf kept"
        );
        assert_eq!(
            node_hash(&shard_after, TREE_DEPTH, 1),
            [0; 32],
            "B's leaf zeroed"
        );
        assert_eq!(tree_header(&setup.state).next_index, 2);
        assert!(membership(&setup.state, &idc_a).is_some());
        assert!(membership(&setup.state, &idc_b).is_none());
        let after = config(&setup.state);
        assert_eq!(after.total_registrations, 1);
        assert_eq!(after.current_total_rate_limit, 100);

        // And A, the other way out.
        erase(&mut setup, idc_a).expect("erase at A's index");
        assert_eq!(node_hash(&tree_shard(&setup.state), TREE_DEPTH, 0), [0; 32]);
        assert_eq!(config(&setup.state).total_registrations, 0);
    }

    // ====================================================================
    // Rate-limit accounting
    // ====================================================================

    #[test]
    fn test_total_rate_limit_cap_enforced() {
        let mut setup = setup_with(
            500,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
        .expect("setup");
        register(&mut setup, valid_field_element(0x01), 300);

        let tx = register_tx(
            &setup,
            register_ix(&setup.state, valid_field_element(0x02), 300),
        );
        assert!(
            apply(&mut setup.state, &tx).is_err(),
            "a registration past max_total_rate_limit must fail"
        );
        assert_eq!(config(&setup.state).current_total_rate_limit, 300);
    }

    #[test]
    fn test_current_total_rate_limit_tracking() {
        let mut setup = setup_or_skip();
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        assert_eq!(config(&setup.state).current_total_rate_limit, 300);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
    }

    // ====================================================================
    // Native payment
    // ====================================================================
    //
    // The price moves through a chained call to the native token program,
    // which refuses an unauthorized sender and an insufficient balance. The
    // destination is the registry's to check, against the config's treasury.

    #[test]
    fn register_debits_payer_and_credits_treasury_natively() {
        let mut setup = setup_or_skip();
        let price = 300 * PRICE_PER_UNIT;
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert_eq!(native_balance(&setup.state, &setup.treasury_id), 0);

        register(&mut setup, valid_field_element(0x42), 300);

        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE - price
        );
        assert_eq!(native_balance(&setup.state, &setup.treasury_id), price);
    }

    /// SECURITY (payment routing): the treasury check in the config apply is
    /// the only thing deciding where the price lands.
    #[test]
    fn register_rejects_a_treasury_that_is_not_the_configured_one() {
        let mut setup = setup_or_skip();
        let (_, attacker_treasury) = keypair(9);
        assert_ne!(attacker_treasury, setup.treasury_id);

        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &setup.payer_key,
            &setup.payer_id,
            &attacker_treasury,
            register_ix(&setup.state, idc, 300),
        );
        let result = apply(&mut setup.state, &tx);
        assert!(
            result.is_err(),
            "an unconfigured treasury must be refused; got {result:?}"
        );
        assert_eq!(native_balance(&setup.state, &attacker_treasury), 0);
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert!(membership(&setup.state, &idc).is_none());
    }

    /// An unsigned payer row: the payer is named but does not sign.
    #[test]
    fn register_rejects_an_unauthorized_payer() {
        let mut setup = setup_or_skip();
        let (other_key, other_id) = keypair(7);
        fund_native(&mut setup.state, &other_id, DEFAULT_PAYER_BALANCE);

        // `other` signs, but the payer row names `setup.payer`.
        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &other_key,
            &setup.payer_id,
            &setup.treasury_id,
            register_ix(&setup.state, idc, 300),
        );
        assert!(
            apply(&mut setup.state, &tx).is_err(),
            "a payer that did not sign must not be debited"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert_eq!(
            native_balance(&setup.state, &other_id),
            DEFAULT_PAYER_BALANCE
        );
        assert!(membership(&setup.state, &idc).is_none());
    }

    /// One unit short of the price is refused; exactly the price is accepted.
    #[test]
    fn register_rejects_an_underfunded_payer() {
        let mut setup = setup_or_skip();
        let price = 300 * PRICE_PER_UNIT;
        let payer_id = setup.payer_id;
        fund_native(&mut setup.state, &payer_id, price - 1);

        let idc = valid_field_element(0x42);
        let tx = register_tx(&setup, register_ix(&setup.state, idc, 300));
        assert!(
            apply(&mut setup.state, &tx).is_err(),
            "one unit short must be refused"
        );
        assert_eq!(native_balance(&setup.state, &payer_id), price - 1);
        assert!(membership(&setup.state, &idc).is_none());

        fund_native(&mut setup.state, &payer_id, price);
        register(&mut setup, idc, 300);
        assert_eq!(
            native_balance(&setup.state, &payer_id),
            0,
            "exactly the price empties the payer"
        );
    }

    /// Across every account a register touches, native balance is moved,
    /// never minted or burnt.
    #[test]
    fn register_conserves_total_balance() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let accounts: Vec<AccountId> = [
            config_selector(&TREE_ID),
            tree_selector(&TREE_ID, MERKLE_ID),
            ProgramShardSelector::native_balance(setup.payer_id),
            ProgramShardSelector::native_balance(setup.treasury_id),
            clock_selector(),
            membership_selector(&TREE_ID, &idc),
        ]
        .iter()
        .map(|s| s.account_id)
        .collect();
        let total = |state: &V03State| -> u128 {
            accounts.iter().map(|id| native_balance(state, id)).sum()
        };

        let before = total(&setup.state);
        register(&mut setup, idc, 300);
        assert_eq!(total(&setup.state), before);
        assert!(
            native_balance(&setup.state, &setup.treasury_id) > 0,
            "the transfer happened"
        );
    }

    // ====================================================================
    // Gas
    // ====================================================================

    /// The error a transaction fails with, and what the sequencer charges for
    /// it under a `MAX_GAS_EXEC` declaration.
    fn failure_and_charge(state: &V03State, tx: &PublicTransaction) -> (LeeError, u64) {
        let err = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            state,
            1,
            0,
            MAX_GAS_EXEC,
        )
        .err()
        .expect("the transaction should fail");
        let (charge, settled) = nssa::ValidatedStateDiff::from_public_transaction_metered(
            tx,
            state,
            1,
            0,
            MAX_GAS_EXEC,
        );
        assert!(
            settled.is_ok(),
            "a chargeable failure settles as nonce bumps, got {:?}",
            settled.err()
        );
        (err, charge.cycles)
    }

    /// A claim that went stale because the chain moved (here: the clock) halts
    /// the guest with an exit code, and is charged the cycles that ran — the
    /// registration plan's leaf Poseidon plus two small applies — not the
    /// declared gas. A malformed claim still panics and pays the full budget.
    #[test]
    fn a_stale_clock_claim_is_charged_measured_cycles() {
        let setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 100);

        let stale = with_claim!(
            ix.clone(),
            Register {
                now_ms: clock_ms(&setup.state) + 1
            }
        );
        let (err, charged) = failure_and_charge(&setup.state, &register_tx(&setup, stale));
        println!(
            "stale clock claim: {err:?} ({}), charged {charged} cycles ({:.1}% of MAX_GAS_EXEC)",
            exit_code_name(u32::from(EXIT_STALE_CLOCK)).unwrap(),
            charged as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            matches!(err, LeeError::ProgramExitedWithCode { code, .. } if code == u32::from(EXIT_STALE_CLOCK)),
            "got {err:?}"
        );
        assert!(
            charged < 1_200_000,
            "a stale claim must not pay the ceiling: {charged}"
        );

        let malformed = with_claim!(
            ix,
            Register {
                merkle_program_id: *ROGUE_MERKLE_ID.value()
            }
        );
        let (err, charged) = failure_and_charge(&setup.state, &register_tx(&setup, malformed));
        assert!(
            matches!(err, LeeError::ProgramExecutionFailed(_)),
            "got {err:?}"
        );
        assert_eq!(
            charged, MAX_GAS_EXEC,
            "a malformed claim still pays the full budget"
        );
    }

    /// A whole register transaction — every plan and apply session of the
    /// registration program plus the chained merkle insert — against the
    /// ceiling that rejects it (`fee_core::market::MAX_GAS_EXEC`, one gas per
    /// cycle). Printed: the margin is what says whether a deeper tree fits.
    #[test]
    fn register_transaction_fits_the_gas_ceiling() {
        let setup = setup_or_skip();
        let tx = register_tx(
            &setup,
            register_ix(&setup.state, valid_field_element(0x42), 100),
        );

        let used = whole_tx_cycles(&setup.state, &tx);
        println!(
            "register transaction: {used} cycles ({:.1}% of MAX_GAS_EXEC), tree depth {TREE_DEPTH}",
            used as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            used <= MAX_GAS_EXEC,
            "register costs {used} cycles against {MAX_GAS_EXEC}"
        );
    }

    /// Slash and erase hash the member's leaf in their plan (the merkle
    /// `Remove` checks it by content) on top of a nine-level root update, so
    /// they cost about one Poseidon more than a register.
    #[test]
    fn slash_and_erase_transactions_fit_the_gas_ceiling() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let (secret, idc) = slashable_identity(0x42);
        register(&mut setup, idc, 100);

        let slash = whole_tx_cycles(
            &setup.state,
            &slash_tx(&setup.state, slash_ix(&setup.state, secret, idc)),
        );
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        let erase = whole_tx_cycles(
            &setup.state,
            &erase_tx(&setup.state, erase_ix(&setup.state, idc)),
        );
        for (what, used) in [("slash", slash), ("erase", erase)] {
            println!(
                "{what} transaction: {used} cycles ({:.1}% of MAX_GAS_EXEC)",
                used as f64 / MAX_GAS_EXEC as f64 * 100.0
            );
            assert!(used <= MAX_GAS_EXEC, "{what} costs {used} cycles");
        }
    }

    // ====================================================================
    // RLN proofs against on-chain state
    // ====================================================================

    fn rate_commitment(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
        let id_fr = bytes_le_to_fr(id_commitment).expect("valid id_commitment");
        fr_to_bytes_le(&Hasher::<PoseidonHash>::hash_pair(
            id_fr,
            Fr::from(rate_limit),
        ))
    }

    fn recompute_root(proof: &MerkleProof) -> [u8; 32] {
        let mut current = bytes_le_to_fr(&proof.leaf).expect("valid leaf");
        for (sibling, &right) in proof.path_elements.iter().zip(&proof.path_indices) {
            let sibling = bytes_le_to_fr(sibling).expect("valid sibling");
            current = if right == 0 {
                Hasher::<PoseidonHash>::hash_pair(current, sibling)
            } else {
                Hasher::<PoseidonHash>::hash_pair(sibling, current)
            };
        }
        fr_to_bytes_le(&current)
    }

    /// The proof lifted from the tree's depth to the circuit's, and its root.
    fn circuit_proof(proof: &MerkleProof) -> (RLNMerkleProof, Fr) {
        let mut path: Vec<Fr> = proof
            .path_elements
            .iter()
            .map(|b| bytes_le_to_fr(b).expect("valid path element"))
            .collect();
        let mut indices = proof.path_indices.clone();
        crate::proof_circuit::pad_path(&mut path, &mut indices);
        let root =
            crate::proof_circuit::fold_root(bytes_le_to_fr(&proof.root).expect("valid root"));
        (RLNMerkleProof::new(path, indices), root)
    }

    fn external_nullifier(epoch: &[u8]) -> Fr {
        Hasher::<PoseidonHash>::hash_pair(
            hash_to_field_le(epoch),
            hash_to_field_le(b"lssa-rln-test"),
        )
    }

    #[test]
    fn test_merkle_proof_extraction_from_state() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        register(&mut setup, idc, 300);

        let proof = merkle_proof(&tree_shard(&setup.state), 0);
        assert_eq!(proof.path_elements.len(), TREE_DEPTH);
        assert_eq!(proof.path_indices.len(), TREE_DEPTH);
        assert_eq!(proof.leaf, rate_commitment(&idc, 300));
        assert_eq!(
            recompute_root(&proof),
            proof.root,
            "the proof reproduces the on-chain root"
        );
    }

    fn prove_and_verify(setup: &TestSetup, keys: &IdentityKeys, leaf_index: u64, rate_limit: u64) {
        let proof = merkle_proof(&tree_shard(&setup.state), leaf_index);
        assert_eq!(
            proof.leaf,
            rate_commitment(&fr_to_bytes_le(&keys.id_commitment()), rate_limit)
        );
        let (merkle_proof, root) = circuit_proof(&proof);
        let x = hash_to_field_le(b"Hello, RLN!");
        let witness = RLNWitnessInput::new_single()
            .identity_secret(keys.identity_secret())
            .user_message_limit(Fr::from(rate_limit))
            .merkle_proof(merkle_proof)
            .x(x)
            .external_nullifier(external_nullifier(b"test-epoch"))
            .message_id(Fr::from(0u64))
            .build()
            .expect("witness");
        let rln = crate::proof_circuit::engine();
        let (rln_proof, values) = rln.generate_proof(&witness).expect("proof");
        assert_eq!(values.root(), root, "proof root is the on-chain root");
        assert!(
            rln.verify_with_roots(&rln_proof, &values, &x, &[root])
                .expect("verify"),
            "RLN proof must verify against the on-chain root"
        );
    }

    #[test]
    fn test_rln_proof_generation_and_verification() {
        let mut setup = setup_or_skip();
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[0x42; 32]);
        register(&mut setup, fr_to_bytes_le(&keys.id_commitment()), 300);
        prove_and_verify(&setup, &keys, 0, 300);
    }

    #[test]
    fn test_rln_proof_with_multiple_registrations() {
        let mut setup = setup_or_skip();
        let keys: Vec<IdentityKeys> = (1u8..=3)
            .map(|s| IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[s; 32]))
            .collect();
        for k in &keys {
            register(&mut setup, fr_to_bytes_le(&k.id_commitment()), 100);
        }
        prove_and_verify(&setup, &keys[1], 1, 100);
    }

    #[test]
    fn test_rln_proof_invalid_after_slash() {
        let mut setup = setup_or_skip();
        let empty_root = tree_header(&setup.state).root;
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let root_registered = tree_header(&setup.state).root;

        slash(&mut setup, secret, idc).expect("slash");

        let proof = merkle_proof(&tree_shard(&setup.state), 0);
        assert_ne!(proof.root, root_registered, "the root moved");
        assert_ne!(proof.leaf, rate_commitment(&idc, 300), "the leaf is gone");
        assert_eq!(proof.root, empty_root, "back to the empty root");
    }

    #[test]
    fn test_rln_double_message_detection() {
        let mut setup = setup_or_skip();
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[0x99; 32]);
        register(&mut setup, fr_to_bytes_le(&keys.id_commitment()), 300);

        let (merkle_proof, root) = circuit_proof(&merkle_proof(&tree_shard(&setup.state), 0));
        let rln = crate::proof_circuit::engine();
        let prove = |msg: &[u8]| {
            let x = hash_to_field_le(msg);
            let witness = RLNWitnessInput::new_single()
                .identity_secret(keys.identity_secret())
                .user_message_limit(Fr::from(300u64))
                .merkle_proof(merkle_proof.clone())
                .x(x)
                .external_nullifier(external_nullifier(b"epoch-1"))
                .message_id(Fr::from(0u64))
                .build()
                .expect("witness");
            let (p, v) = rln.generate_proof(&witness).expect("proof");
            assert!(rln.verify_with_roots(&p, &v, &x, &[root]).expect("verify"));
            v
        };
        let v1 = prove(b"First message");
        let v2 = prove(b"Second message");
        // Same identity + epoch + message_id → same nullifier: the double
        // signal is detectable.
        assert_eq!(
            v1.nullifier().expect("single"),
            v2.nullifier().expect("single")
        );
    }

    // ====================================================================
    // Expiration
    // ====================================================================

    const EXP_RATE_LIMIT: u64 = 300;

    fn extend(setup: &mut TestSetup, idc: [u8; 32]) -> Result<(), nssa::error::LeeError> {
        let tx = extend_tx(setup, &setup.payer_key, extend_ix(&setup.state, idc));
        apply(&mut setup.state, &tx)
    }

    fn erase(setup: &mut TestSetup, idc: [u8; 32]) -> Result<(), nssa::error::LeeError> {
        let tx = erase_tx(&setup.state, erase_ix(&setup.state, idc));
        apply(&mut setup.state, &tx)
    }

    /// Registered at `GENESIS_TIMESTAMP_MS`.
    fn registered_at_genesis(seed: u8) -> (TestSetup, [u8; 32]) {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let idc = valid_field_element(seed);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        (setup, idc)
    }

    #[test]
    fn test_register_snapshots_grace_period_start() {
        let mut setup = setup_or_skip();
        let at = GENESIS_TIMESTAMP_MS + 500;
        set_clock_50(&mut setup.state, at, 50);
        let idc = valid_field_element(0xA1);
        register(&mut setup, idc, EXP_RATE_LIMIT);

        let m = membership(&setup.state, &idc).unwrap();
        assert_eq!(m.grace_period_start_timestamp_ms, at + ACTIVE_MS);
        assert_eq!(m.active_duration_sec, DEFAULT_ACTIVE_DURATION_SEC);
        assert_eq!(
            m.grace_period_duration_sec,
            DEFAULT_GRACE_PERIOD_DURATION_SEC
        );
    }

    /// A fresh chain carries the genesis CLOCK_50 (timestamp 0) until block
    /// 50. A membership stamped from it would expire the instant the clock is
    /// first written, so registration refuses — even with a matching claim.
    #[test]
    fn test_register_is_refused_while_the_clock_reads_zero() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, 0, 0);
        let idc = valid_field_element(0xB2);
        let ix = register_ix(&setup.state, idc, EXP_RATE_LIMIT);
        assert!(matches!(ix, Instruction::Register { now_ms: 0, .. }));
        let tx = register_tx(&setup, ix);
        assert!(apply(&mut setup.state, &tx).is_err());
        assert!(membership(&setup.state, &idc).is_none());
    }

    /// The production defaults over a realistic timeline: guards the bug that
    /// turned a 30-day membership into a 43-minute one.
    #[test]
    fn test_production_durations_span_real_days_of_chain_time() {
        use crate::rln::client::{
            DEFAULT_ACTIVE_DURATION_SECS, DEFAULT_GRACE_PERIOD_DURATION_SECS,
        };
        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

        let mut setup = setup_with(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SECS,
            DEFAULT_GRACE_PERIOD_DURATION_SECS,
        )
        .expect("setup");
        let t0 = GENESIS_TIMESTAMP_MS;
        set_clock_50(&mut setup.state, t0, 50);
        let idc = valid_field_element(0xB1);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            t0 + 30 * DAY_MS
        );

        set_clock_50(&mut setup.state, t0 + 29 * DAY_MS, 100);
        assert!(extend(&mut setup, idc).is_err(), "still active on day 29");

        set_clock_50(&mut setup.state, t0 + 31 * DAY_MS, 150);
        extend(&mut setup, idc).expect("in grace on day 31");
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            t0 + (30 + 7 + 30) * DAY_MS,
            "extend adds one grace + one active period"
        );

        set_clock_50(&mut setup.state, t0 + 75 * DAY_MS, 200);
        erase(&mut setup, idc).expect("expired by day 75");
        assert!(membership(&setup.state, &idc).is_none());
    }

    #[test]
    fn test_extend_succeeds_in_grace_period() {
        let (mut setup, idc) = registered_at_genesis(0xA2);
        let grace_start = GENESIS_TIMESTAMP_MS + ACTIVE_MS;
        set_clock_50(&mut setup.state, grace_start + GRACE_MS / 2, 100);
        extend(&mut setup, idc).expect("extend during grace");
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            grace_start + GRACE_MS + ACTIVE_MS
        );
    }

    #[test]
    fn test_extend_fails_when_still_active() {
        let (mut setup, idc) = registered_at_genesis(0xA3);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + 10, 100);
        assert!(extend(&mut setup, idc).is_err());
    }

    #[test]
    fn test_extend_fails_when_expired() {
        let (mut setup, idc) = registered_at_genesis(0xA4);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        assert!(extend(&mut setup, idc).is_err());
    }

    /// SECURITY (rate-limit pinning): extend does not check who pays — a
    /// membership records no owner — but it charges the registration price,
    /// so keeping an abandoned membership alive is not free.
    #[test]
    fn test_extend_by_a_third_party_is_allowed_but_charged() {
        let (mut setup, idc) = registered_at_genesis(0xA5);
        let (third_key, third_id) = keypair(5);
        fund_native(&mut setup.state, &third_id, DEFAULT_PAYER_BALANCE);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);

        let treasury_before = native_balance(&setup.state, &setup.treasury_id);
        let owner_before = native_balance(&setup.state, &setup.payer_id);
        let tx = extend_tx(&setup, &third_key, extend_ix(&setup.state, idc));
        apply(&mut setup.state, &tx).expect("a paying third party may renew");

        let price = u128::from(EXP_RATE_LIMIT) * PRICE_PER_UNIT;
        assert!(price > 0, "a zero-priced renewal would restore the grief");
        assert_eq!(
            native_balance(&setup.state, &third_id),
            DEFAULT_PAYER_BALANCE - price
        );
        assert_eq!(
            native_balance(&setup.state, &setup.treasury_id) - treasury_before,
            price
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            owner_before,
            "owner untouched"
        );
    }

    #[test]
    fn test_extend_fails_when_payer_cannot_cover_the_price() {
        let (mut setup, idc) = registered_at_genesis(0xA7);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let payer = setup.payer_id;
        fund_native(&mut setup.state, &payer, 0);
        assert!(
            extend(&mut setup, idc).is_err(),
            "an unfunded renewal must fail"
        );
    }

    /// Renewal claims: a cheaper price or a lower rate limit would renew for
    /// less than registering costs.
    #[test]
    fn extend_rejects_wrong_price_and_rate_limit_claims() {
        let (mut setup, idc) = registered_at_genesis(0xA9);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let before = membership(&setup.state, &idc)
            .unwrap()
            .grace_period_start_timestamp_ms;
        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let ix = extend_ix(&setup.state, idc);

        for (what, bad) in [
            (
                "an under-priced claim",
                with_claim!(ix.clone(), Extend { price_per_unit: 1 }),
            ),
            (
                "a lower rate limit",
                with_claim!(ix.clone(), Extend { rate_limit: 100 }),
            ),
            (
                "a wrong now_ms",
                with_claim!(
                    ix,
                    Extend {
                        now_ms: GENESIS_TIMESTAMP_MS + ACTIVE_MS
                    }
                ),
            ),
        ] {
            let tx = extend_tx(&setup, &setup.payer_key, bad);
            assert!(
                apply(&mut setup.state, &tx).is_err(),
                "extend with {what} must fail"
            );
            assert_eq!(
                membership(&setup.state, &idc)
                    .unwrap()
                    .grace_period_start_timestamp_ms,
                before
            );
            assert_eq!(native_balance(&setup.state, &setup.payer_id), payer_before);
        }
    }

    #[test]
    fn test_erase_succeeds_when_expired() {
        let (mut setup, idc) = registered_at_genesis(0xA6);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        erase(&mut setup, idc).expect("erase of an expired membership");
        assert!(membership(&setup.state, &idc).is_none());
    }

    #[test]
    fn test_erase_fails_when_active() {
        let (mut setup, idc) = registered_at_genesis(0xA7);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + 1, 100);
        assert!(erase(&mut setup, idc).is_err());
    }

    #[test]
    fn test_erase_fails_in_grace_period() {
        let (mut setup, idc) = registered_at_genesis(0xA8);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        assert!(erase(&mut setup, idc).is_err());
    }

    #[test]
    fn test_erase_decrements_total_rate_limit() {
        let (mut setup, idc) = registered_at_genesis(0xAA);
        assert_eq!(
            config(&setup.state).current_total_rate_limit,
            EXP_RATE_LIMIT
        );
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        erase(&mut setup, idc).expect("erase");
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
    }

    /// Erase removes the leaf the MEMBERSHIP records: pointing it at another
    /// member's leaf must not evict that member.
    #[test]
    fn erase_rejects_wrong_leaf_index_and_rate_limit_claims() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        register(&mut setup, valid_field_element(0x01), 100);
        let idc = valid_field_element(0xAB);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );

        let tree_before = tree_shard(&setup.state);
        let ix = erase_ix(&setup.state, idc);
        for (what, bad) in [
            (
                "another member's leaf",
                with_claim!(ix.clone(), Erase { leaf_index: 0 }),
            ),
            (
                "a larger rate limit",
                with_claim!(ix.clone(), Erase { rate_limit: 600 }),
            ),
            (
                "an unconfigured merkle program",
                with_claim!(
                    ix,
                    Erase {
                        merkle_program_id: *ROGUE_MERKLE_ID.value()
                    }
                ),
            ),
        ] {
            let tx = erase_tx(&setup.state, bad);
            assert!(
                apply(&mut setup.state, &tx).is_err(),
                "erase with {what} must fail"
            );
            assert_eq!(
                tree_shard(&setup.state),
                tree_before,
                "{what}: tree untouched"
            );
            assert!(
                membership(&setup.state, &idc).is_some(),
                "{what}: membership kept"
            );
        }
    }

    /// Erase clears the membership shard, so the commitment can register again.
    #[test]
    fn an_erased_commitment_can_register_again() {
        let (mut setup, idc) = registered_at_genesis(0xAC);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        erase(&mut setup, idc).expect("erase");

        register(&mut setup, idc, EXP_RATE_LIMIT);
        assert!(membership(&setup.state, &idc).is_some(), "re-registered");
        assert_eq!(leaf_index_of(&setup.state, &idc), Some(1));
        assert_eq!(
            config(&setup.state).current_total_rate_limit,
            EXP_RATE_LIMIT
        );
    }
}
