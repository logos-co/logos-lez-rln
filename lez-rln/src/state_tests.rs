//! State-level tests for the RLN registration and merkle programs.
//!
//! Every test drives the real guest `.bin`s through `V03State`, the same state
//! machine the sequencer runs, so a transaction here is delivered to its
//! actors exactly as it would be on chain.
//!
//! The programs sit at fixed header accounts (`REG_ID`, `MERKLE_ID`), seeded
//! with `V03State::with_named_programs` the way a deployer's `CreateHeader`
//! would place them; every PDA hangs off `REG_ID`. The registry belongs to
//! `owner()`, who signs `Initialize` at its own account, and `TREE_ID` is
//! what the program makes of that account and `TREE_LABEL`. A transaction sends one
//! message to one actor and declares every actor the program will touch; an
//! actor that does not exist yet is admitted by the PDA seed it is derived
//! from, as the host client does. Chain time is the block timestamp a
//! transaction is applied at (`TestSetup::now_ms`), and every time-dependent
//! message carries it as `now_ms`, read just before the transaction is built,
//! as the host client does. Leaf indices are never sent for a registration:
//! the tree assigns them, and slash/erase find theirs by scanning the tree.
//!
//! Run (the suite is feature-gated; see `lez-rln/CLAUDE.md`):
//! ```bash
//! RISC0_DEV_MODE=1 cargo test --release --features rc5-state-tests
//! ```

/// Fixtures shared by `state_tests` and `cycle_harness`.
pub(crate) mod fixtures {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use borsh::BorshSerialize;
    use nssa::{
        AccountId, Actor, ActorState, PrivateKey, PublicAccountEvidence, PublicKey,
        PublicTransaction, V03State,
        program::Program,
        public_transaction::{Message as TxMessage, WitnessSet},
    };
    use nssa_core::{account::Account, program::PdaSeed};
    use rln_layouts::{ConfigState, MembershipState, Message};

    use crate::{
        merkle_tree::{ParsedTreeMain, find_leaf_index, main_seed},
        rln::{
            client::registration_leaf, config_seed, derive_config_account,
            derive_membership_account, derive_tree_main_account, membership_seed,
        },
    };

    // ── deployment ─────────────────────────────────────────────────────

    /// Header account of the registration program.
    pub const REG_ID: AccountId = AccountId::new([0xA1; 32]);
    /// Header account of the merkle program.
    pub const MERKLE_ID: AccountId = AccountId::new([0xB2; 32]);
    /// A second copy of the merkle program, deployed where the config does
    /// not point: a transaction declaring it gets nothing from the config,
    /// which messages only the program it stores.
    pub const ROGUE_MERKLE_ID: AccountId = AccountId::new([0xC3; 32]);

    /// The label the owner names its registry by: "state-tests", zero-padded.
    pub const TREE_LABEL: [u8; 32] = *b"state-tests\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    /// The tree `owner()` creates under `TREE_LABEL`:
    /// `owner_tree_id(owner, TREE_LABEL)`, written out so every fixture can
    /// name it as a constant (`the_test_tree_is_the_owners`).
    pub const TREE_ID: [u8; 32] = [
        0xdb, 0x45, 0x1b, 0x57, 0xab, 0x3f, 0x5f, 0xf8, 0xee, 0x1d, 0xc2, 0x14, 0x9a, 0xba, 0x8d,
        0x5e, 0x54, 0x3c, 0xd8, 0x2b, 0x1d, 0xd5, 0x9c, 0x00, 0x4c, 0x79, 0xc0, 0x19, 0x45, 0xd9,
        0xa3, 0xd2,
    ];

    pub const PRICE_PER_UNIT: u128 = 10_000;
    pub const DEFAULT_MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;
    pub const DEFAULT_MIN_RATE_LIMIT: u64 = 100;
    pub const DEFAULT_MAX_RATE_LIMIT: u64 = 600;

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
    /// merkle program again at `ROGUE_MERKLE_ID`).
    pub fn state_with_programs() -> Option<V03State> {
        let registration = load_registration()?;
        let merkle = load_merkle()?;
        Some(V03State::new().with_named_programs([
            (REG_ID, registration),
            (MERKLE_ID, merkle.clone()),
            (ROGUE_MERKLE_ID, merkle),
        ]))
    }

    // ── keys and balances ──────────────────────────────────────────────

    pub fn keypair(seed: u8) -> (PrivateKey, AccountId) {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let key = PrivateKey::try_new(bytes).unwrap();
        let id = AccountId::from(&PublicKey::new_from_private_key(&key));
        (key, id)
    }

    /// The registry's owner: signs `Initialize`, and its account is half of
    /// what `TREE_ID` is made of.
    pub fn owner() -> (PrivateKey, AccountId) {
        keypair(3)
    }

    /// The registration program at `account`: where a signed `Initialize`
    /// enters.
    pub fn owner_actor(account: &AccountId) -> Actor {
        Actor::new(*account, REG_ID)
    }

    /// A funded wallet account: a native balance and nothing else. No program
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
            .expect("native balance decodes")
    }

    // ── actors ─────────────────────────────────────────────────────────

    pub fn config_actor(tree_id: &[u8; 32]) -> Actor {
        Actor::new(derive_config_account(&REG_ID, tree_id), REG_ID)
    }

    /// The tree under `merkle`: the configured program, or a rogue copy a
    /// transaction may declare but the config never messages.
    pub fn tree_actor(tree_id: &[u8; 32], merkle: AccountId) -> Actor {
        Actor::new(derive_tree_main_account(&REG_ID, tree_id), merkle)
    }

    pub fn membership_actor(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> Actor {
        Actor::new(
            derive_membership_account(&REG_ID, tree_id, id_commitment),
            REG_ID,
        )
    }

    /// Admission for a PDA of the registration program that does not exist
    /// on chain yet.
    pub fn pda_evidence(seed: [u8; 32]) -> PublicAccountEvidence {
        PublicAccountEvidence::Pda {
            program: REG_ID,
            seed: PdaSeed::new(seed),
        }
    }

    // ── readers ────────────────────────────────────────────────────────

    pub fn actor_state(state: &V03State, actor: Actor) -> Vec<u8> {
        state
            .get_account_by_id(actor.account_id)
            .data
            .actor_state(actor.program_account_id)
            .to_vec()
    }

    pub fn config_bytes(state: &V03State) -> Vec<u8> {
        actor_state(state, config_actor(&TREE_ID))
    }

    pub fn config(state: &V03State) -> ConfigState {
        borsh::from_slice(&config_bytes(state)).expect("config state decodes")
    }

    pub fn membership(state: &V03State, id_commitment: &[u8; 32]) -> Option<MembershipState> {
        let bytes = actor_state(state, membership_actor(&TREE_ID, id_commitment));
        (!bytes.is_empty()).then(|| borsh::from_slice(&bytes).expect("membership state decodes"))
    }

    pub fn tree_state(state: &V03State) -> Vec<u8> {
        actor_state(state, tree_actor(&TREE_ID, MERKLE_ID))
    }

    pub fn tree_header(state: &V03State) -> ParsedTreeMain {
        ParsedTreeMain::from_bytes(&tree_state(state))
    }

    /// Where the live membership of `id_commitment` sits in the tree, found
    /// by scanning for its leaf.
    pub fn leaf_index_of(state: &V03State, id_commitment: &[u8; 32]) -> Option<u64> {
        let rate_limit = membership(state, id_commitment)?.rate_limit;
        find_leaf_index(
            &tree_state(state),
            &registration_leaf(id_commitment, rate_limit),
        )
    }

    // ── transactions ───────────────────────────────────────────────────

    /// A public transaction with one root message, signed by `signers`, each
    /// at its current nonce.
    pub fn public_tx(
        state: &V03State,
        root: Actor,
        public_actors: Vec<Actor>,
        evidence: Vec<PublicAccountEvidence>,
        message: impl BorshSerialize,
        signers: &[&PrivateKey],
    ) -> PublicTransaction {
        let nonces: BTreeMap<AccountId, _> = signers
            .iter()
            .map(|key| {
                let id = AccountId::from(&PublicKey::new_from_private_key(key));
                (id, state.get_account_by_id(id).nonce)
            })
            .collect();
        let message = TxMessage::new(
            root,
            Program::serialize_message(message).expect("message serializes"),
            public_actors,
            nonces,
            None,
            evidence,
        );
        let witness = WitnessSet::for_message(&message, signers);
        PublicTransaction::new(message, witness)
    }

    /// `Initialize` with `TREE_LABEL`, every knob given.
    pub fn initialize_msg(
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
        (min_rate_limit, max_rate_limit): (u64, u64),
    ) -> Message {
        Message::Initialize {
            merkle_program_id: *MERKLE_ID.value(),
            tree_label: TREE_LABEL,
            price_per_unit: PRICE_PER_UNIT,
            treasury_account_id: *treasury_id.value(),
            max_total_rate_limit,
            active_duration_for_new_memberships_sec: active_duration_sec,
            grace_period_duration_for_new_memberships_sec: grace_period_duration_sec,
            min_rate_limit,
            max_rate_limit,
        }
    }

    /// `message` sent the way the host sends `Initialize`: to the program at
    /// the account of `signer`, which signs, declaring the config of
    /// `tree_id` with the evidence that admits it.
    pub fn signed_init_tx(
        state: &V03State,
        signer: &PrivateKey,
        tree_id: &[u8; 32],
        message: Message,
    ) -> PublicTransaction {
        let account = AccountId::from(&PublicKey::new_from_private_key(signer));
        public_tx(
            state,
            owner_actor(&account),
            vec![owner_actor(&account), config_actor(tree_id)],
            vec![pda_evidence(config_seed(tree_id))],
            message,
            &[signer],
        )
    }

    pub fn init_config_tx(
        state: &V03State,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
        bounds: (u64, u64),
    ) -> PublicTransaction {
        let (owner_key, _) = owner();
        signed_init_tx(
            state,
            &owner_key,
            &TREE_ID,
            initialize_msg(
                treasury_id,
                max_total_rate_limit,
                active_duration_sec,
                grace_period_duration_sec,
                bounds,
            ),
        )
    }

    /// `InitializeMerkleTree` for `tree_id`, declaring the tree under
    /// `merkle`. The tree is admitted by the seed the config grants it.
    pub fn init_tree_tx(
        state: &V03State,
        tree_id: &[u8; 32],
        merkle: AccountId,
    ) -> PublicTransaction {
        public_tx(
            state,
            config_actor(tree_id),
            vec![config_actor(tree_id), tree_actor(tree_id, merkle)],
            Vec::new(),
            Message::InitializeMerkleTree { tree_id: *tree_id },
            &[],
        )
    }

    pub struct TestSetup {
        pub state: V03State,
        /// Where the price is credited: a plain keyed account that exists on
        /// chain with no balance, as `run_setup`'s seed leaves it, so a
        /// transaction may declare it without evidence.
        pub treasury_id: AccountId,
        /// Signs register/extend and pays the price from its native balance.
        pub payer_id: AccountId,
        pub payer_key: PrivateKey,
        /// Chain time: the timestamp of the block every transaction is
        /// applied in, and the `now_ms` time-dependent messages carry.
        pub now_ms: u64,
    }

    impl TestSetup {
        /// Apply `tx` in a block at `now_ms`.
        pub fn apply(&mut self, tx: &PublicTransaction) -> Result<(), nssa::error::LeeError> {
            self.state
                .transition_from_public_transaction(tx, 1, self.now_ms)
                .map(drop)
        }
    }

    /// Programs deployed, payer funded, treasury existing, config written —
    /// tree NOT initialized.
    pub fn setup_config_only(
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> Option<TestSetup> {
        setup_config_only_with_bounds(
            max_total_rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
            (DEFAULT_MIN_RATE_LIMIT, DEFAULT_MAX_RATE_LIMIT),
        )
    }

    pub fn setup_config_only_with_bounds(
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
        bounds: (u64, u64),
    ) -> Option<TestSetup> {
        let (_, treasury_id) = keypair(1);
        let (payer_key, payer_id) = keypair(2);
        let mut state = state_with_programs()?.with_empty_public_accounts([treasury_id]);
        fund_native(&mut state, &payer_id, DEFAULT_PAYER_BALANCE);
        let mut setup = TestSetup {
            state,
            treasury_id,
            payer_id,
            payer_key,
            now_ms: GENESIS_TIMESTAMP_MS,
        };
        let tx = init_config_tx(
            &setup.state,
            &treasury_id,
            max_total_rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
            bounds,
        );
        setup.apply(&tx).expect("Initialize should succeed");
        Some(setup)
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
            .apply(&tx)
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

    /// A registry accepting `min..=max` with every other knob at its default.
    pub fn setup_with_bounds(min_rate_limit: u64, max_rate_limit: u64) -> Option<TestSetup> {
        let mut setup = setup_config_only_with_bounds(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
            (min_rate_limit, max_rate_limit),
        )?;
        let tx = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        setup
            .apply(&tx)
            .expect("InitializeMerkleTree should succeed");
        Some(setup)
    }

    /// `Register` as the host client sends it: paid by the setup's payer,
    /// dated by chain time.
    pub fn register_msg(setup: &TestSetup, id_commitment: [u8; 32], rate_limit: u64) -> Message {
        Message::Register {
            tree_id: TREE_ID,
            id_commitment,
            rate_limit,
            payer: *setup.payer_id.value(),
            now_ms: setup.now_ms,
        }
    }

    /// A `Register` transaction signed by `payer_key`, declaring `treasury`
    /// as the price's destination and the tree under `merkle`.
    pub fn register_tx_to(
        state: &V03State,
        payer_key: &PrivateKey,
        treasury: &AccountId,
        merkle: AccountId,
        msg: Message,
    ) -> PublicTransaction {
        let Message::Register {
            tree_id,
            id_commitment,
            payer,
            ..
        } = msg
        else {
            panic!("not a Register message");
        };
        public_tx(
            state,
            config_actor(&tree_id),
            vec![
                config_actor(&tree_id),
                membership_actor(&tree_id, &id_commitment),
                tree_actor(&tree_id, merkle),
                Actor::native_balance(AccountId::new(payer)),
                Actor::native_balance(*treasury),
            ],
            vec![pda_evidence(membership_seed(&tree_id, &id_commitment))],
            msg,
            &[payer_key],
        )
    }

    pub fn register_tx(setup: &TestSetup, msg: Message) -> PublicTransaction {
        register_tx_to(
            &setup.state,
            &setup.payer_key,
            &setup.treasury_id,
            MERKLE_ID,
            msg,
        )
    }

    /// Register `id_commitment`; panics on failure.
    pub fn register(setup: &mut TestSetup, id_commitment: [u8; 32], rate_limit: u64) {
        let tx = register_tx(setup, register_msg(setup, id_commitment, rate_limit));
        setup.apply(&tx).expect("Register should succeed");
    }

    /// `Slash` with the leaf index found by scanning, as the host does.
    pub fn slash_msg(
        state: &V03State,
        identity_secret: [u8; 32],
        id_commitment: [u8; 32],
    ) -> Message {
        Message::Slash {
            tree_id: TREE_ID,
            id_commitment,
            identity_secret,
            leaf_index: leaf_index_of(state, &id_commitment).unwrap_or(0),
        }
    }

    /// Slash needs no signer: the identity secret is the authorization.
    pub fn slash_tx(state: &V03State, msg: Message) -> PublicTransaction {
        let Message::Slash {
            tree_id,
            id_commitment,
            ..
        } = msg
        else {
            panic!("not a Slash message");
        };
        public_tx(
            state,
            membership_actor(&tree_id, &id_commitment),
            vec![
                membership_actor(&tree_id, &id_commitment),
                config_actor(&tree_id),
                tree_actor(&tree_id, MERKLE_ID),
            ],
            Vec::new(),
            msg,
            &[],
        )
    }

    pub fn extend_msg(setup: &TestSetup, payer: &AccountId, id_commitment: [u8; 32]) -> Message {
        Message::Extend {
            tree_id: TREE_ID,
            id_commitment,
            payer: *payer.value(),
            now_ms: setup.now_ms,
        }
    }

    /// Renewal is paid, so `payer_key` signs and is debited.
    pub fn extend_tx(setup: &TestSetup, payer_key: &PrivateKey, msg: Message) -> PublicTransaction {
        let Message::Extend {
            tree_id,
            id_commitment,
            payer,
            ..
        } = msg
        else {
            panic!("not an Extend message");
        };
        public_tx(
            &setup.state,
            membership_actor(&tree_id, &id_commitment),
            vec![
                membership_actor(&tree_id, &id_commitment),
                config_actor(&tree_id),
                Actor::native_balance(AccountId::new(payer)),
                Actor::native_balance(setup.treasury_id),
            ],
            Vec::new(),
            msg,
            &[payer_key],
        )
    }

    pub fn erase_msg(setup: &TestSetup, id_commitment: [u8; 32]) -> Message {
        Message::Erase {
            tree_id: TREE_ID,
            id_commitment,
            leaf_index: leaf_index_of(&setup.state, &id_commitment).unwrap_or(0),
            now_ms: setup.now_ms,
        }
    }

    pub fn erase_tx(state: &V03State, msg: Message) -> PublicTransaction {
        let Message::Erase {
            tree_id,
            id_commitment,
            ..
        } = msg
        else {
            panic!("not an Erase message");
        };
        public_tx(
            state,
            membership_actor(&tree_id, &id_commitment),
            vec![
                membership_actor(&tree_id, &id_commitment),
                config_actor(&tree_id),
                tree_actor(&tree_id, MERKLE_ID),
            ],
            Vec::new(),
            msg,
            &[],
        )
    }

    /// The tree's seed as evidence, for tests that must admit it themselves.
    pub fn tree_evidence(tree_id: &[u8; 32]) -> PublicAccountEvidence {
        pda_evidence(main_seed(tree_id))
    }

    /// Overwrite the tree's actor state.
    pub fn set_tree_state(state: &mut V03State, data: Vec<u8>) {
        let tree = tree_actor(&TREE_ID, MERKLE_ID);
        let account = state
            .get_account_by_id(tree.account_id)
            .with_actor_state(MERKLE_ID, ActorState::from(data));
        state.force_insert_account(tree.account_id, account);
    }
}

#[cfg(test)]
mod tests {
    use nssa::{AccountId, Actor, PublicTransaction, V03State, error::LeeError};
    use rand_chacha::ChaCha20Rng;
    use rln::prelude::{
        Fr, Hasher, IdentityKeys, PoseidonHash, RLNMerkleProof, RLNWitnessInput, hash_to_field_le,
    };
    use rln_layouts::{
        CLOCK_CLAIM_TOLERANCE_MS, MerkleMessage, Message, OFFSET_NEXT_INDEX, OFFSET_TREE_DATA,
        SPARSE_ENTRY_LEN, TREE_LEAVES, TREE_SHARD_MAX_BYTES, config_seed,
        exit::{EXIT_LEAF_MISMATCH, EXIT_MEMBERSHIP_EXISTS, EXIT_TREE_FULL, exit_code_name},
        label_seed, owner_tree_id,
    };

    use super::fixtures::*;
    use crate::{
        fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
        merkle_tree::{MerkleProof, cached_defaults, find_leaf_index, merkle_proof, node_hash},
        rln::{
            CONFIG_OFFSET_ACTIVE_DURATION, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT,
            CONFIG_OFFSET_GRACE_PERIOD_DURATION, CONFIG_OFFSET_MAX_RATE_LIMIT,
            CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT, CONFIG_OFFSET_MERKLE_PROGRAM_ID,
            CONFIG_OFFSET_MIN_RATE_LIMIT, CONFIG_OFFSET_PRICE_PER_UNIT,
            CONFIG_OFFSET_TOTAL_REGISTRATIONS, CONFIG_OFFSET_TREASURY_ACCOUNT_ID,
            CONFIG_OFFSET_TREE_ID, CONFIG_SIZE, MEMBERSHIP_SIZE, TREE_DEPTH,
            client::registration_leaf, derive_config_account, derive_membership_account,
            derive_tree_main_account,
        },
    };

    /// `fee_core::market::MAX_GAS_EXEC`: one gas per cycle, summed over every
    /// session of a transaction.
    const MAX_GAS_EXEC: u64 = 10_000_000;

    /// Cycles a whole transaction costs against `setup`, all sessions summed.
    fn whole_tx_cycles(setup: &TestSetup, tx: &PublicTransaction) -> u64 {
        let (_diff, charge) = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            &setup.state,
            1,
            setup.now_ms,
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

    /// Replace one field of a message, keeping every other.
    macro_rules! with_field {
        ($msg:expr, $variant:ident { $field:ident : $value:expr }) => {{
            let mut msg = $msg;
            match &mut msg {
                Message::$variant { $field, .. } => *$field = $value,
                _ => panic!(concat!("not a ", stringify!($variant), " message")),
            }
            msg
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
    // Direct merkle messages: only the registration program's PDA grant
    // authorizes the tree account.
    // ====================================================================

    #[test]
    fn test_direct_merkle_init_blocked_by_authorization() {
        let mut setup = setup_config_only(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
        .expect("programs should load");
        // Admitted by evidence, so authorization is what refuses it.
        let tx = public_tx(
            &setup.state,
            tree_actor(&TREE_ID, MERKLE_ID),
            vec![tree_actor(&TREE_ID, MERKLE_ID)],
            vec![tree_evidence(&TREE_ID)],
            MerkleMessage::Initialize,
            &[],
        );
        let result = setup.apply(&tx);
        assert!(
            matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
            "direct merkle init must fail in the guest: tree_main is not authorized, got {result:?}"
        );
        assert!(tree_state(&setup.state).is_empty());
    }

    #[test]
    fn test_direct_merkle_insert_blocked_by_authorization() {
        let mut setup = setup_or_skip();
        let before = tree_state(&setup.state);
        let tx = public_tx(
            &setup.state,
            tree_actor(&TREE_ID, MERKLE_ID),
            vec![tree_actor(&TREE_ID, MERKLE_ID)],
            Vec::new(),
            MerkleMessage::Insert {
                leaf: valid_field_element(0x42),
            },
            &[],
        );
        let result = setup.apply(&tx);
        assert!(
            matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
            "direct merkle insert must fail in the guest: tree_main is not authorized, got {result:?}"
        );
        assert_eq!(tree_state(&setup.state), before);
    }

    // ====================================================================
    // Initialization
    // ====================================================================

    #[test]
    fn test_registration_init_succeeds() {
        let setup = setup_or_skip();
        assert!(!config_bytes(&setup.state).is_empty());
        assert!(!tree_state(&setup.state).is_empty());
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
            "config state must be exactly CONFIG_SIZE bytes"
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
        assert_eq!(u64_at(CONFIG_OFFSET_MIN_RATE_LIMIT), DEFAULT_MIN_RATE_LIMIT);
        assert_eq!(u64_at(CONFIG_OFFSET_MAX_RATE_LIMIT), DEFAULT_MAX_RATE_LIMIT);
    }

    #[test]
    fn test_registration_init_creates_tree_main() {
        let setup = setup_or_skip();
        let tree = tree_state(&setup.state);

        assert_eq!(
            tree.len(),
            OFFSET_TREE_DATA,
            "a fresh tree is the header plus cached defaults, with no sparse map yet"
        );
        let header = tree_header(&setup.state);
        assert_eq!(header.depth as usize, TREE_DEPTH);
        assert_eq!(header.next_index, 0);
        assert_eq!(
            header.root,
            cached_defaults(&tree)[0],
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
            (DEFAULT_MIN_RATE_LIMIT, DEFAULT_MAX_RATE_LIMIT),
        );
        assert!(
            setup.apply(&reinit).is_err(),
            "Initialize must refuse a config state that already holds data"
        );
        assert_eq!(config_bytes(&setup.state), config_before);
    }

    /// `TREE_ID` is written out as a constant; this is what it stands for.
    #[test]
    fn the_test_tree_is_the_owners() {
        let (_, owner_id) = owner();
        assert_eq!(TREE_LABEL, label_seed("state-tests"));
        assert_eq!(TREE_ID, owner_tree_id(owner_id.value(), &TREE_LABEL));
    }

    /// Programs deployed and the treasury existing: nothing initialized.
    fn bare_state() -> (V03State, AccountId) {
        let (_, treasury_id) = keypair(1);
        let state = state_with_programs()
            .expect("programs should load")
            .with_empty_public_accounts([treasury_id]);
        (state, treasury_id)
    }

    fn default_initialize(treasury_id: &AccountId) -> Message {
        initialize_msg(
            treasury_id,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
            (DEFAULT_MIN_RATE_LIMIT, DEFAULT_MAX_RATE_LIMIT),
        )
    }

    /// The config is reached by the program's own sync message, which
    /// carries the PDA's seed: that admits it, with no evidence from the
    /// transaction.
    #[test]
    fn initialize_admits_the_config_without_evidence() {
        let (mut state, treasury_id) = bare_state();
        let (owner_key, owner_id) = owner();
        let tx = public_tx(
            &state,
            owner_actor(&owner_id),
            vec![owner_actor(&owner_id), config_actor(&TREE_ID)],
            Vec::new(),
            default_initialize(&treasury_id),
            &[&owner_key],
        );
        state
            .transition_from_public_transaction(&tx, 1, GENESIS_TIMESTAMP_MS)
            .expect("the owner's Initialize should succeed");
        assert_eq!(config(&state).tree_id, TREE_ID);
    }

    /// SECURITY (registry squatting): `Initialize` used to go straight to the
    /// config, unsigned, so whoever knew a tree id could initialize it first
    /// with a treasury and a merkle program of their own. A config is a PDA:
    /// nothing signs for it, and the program now refuses the route.
    #[test]
    fn an_unsigned_initialize_at_the_config_is_refused() {
        let (mut state, treasury_id) = bare_state();
        let tx = public_tx(
            &state,
            config_actor(&TREE_ID),
            vec![config_actor(&TREE_ID)],
            vec![pda_evidence(config_seed(&TREE_ID))],
            default_initialize(&treasury_id),
            &[],
        );
        let result = state.transition_from_public_transaction(&tx, 1, GENESIS_TIMESTAMP_MS);
        assert!(
            matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
            "an unsigned Initialize must fail in the guest, got {result:?}"
        );
        assert!(config_bytes(&state).is_empty());
    }

    /// The owner's account without the owner's signature is anybody's
    /// message: naming the account is not enough.
    #[test]
    fn initialize_at_the_owners_account_needs_its_signature() {
        let (_, treasury_id) = keypair(1);
        let (_, owner_id) = owner();
        // The owner exists on chain, so admission is not what refuses it.
        let mut state = state_with_programs()
            .expect("programs should load")
            .with_empty_public_accounts([treasury_id, owner_id]);
        let tx = public_tx(
            &state,
            owner_actor(&owner_id),
            vec![owner_actor(&owner_id), config_actor(&TREE_ID)],
            vec![pda_evidence(config_seed(&TREE_ID))],
            default_initialize(&treasury_id),
            &[],
        );
        let result = state.transition_from_public_transaction(&tx, 1, GENESIS_TIMESTAMP_MS);
        assert!(
            matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
            "Initialize without the owner's signature must fail in the guest, got {result:?}"
        );
        assert!(config_bytes(&state).is_empty());
    }

    /// SECURITY (registry squatting): another account signing the same label
    /// gets a registry of its own, at another tree id. It cannot write the
    /// owner's config, and the owner's registry is still there to initialize.
    #[test]
    fn another_account_cannot_take_the_owners_tree() {
        let (mut state, treasury_id) = bare_state();
        let (squatter_key, squatter_id) = keypair(7);
        let (_, squatter_treasury) = keypair(8);
        let squatter_tree = owner_tree_id(squatter_id.value(), &TREE_LABEL);
        assert_ne!(squatter_tree, TREE_ID);

        // Aimed at the owner's config: the program forwards to the
        // squatter's own, which this transaction does not declare.
        let aimed = signed_init_tx(
            &state,
            &squatter_key,
            &TREE_ID,
            default_initialize(&squatter_treasury),
        );
        let result = state.transition_from_public_transaction(&aimed, 1, GENESIS_TIMESTAMP_MS);
        assert!(
            result.is_err(),
            "a stranger's Initialize must not reach the owner's config, got {result:?}"
        );
        assert!(config_bytes(&state).is_empty());

        // Declared honestly, it initializes the squatter's own registry.
        let own = signed_init_tx(
            &state,
            &squatter_key,
            &squatter_tree,
            default_initialize(&squatter_treasury),
        );
        state
            .transition_from_public_transaction(&own, 1, GENESIS_TIMESTAMP_MS)
            .expect("anyone may initialize a registry of their own");
        let theirs: rln_layouts::ConfigState =
            borsh::from_slice(&actor_state(&state, config_actor(&squatter_tree)))
                .expect("config state decodes");
        assert_eq!(theirs.tree_id, squatter_tree);
        assert_eq!(theirs.treasury_account_id, *squatter_treasury.value());
        assert!(config_bytes(&state).is_empty());

        // The owner's registry is untouched and still the owner's to make.
        let (owner_key, _) = owner();
        let honest = signed_init_tx(
            &state,
            &owner_key,
            &TREE_ID,
            default_initialize(&treasury_id),
        );
        state
            .transition_from_public_transaction(&honest, 1, GENESIS_TIMESTAMP_MS)
            .expect("the owner's Initialize should succeed");
        assert_eq!(config(&state).treasury_account_id, *treasury_id.value());
    }

    /// One owner, two labels: two registries on the same programs.
    #[test]
    fn one_owner_holds_a_registry_per_label() {
        let (mut state, treasury_id) = bare_state();
        let (owner_key, owner_id) = owner();
        let other_label = label_seed("mix");
        let other_tree = owner_tree_id(owner_id.value(), &other_label);
        for (label, tree_id) in [(TREE_LABEL, TREE_ID), (other_label, other_tree)] {
            let message = with_field!(
                default_initialize(&treasury_id),
                Initialize { tree_label: label }
            );
            let tx = signed_init_tx(&state, &owner_key, &tree_id, message);
            state
                .transition_from_public_transaction(&tx, 1, GENESIS_TIMESTAMP_MS)
                .expect("Initialize should succeed");
        }
        assert_eq!(config(&state).tree_id, TREE_ID);
        let other: rln_layouts::ConfigState =
            borsh::from_slice(&actor_state(&state, config_actor(&other_tree)))
                .expect("config state decodes");
        assert_eq!(other.tree_id, other_tree);
    }

    /// SECURITY (callee substitution): the config messages the merkle program
    /// it stores, and grants the tree's PDA to that one alone. A transaction
    /// declaring another copy of the merkle program gets nothing.
    #[test]
    fn test_init_merkle_messages_only_the_configured_program() {
        let mut setup = setup_config_only(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
        .expect("programs should load");

        // A tree_id whose config was never initialized has no config to act.
        let orphan_tree = [0x99u8; 32];
        let orphan = init_tree_tx(&setup.state, &orphan_tree, MERKLE_ID);
        assert!(
            setup.apply(&orphan).is_err(),
            "InitializeMerkleTree without an initialized config must fail"
        );

        // A real merkle program, deployed, but not the configured one: the
        // config's message goes to the configured program's actor, which the
        // transaction did not declare.
        let rogue = init_tree_tx(&setup.state, &TREE_ID, ROGUE_MERKLE_ID);
        assert!(
            setup.apply(&rogue).is_err(),
            "InitializeMerkleTree declaring an unconfigured merkle program must fail"
        );
        assert!(
            actor_state(&setup.state, tree_actor(&TREE_ID, ROGUE_MERKLE_ID)).is_empty(),
            "the rogue program must not have been granted the tree account"
        );
        assert!(tree_state(&setup.state).is_empty());

        // Positive control: the configured program is accepted.
        let honest = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        setup
            .apply(&honest)
            .expect("the configured merkle program is accepted");
        assert_eq!(tree_header(&setup.state).next_index, 0);
    }

    /// SECURITY (tree reset): replaying InitializeMerkleTree must not reset a
    /// live tree. Public transactions need no signature, so the merkle
    /// program's empty-state check is the only thing between anyone and a
    /// tree wipe that would invalidate every member's proof while their
    /// memberships survive.
    #[test]
    fn test_initialize_merkle_tree_cannot_reset_a_live_tree() {
        let mut setup = setup_or_skip();
        register(&mut setup, valid_field_element(0x42), 300);

        let before = tree_state(&setup.state);
        assert_eq!(tree_header(&setup.state).next_index, 1);

        let attack = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        let result = setup.apply(&attack);
        assert!(
            result.is_err(),
            "re-initializing a live tree must fail, got {result:?}"
        );
        assert_eq!(
            tree_state(&setup.state),
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
        let tx = register_tx(&setup, register_msg(&setup, valid_field_element(0x42), 300));
        let result = setup.apply(&tx);
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
            actor_state(&setup.state, membership_actor(&TREE_ID, &id_commitment)).len(),
            MEMBERSHIP_SIZE
        );
        let m = membership(&setup.state, &id_commitment).expect("membership state exists");
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

    /// The tree state stores one sparse entry per populated node and nothing
    /// else, so a full tree is `TREE_SHARD_MAX_BYTES`, which `rln_layouts`
    /// const-asserts under its own `SHARD_MAX_BYTES`.
    #[test]
    fn tree_state_stores_exactly_the_populated_nodes() {
        let mut setup = setup_or_skip();
        let size = |nodes: usize| OFFSET_TREE_DATA + 2 + nodes * SPARSE_ENTRY_LEN;

        register(&mut setup, valid_field_element(0x41), 100);
        assert_eq!(
            tree_state(&setup.state).len(),
            size(TREE_DEPTH + 1),
            "one leaf stores exactly its root-to-leaf path"
        );

        // Leaf 1 shares every ancestor with leaf 0: one new node.
        register(&mut setup, valid_field_element(0x42), 100);
        assert_eq!(tree_state(&setup.state).len(), size(TREE_DEPTH + 2));
        assert_eq!(size(rln_layouts::TREE_NODES), TREE_SHARD_MAX_BYTES);
    }

    /// `next_index` only advances, and an index past the last leaf aliases
    /// live nodes and produces a wrong root without failing. The merkle insert
    /// refuses it, and the whole registration with it.
    #[test]
    fn register_is_refused_once_every_leaf_index_is_used() {
        let mut setup = setup_or_skip();

        let mut data = tree_state(&setup.state);
        data[OFFSET_NEXT_INDEX..OFFSET_NEXT_INDEX + 8].copy_from_slice(&TREE_LEAVES.to_le_bytes());
        set_tree_state(&mut setup.state, data);

        let idc = valid_field_element(0xC2);
        let tx = register_tx(&setup, register_msg(&setup, idc, 100));
        assert_exit(
            setup.apply(&tx),
            EXIT_TREE_FULL,
            "a registration past the last leaf",
        );
        assert!(membership(&setup.state, &idc).is_none());
        assert_eq!(config(&setup.state).total_registrations, 0);
    }

    /// The config reaches the new membership by a sync message carrying its
    /// PDA seed, which admits it: a sender that can only name the account by
    /// id (a wallet module given plain account ids) can still register.
    #[test]
    fn register_admits_the_membership_without_evidence() {
        let mut setup = setup_or_skip();
        let id_commitment = valid_field_element(0x42);
        let msg = register_msg(&setup, id_commitment, 300);
        let tx = public_tx(
            &setup.state,
            config_actor(&TREE_ID),
            vec![
                config_actor(&TREE_ID),
                membership_actor(&TREE_ID, &id_commitment),
                tree_actor(&TREE_ID, MERKLE_ID),
                Actor::native_balance(setup.payer_id),
                Actor::native_balance(setup.treasury_id),
            ],
            vec![],
            msg,
            &[&setup.payer_key],
        );
        setup
            .apply(&tx)
            .expect("Register without admission evidence should succeed");
        assert!(membership(&setup.state, &id_commitment).is_some());
    }

    /// The membership init guard is the ONLY duplicate check: neither the
    /// register handler nor the merkle insert dedupes.
    #[test]
    fn test_register_same_commitment_twice_fails() {
        let mut setup = setup_or_skip();
        let id_commitment = valid_field_element(0x42);
        register(&mut setup, id_commitment, 300);

        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let tree_before = tree_state(&setup.state);
        let tx = register_tx(&setup, register_msg(&setup, id_commitment, 300));
        assert_exit(
            setup.apply(&tx),
            EXIT_MEMBERSHIP_EXISTS,
            "a second registration of the same id_commitment",
        );
        assert_eq!(tree_state(&setup.state), tree_before, "no second leaf");
        assert_eq!(native_balance(&setup.state, &setup.payer_id), payer_before);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    /// A registration that fails for any reason leaves no trace.
    fn assert_register_refused(
        setup: &mut TestSetup,
        tx: &PublicTransaction,
        idc: &[u8; 32],
        what: &str,
    ) {
        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let tree_before = tree_state(&setup.state);
        let config_before = config_bytes(&setup.state);

        let result = setup.apply(tx);
        assert!(
            result.is_err(),
            "register with {what} must fail, got {result:?}"
        );

        assert!(
            membership(&setup.state, idc).is_none(),
            "{what}: no membership"
        );
        assert_eq!(
            tree_state(&setup.state),
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

        let tx_a = register_tx(&setup, register_msg(&setup, idc_a, 100));
        let msg_b = with_field!(
            register_msg(&setup, idc_b, 200),
            Register {
                payer: *payer_b.value()
            }
        );
        let tx_b = register_tx_to(&setup.state, &key_b, &setup.treasury_id, MERKLE_ID, msg_b);

        setup.apply(&tx_a).expect("first registration of the block");
        setup
            .apply(&tx_b)
            .expect("second registration, built from the same state");

        let tree = tree_state(&setup.state);
        assert_eq!(tree_header(&setup.state).next_index, 2);
        assert_eq!(
            node_hash(&tree, TREE_DEPTH, 0),
            registration_leaf(&idc_a, 100)
        );
        assert_eq!(
            node_hash(&tree, TREE_DEPTH, 1),
            registration_leaf(&idc_b, 200)
        );
        assert_eq!(
            find_leaf_index(&tree, &registration_leaf(&idc_a, 100)),
            Some(0)
        );
        assert_eq!(
            find_leaf_index(&tree, &registration_leaf(&idc_b, 200)),
            Some(1)
        );
        assert_eq!(membership(&setup.state, &idc_a).unwrap().rate_limit, 100);
        assert_eq!(membership(&setup.state, &idc_b).unwrap().rate_limit, 200);
        let config = config(&setup.state);
        assert_eq!(config.total_registrations, 2);
        assert_eq!(config.current_total_rate_limit, 300);
    }

    /// The tree lives under the program the config stores; a transaction
    /// declaring another copy of the merkle program has not declared the
    /// actor the config messages.
    #[test]
    fn register_declaring_a_rogue_merkle_program_is_refused() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &setup.payer_key,
            &setup.treasury_id,
            ROGUE_MERKLE_ID,
            register_msg(&setup, idc, 300),
        );
        assert_register_refused(&mut setup, &tx, &idc, "an unconfigured merkle program");
        assert!(
            actor_state(&setup.state, tree_actor(&TREE_ID, ROGUE_MERKLE_ID)).is_empty(),
            "the rogue program must not have written the tree account"
        );
    }

    // ── chain time ──────────────────────────────────────────────────────
    //
    // `now_ms` dates the membership and pins the transaction to blocks whose
    // timestamp lies in `[now_ms, now_ms + CLOCK_CLAIM_TOLERANCE_MS)`.

    /// A register read just before a block and included some blocks later
    /// carries a `now_ms` behind the including block's timestamp. That is
    /// accepted up to the tolerance, and the membership is dated by the
    /// claim — earlier than the chain's time, which only shortens the
    /// member's own window.
    #[test]
    fn a_now_ms_behind_the_block_is_accepted_up_to_the_tolerance() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let read_at = setup.now_ms;
        let tx = register_tx(&setup, register_msg(&setup, idc, 300));
        setup.now_ms = read_at + 750_000;
        setup
            .apply(&tx)
            .expect("a claim twelve minutes behind the block is accepted");
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            read_at + ACTIVE_MS,
            "dated by the claim, not by the block"
        );

        // The window is half-open: the last admitted block is one
        // millisecond short of the tolerance.
        let idc = valid_field_element(0x43);
        let read_at = setup.now_ms;
        let tx = register_tx(&setup, register_msg(&setup, idc, 300));
        setup.now_ms = read_at + CLOCK_CLAIM_TOLERANCE_MS - 1;
        setup
            .apply(&tx)
            .expect("a claim just inside the tolerance is accepted");
    }

    /// A `now_ms` ahead of the block, or further behind it than the
    /// tolerance, puts the block outside the validity window: the
    /// transaction reverts and leaves nothing behind.
    #[test]
    fn a_now_ms_outside_the_window_is_refused() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let block = setup.now_ms;
        for (what, claim) in [
            ("1 ms ahead of the block", block + 1),
            (
                "exactly the tolerance behind",
                block - CLOCK_CLAIM_TOLERANCE_MS,
            ),
            (
                "a future that would lengthen the membership",
                block + ACTIVE_MS,
            ),
        ] {
            let msg = with_field!(register_msg(&setup, idc, 300), Register { now_ms: claim });
            let tx = register_tx(&setup, msg);
            assert_register_refused(&mut setup, &tx, &idc, what);
        }
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
        let tx = slash_tx(&setup.state, slash_msg(&setup.state, secret, idc));
        setup.apply(&tx)
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
            actor_state(&setup.state, membership_actor(&TREE_ID, &idc)).is_empty(),
            "the membership state is cleared"
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
        // The index as a slasher would guess it (the membership is gone).
        let msg = Message::Slash {
            tree_id: TREE_ID,
            id_commitment: idc,
            identity_secret: secret,
            leaf_index: 0,
        };
        let tx = slash_tx(&setup.state, msg);
        assert!(setup.apply(&tx).is_err(), "double slash must fail");
    }

    /// The leaf a slash removes is the membership's, not the caller's pick:
    /// naming another member's leaf index must not evict that member. The
    /// index is a hint the merkle program checks by content.
    #[test]
    fn slash_rejects_another_members_leaf_index() {
        let mut setup = setup_or_skip();
        register(&mut setup, valid_field_element(0x01), 100);
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let tree_before = tree_state(&setup.state);
        let msg = with_field!(
            slash_msg(&setup.state, secret, idc),
            Slash { leaf_index: 0 }
        );
        let tx = slash_tx(&setup.state, msg);
        assert_exit(
            setup.apply(&tx),
            EXIT_LEAF_MISMATCH,
            "another member's leaf",
        );
        assert_eq!(tree_state(&setup.state), tree_before, "tree untouched");
        assert!(membership(&setup.state, &idc).is_some(), "membership kept");
    }

    /// Slashing clears the membership state, so the init guard no longer
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
            node_hash(&tree_state(&setup.state), TREE_DEPTH, 0),
            [0; 32],
            "the old leaf stays zeroed"
        );
        assert_eq!(tree_header(&setup.state).next_index, 2);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    /// Slash and erase name a leaf index the caller found by scanning; the
    /// merkle program removes it only if it holds `H(id_commitment,
    /// rate_limit)` with the membership's own rate limit. Any other index
    /// fails the whole transaction and changes nothing.
    #[test]
    fn remove_refuses_a_wrong_index() {
        let mut setup = setup_or_skip();
        let (_, idc_a) = slashable_identity(0x41);
        let (secret_b, idc_b) = slashable_identity(0x42);
        register(&mut setup, idc_a, 100);
        register(&mut setup, idc_b, 300);
        assert_eq!(leaf_index_of(&setup.state, &idc_a), Some(0));
        assert_eq!(leaf_index_of(&setup.state, &idc_b), Some(1));
        let leaf_a = registration_leaf(&idc_a, 100);

        // Erase becomes legal once both have expired; slash is always legal.
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;

        let tree_before = tree_state(&setup.state);
        let config_before = config_bytes(&setup.state);
        let membership_a_before = actor_state(&setup.state, membership_actor(&TREE_ID, &idc_a));
        let membership_b_before = actor_state(&setup.state, membership_actor(&TREE_ID, &idc_b));

        let slash_b = slash_msg(&setup.state, secret_b, idc_b);
        let erase_b = erase_msg(&setup, idc_b);
        let bad: Vec<(&str, PublicTransaction)> = vec![
            (
                "slash at A's index",
                slash_tx(
                    &setup.state,
                    with_field!(slash_b.clone(), Slash { leaf_index: 0 }),
                ),
            ),
            (
                "slash past next_index",
                slash_tx(
                    &setup.state,
                    with_field!(slash_b.clone(), Slash { leaf_index: 2 }),
                ),
            ),
            (
                "erase at A's index",
                erase_tx(&setup.state, with_field!(erase_b, Erase { leaf_index: 0 })),
            ),
        ];
        for (what, tx) in bad {
            assert_exit(setup.apply(&tx), EXIT_LEAF_MISMATCH, what);
            assert_eq!(
                tree_state(&setup.state),
                tree_before,
                "{what}: tree untouched"
            );
            assert_eq!(
                config_bytes(&setup.state),
                config_before,
                "{what}: config untouched"
            );
            assert_eq!(
                actor_state(&setup.state, membership_actor(&TREE_ID, &idc_a)),
                membership_a_before,
                "{what}: A untouched"
            );
            assert_eq!(
                actor_state(&setup.state, membership_actor(&TREE_ID, &idc_b)),
                membership_b_before,
                "{what}: B untouched"
            );
        }

        // The right index: exactly B's leaf is zeroed.
        let tx = slash_tx(&setup.state, slash_b);
        setup.apply(&tx).expect("slash at B's index");
        let tree_after = tree_state(&setup.state);
        assert_eq!(
            node_hash(&tree_after, TREE_DEPTH, 0),
            leaf_a,
            "A's leaf kept"
        );
        assert_eq!(
            node_hash(&tree_after, TREE_DEPTH, 1),
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
        assert_eq!(node_hash(&tree_state(&setup.state), TREE_DEPTH, 0), [0; 32]);
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

        let tx = register_tx(&setup, register_msg(&setup, valid_field_element(0x02), 300));
        assert!(
            setup.apply(&tx).is_err(),
            "a registration past max_total_rate_limit must fail"
        );
        assert_eq!(config(&setup.state).current_total_rate_limit, 300);
    }

    /// The bounds are the registry's own: a 20..=100 registry on the same
    /// programs as a 100..=600 one admits 20 and refuses 101.
    #[test]
    fn test_rate_limit_bounds_are_per_registry_config() {
        let Some(mut setup) = setup_with_bounds(20, 100) else {
            setup_or_skip();
            unreachable!()
        };
        assert_eq!(config(&setup.state).min_rate_limit, 20);
        assert_eq!(config(&setup.state).max_rate_limit, 100);
        register(&mut setup, valid_field_element(0x01), 20);
        register(&mut setup, valid_field_element(0x02), 100);
        assert_eq!(config(&setup.state).current_total_rate_limit, 120);

        for (seed, rate) in [(0x03, 19), (0x04, 101)] {
            let tx = register_tx(
                &setup,
                register_msg(&setup, valid_field_element(seed), rate),
            );
            assert!(
                setup.apply(&tx).is_err(),
                "a registration at {rate} outside 20..=100 must fail"
            );
        }
        assert_eq!(config(&setup.state).current_total_rate_limit, 120);
        assert_eq!(config(&setup.state).total_registrations, 2);
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
    // The price moves by a message to the payer's native actor, which refuses
    // an unauthorized sender and an insufficient balance, and credits the
    // config's treasury asynchronously — in the same transaction only when
    // the treasury's native actor is declared.

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

    /// SECURITY (payment routing): the price goes to the treasury the config
    /// stores, whatever the transaction declares. Declaring someone else's
    /// native actor in its place leaves the real credit undeliverable, and
    /// the transaction fails without moving anything.
    #[test]
    fn register_fails_when_the_configured_treasury_is_not_declared() {
        let mut setup = setup_or_skip();
        let (_, attacker_treasury) = keypair(9);
        assert_ne!(attacker_treasury, setup.treasury_id);
        fund_native(&mut setup.state, &attacker_treasury, 1);

        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &setup.payer_key,
            &attacker_treasury,
            MERKLE_ID,
            register_msg(&setup, idc, 300),
        );
        let result = setup.apply(&tx);
        assert!(
            result.is_err(),
            "a transaction not declaring the treasury must be refused; got {result:?}"
        );
        assert_eq!(native_balance(&setup.state, &attacker_treasury), 1);
        assert_eq!(native_balance(&setup.state, &setup.treasury_id), 0);
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert!(membership(&setup.state, &idc).is_none());
    }

    /// The treasury must exist on chain (or be a signer, or carry evidence)
    /// to be declared: `run_setup` seeds it for that reason.
    #[test]
    fn register_fails_when_the_treasury_has_never_existed() {
        let (_, treasury_id) = keypair(1);
        let (payer_key, payer_id) = keypair(2);
        let mut state = state_with_programs().expect("programs should load");
        fund_native(&mut state, &payer_id, DEFAULT_PAYER_BALANCE);
        let mut setup = TestSetup {
            state,
            treasury_id,
            payer_id,
            payer_key,
            now_ms: GENESIS_TIMESTAMP_MS,
        };
        let tx = init_config_tx(
            &setup.state,
            &treasury_id,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
            (DEFAULT_MIN_RATE_LIMIT, DEFAULT_MAX_RATE_LIMIT),
        );
        setup.apply(&tx).expect("Initialize");
        let tx = init_tree_tx(&setup.state, &TREE_ID, MERKLE_ID);
        setup.apply(&tx).expect("InitializeMerkleTree");

        let idc = valid_field_element(0x42);
        let tx = register_tx(&setup, register_msg(&setup, idc, 300));
        assert_register_refused(&mut setup, &tx, &idc, "an unadmitted treasury");
    }

    /// The payer is named but does not sign: its native actor is not
    /// authorized to be debited.
    #[test]
    fn register_rejects_an_unauthorized_payer() {
        let mut setup = setup_or_skip();
        let (other_key, other_id) = keypair(7);
        fund_native(&mut setup.state, &other_id, DEFAULT_PAYER_BALANCE);

        // `other` signs, but the message names `setup.payer`.
        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &other_key,
            &setup.treasury_id,
            MERKLE_ID,
            register_msg(&setup, idc, 300),
        );
        assert!(
            setup.apply(&tx).is_err(),
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
        let tx = register_tx(&setup, register_msg(&setup, idc, 300));
        assert!(setup.apply(&tx).is_err(), "one unit short must be refused");
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
            config_actor(&TREE_ID),
            tree_actor(&TREE_ID, MERKLE_ID),
            Actor::native_balance(setup.payer_id),
            Actor::native_balance(setup.treasury_id),
            membership_actor(&TREE_ID, &idc),
        ]
        .iter()
        .map(|a| a.account_id)
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
    fn failure_and_charge(setup: &TestSetup, tx: &PublicTransaction) -> (LeeError, u64) {
        let err = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            &setup.state,
            1,
            setup.now_ms,
            MAX_GAS_EXEC,
        )
        .err()
        .expect("the transaction should fail");
        let (charge, settled) = nssa::ValidatedStateDiff::from_public_transaction_metered(
            tx,
            &setup.state,
            1,
            setup.now_ms,
            MAX_GAS_EXEC,
        );
        assert!(
            settled.is_ok(),
            "a chargeable failure settles as nonce bumps, got {:?}",
            settled.err()
        );
        assert!(
            charge.revert.is_some(),
            "a chargeable failure is marked reverted"
        );
        (err, charge.cycles)
    }

    /// A view that went stale because the chain moved (here: the member
    /// registered meanwhile) halts the guest with an exit code, and is
    /// charged the cycles that ran — the config session's leaf Poseidon plus
    /// the membership session — not the declared gas. A malformed message
    /// still panics and pays the full budget.
    #[test]
    fn a_stale_view_is_charged_measured_cycles() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        register(&mut setup, idc, 100);

        let duplicate = register_tx(&setup, register_msg(&setup, idc, 100));
        let (err, charged) = failure_and_charge(&setup, &duplicate);
        println!(
            "duplicate registration: {err:?} ({}), charged {charged} cycles ({:.1}% of MAX_GAS_EXEC)",
            exit_code_name(u32::from(EXIT_MEMBERSHIP_EXISTS)).unwrap(),
            charged as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            matches!(err, LeeError::ProgramExitedWithCode { code, .. } if code == u32::from(EXIT_MEMBERSHIP_EXISTS)),
            "got {err:?}"
        );
        assert!(
            charged < 1_200_000,
            "a stale view must not pay the ceiling: {charged}"
        );

        let malformed = register_tx(
            &setup,
            register_msg(
                &setup,
                valid_field_element(0x43),
                DEFAULT_MAX_RATE_LIMIT + 1,
            ),
        );
        let (err, charged) = failure_and_charge(&setup, &malformed);
        assert!(
            matches!(err, LeeError::ProgramExecutionFailed(_)),
            "got {err:?}"
        );
        assert_eq!(
            charged, MAX_GAS_EXEC,
            "a malformed message still pays the full budget"
        );
    }

    /// A whole register transaction — the config, membership and merkle
    /// sessions — against the ceiling that rejects it
    /// (`fee_core::market::MAX_GAS_EXEC`, one gas per cycle). Printed: the
    /// margin is what says whether a deeper tree fits.
    #[test]
    fn register_transaction_fits_the_gas_ceiling() {
        let setup = setup_or_skip();
        let tx = register_tx(&setup, register_msg(&setup, valid_field_element(0x42), 100));

        let used = whole_tx_cycles(&setup, &tx);
        println!(
            "register transaction: {used} cycles ({:.1}% of MAX_GAS_EXEC), tree depth {TREE_DEPTH}",
            used as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            used <= MAX_GAS_EXEC,
            "register costs {used} cycles against {MAX_GAS_EXEC}"
        );
    }

    /// Slash and erase hash the member's leaf (the merkle `Remove` checks it
    /// by content) on top of a nine-level root update, so they cost about one
    /// Poseidon more than a register.
    #[test]
    fn slash_and_erase_transactions_fit_the_gas_ceiling() {
        let mut setup = setup_or_skip();
        let (secret, idc) = slashable_identity(0x42);
        register(&mut setup, idc, 100);

        let slash = whole_tx_cycles(
            &setup,
            &slash_tx(&setup.state, slash_msg(&setup.state, secret, idc)),
        );
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;
        let erase = whole_tx_cycles(&setup, &erase_tx(&setup.state, erase_msg(&setup, idc)));
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

        let proof = merkle_proof(&tree_state(&setup.state), 0);
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
        let proof = merkle_proof(&tree_state(&setup.state), leaf_index);
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

        let proof = merkle_proof(&tree_state(&setup.state), 0);
        assert_ne!(proof.root, root_registered, "the root moved");
        assert_ne!(proof.leaf, rate_commitment(&idc, 300), "the leaf is gone");
        assert_eq!(proof.root, empty_root, "back to the empty root");
    }

    #[test]
    fn test_rln_double_message_detection() {
        let mut setup = setup_or_skip();
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[0x99; 32]);
        register(&mut setup, fr_to_bytes_le(&keys.id_commitment()), 300);

        let (merkle_proof, root) = circuit_proof(&merkle_proof(&tree_state(&setup.state), 0));
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
        let msg = extend_msg(setup, &setup.payer_id, idc);
        let tx = extend_tx(setup, &setup.payer_key, msg);
        setup.apply(&tx)
    }

    fn erase(setup: &mut TestSetup, idc: [u8; 32]) -> Result<(), nssa::error::LeeError> {
        let tx = erase_tx(&setup.state, erase_msg(setup, idc));
        setup.apply(&tx)
    }

    /// Registered at `GENESIS_TIMESTAMP_MS`.
    fn registered_at_genesis(seed: u8) -> (TestSetup, [u8; 32]) {
        let mut setup = setup_or_skip();
        setup.now_ms = GENESIS_TIMESTAMP_MS;
        let idc = valid_field_element(seed);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        (setup, idc)
    }

    #[test]
    fn test_register_snapshots_grace_period_start() {
        let mut setup = setup_or_skip();
        let at = GENESIS_TIMESTAMP_MS + 500;
        setup.now_ms = at;
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
        setup.now_ms = t0;
        let idc = valid_field_element(0xB1);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            t0 + 30 * DAY_MS
        );

        setup.now_ms = t0 + 29 * DAY_MS;
        assert!(extend(&mut setup, idc).is_err(), "still active on day 29");

        setup.now_ms = t0 + 31 * DAY_MS;
        extend(&mut setup, idc).expect("in grace on day 31");
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            t0 + (30 + 7 + 30) * DAY_MS,
            "extend adds one grace + one active period"
        );

        setup.now_ms = t0 + 75 * DAY_MS;
        erase(&mut setup, idc).expect("expired by day 75");
        assert!(membership(&setup.state, &idc).is_none());
    }

    #[test]
    fn test_extend_succeeds_in_grace_period() {
        let (mut setup, idc) = registered_at_genesis(0xA2);
        let grace_start = GENESIS_TIMESTAMP_MS + ACTIVE_MS;
        setup.now_ms = grace_start + GRACE_MS / 2;
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
        setup.now_ms = GENESIS_TIMESTAMP_MS + 10;
        assert!(extend(&mut setup, idc).is_err());
    }

    #[test]
    fn test_extend_fails_when_expired() {
        let (mut setup, idc) = registered_at_genesis(0xA4);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;
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
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;

        let treasury_before = native_balance(&setup.state, &setup.treasury_id);
        let owner_before = native_balance(&setup.state, &setup.payer_id);
        let msg = extend_msg(&setup, &third_id, idc);
        let tx = extend_tx(&setup, &third_key, msg);
        setup.apply(&tx).expect("a paying third party may renew");

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

    /// SECURITY (renewal is priced): the price moves from the account the
    /// message names as payer, and only its own signature authorizes that
    /// debit — the config's `ChargeRenewal` carries no grant. A renewal naming
    /// a payer who did not sign is refused and nothing moves.
    #[test]
    fn extend_rejects_an_unauthorized_payer() {
        let (mut setup, idc) = registered_at_genesis(0xA8);
        let (other_key, other_id) = keypair(7);
        fund_native(&mut setup.state, &other_id, DEFAULT_PAYER_BALANCE);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        let before = membership(&setup.state, &idc)
            .unwrap()
            .grace_period_start_timestamp_ms;

        // `other` signs; the message names `setup.payer`.
        let msg = extend_msg(&setup, &setup.payer_id, idc);
        let tx = extend_tx(&setup, &other_key, msg);
        assert!(
            setup.apply(&tx).is_err(),
            "a payer that did not sign must not be debited for a renewal"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE - u128::from(EXP_RATE_LIMIT) * PRICE_PER_UNIT
        );
        assert_eq!(
            native_balance(&setup.state, &other_id),
            DEFAULT_PAYER_BALANCE
        );
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            before,
            "not renewed"
        );
    }

    #[test]
    fn test_extend_fails_when_payer_cannot_cover_the_price() {
        let (mut setup, idc) = registered_at_genesis(0xA7);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        let payer = setup.payer_id;
        fund_native(&mut setup.state, &payer, 0);
        assert!(
            extend(&mut setup, idc).is_err(),
            "an unfunded renewal must fail"
        );
    }

    /// A renewal dated ahead of the block is outside its validity window.
    #[test]
    fn extend_rejects_a_now_ms_ahead_of_chain_time() {
        let (mut setup, idc) = registered_at_genesis(0xA9);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        let before = membership(&setup.state, &idc)
            .unwrap()
            .grace_period_start_timestamp_ms;
        let payer_before = native_balance(&setup.state, &setup.payer_id);

        let msg = with_field!(
            extend_msg(&setup, &setup.payer_id, idc),
            Extend {
                now_ms: GENESIS_TIMESTAMP_MS + ACTIVE_MS + 2
            }
        );
        let tx = extend_tx(&setup, &setup.payer_key, msg);
        assert!(
            setup.apply(&tx).is_err(),
            "extend with a now_ms ahead of the block must fail"
        );
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            before
        );
        assert_eq!(native_balance(&setup.state, &setup.payer_id), payer_before);
    }

    #[test]
    fn test_erase_succeeds_when_expired() {
        let (mut setup, idc) = registered_at_genesis(0xA6);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;
        erase(&mut setup, idc).expect("erase of an expired membership");
        assert!(membership(&setup.state, &idc).is_none());
    }

    #[test]
    fn test_erase_fails_when_active() {
        let (mut setup, idc) = registered_at_genesis(0xA7);
        setup.now_ms = GENESIS_TIMESTAMP_MS + 1;
        assert!(erase(&mut setup, idc).is_err());
    }

    #[test]
    fn test_erase_fails_in_grace_period() {
        let (mut setup, idc) = registered_at_genesis(0xA8);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        assert!(erase(&mut setup, idc).is_err());
    }

    #[test]
    fn test_erase_decrements_total_rate_limit() {
        let (mut setup, idc) = registered_at_genesis(0xAA);
        assert_eq!(
            config(&setup.state).current_total_rate_limit,
            EXP_RATE_LIMIT
        );
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;
        erase(&mut setup, idc).expect("erase");
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
    }

    /// Erase removes the leaf the MEMBERSHIP records: pointing it at another
    /// member's leaf must not evict that member.
    #[test]
    fn erase_rejects_another_members_leaf_index() {
        let mut setup = setup_or_skip();
        register(&mut setup, valid_field_element(0x01), 100);
        let idc = valid_field_element(0xAB);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;

        let tree_before = tree_state(&setup.state);
        let msg = with_field!(erase_msg(&setup, idc), Erase { leaf_index: 0 });
        let tx = erase_tx(&setup.state, msg);
        assert_exit(
            setup.apply(&tx),
            EXIT_LEAF_MISMATCH,
            "another member's leaf",
        );
        assert_eq!(tree_state(&setup.state), tree_before, "tree untouched");
        assert!(membership(&setup.state, &idc).is_some(), "membership kept");
    }

    /// Erase clears the membership state, so the commitment can register again.
    #[test]
    fn an_erased_commitment_can_register_again() {
        let (mut setup, idc) = registered_at_genesis(0xAC);
        setup.now_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1;
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
