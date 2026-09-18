//! State-level tests for RLN Registration and Merkle Tree programs.
//!
//! These tests verify program loading and state transitions using the public nssa API.
//!
//! # Prerequisites
//!
//! Compile the guest programs first:
//! ```bash
//! cargo risczero build --manifest-path methods/guest/Cargo.toml
//! ```
//!
//! # Running Tests
//!
//! ```bash
//! RISC0_DEV_MODE=1 cargo test -p logos-lez-rln --lib state_tests
//! ```
//!
//! # Test Categories
//!
//! 1. **Program Loading Tests**: Verify programs load and have correct IDs
//! 2. **PDA Derivation Tests**: Verify deterministic account address derivation
//! 3. **Instruction Building Tests**: Verify correct instruction serialization
//! 4. **State Setup Helpers**: Deploy programs and initialize state
//! 5. **Full Flow Tests**: Execute transactions and verify state changes

#[cfg(test)]
mod tests {
    #[cfg(feature = "rc5-state-tests-privacy")]
    use std::collections::HashMap;
    use std::fs;

    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa::privacy_preserving_transaction::{
        circuit::ProgramWithDependencies, message::Message as PrivacyMessage,
        witness_set::WitnessSet as PrivacyWitnessSet,
    };
    // Privacy-preserving transaction types — only used by the privacy-flow
    // helpers/tests that are gated behind rc5-state-tests-privacy.
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa::{PrivacyPreservingTransaction, execute_and_prove};
    use nssa::{
        PrivateKey, PublicKey, PublicTransaction, V03State,
        program::Program,
        public_transaction::{Message, WitnessSet},
    };
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::account::AccountWithMetadata;
    use nssa_core::account::{Account, AccountId, Data, Nonce};
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::encryption::ViewingPublicKey;
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::{
        AuthorizationSecretKey, Commitment, DUMMY_COMMITMENT_HASH, Identifier, MembershipProof,
        NullifierPublicKey, NullifierSecretKey,
    };
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::{
        EncryptedAccountData, InputAccountIdentity, Nullifier, NullifierWitness, PrivateWitness,
        WitnessKind,
    };
    use token_core::TokenHolding;

    use crate::rln::Instruction;
    // Import shared constants and PDA functions from rln module
    use crate::rln::{
        CLOCK_50_ACCOUNT_ID_BYTES, CONFIG_OFFSET_ACTIVE_DURATION,
        CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT, CONFIG_OFFSET_GRACE_PERIOD_DURATION,
        CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT, CONFIG_OFFSET_MERKLE_PROGRAM_ID,
        CONFIG_OFFSET_PRICE_PER_UNIT, CONFIG_OFFSET_TOTAL_REGISTRATIONS,
        CONFIG_OFFSET_TREASURY_ACCOUNT_ID, CONFIG_OFFSET_TREE_ID, CONFIG_SIZE,
        MEMBERSHIP_OFFSET_ACTIVE_DURATION, MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION,
        MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP, MEMBERSHIP_OFFSET_ID_COMMITMENT,
        MEMBERSHIP_OFFSET_LEAF_INDEX, MEMBERSHIP_OFFSET_RATE_LIMIT, MEMBERSHIP_SIZE, TREE_DEPTH,
        derive_config_account, derive_membership_account, derive_subtree_account,
        derive_tree_main_account, subtree_id_for_index,
    };

    // ========================================================================
    // Program Paths
    // ========================================================================

    /// Get the repository root from CARGO_MANIFEST_DIR
    /// The manifest is at the repo root.
    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Directory holding the guest `.bin`s under test.
    ///
    /// Defaults to the `docker/` dir the deploy host reads, which doubles as
    /// the record of what is live on testnet — so testing a guest change there
    /// means overwriting the artifacts that `verify.sh` checks the deployment
    /// against. `LEZ_RLN_GUEST_DIR` points the suite at a fresh build instead
    /// (e.g. the `release/` dir `cargo build` writes) and leaves them alone.
    fn guest_binary_dir() -> std::path::PathBuf {
        match std::env::var_os("LEZ_RLN_GUEST_DIR") {
            Some(dir) => std::path::PathBuf::from(dir),
            None => repo_root().join("methods/guest/target/riscv32im-risc0-zkvm-elf/docker"),
        }
    }

    fn merkle_tree_binary_path() -> std::path::PathBuf {
        guest_binary_dir().join("incremental_merkle_tree.bin")
    }

    fn rln_registration_binary_path() -> std::path::PathBuf {
        guest_binary_dir().join("rln_registration.bin")
    }

    // ========================================================================
    // Constants
    // ========================================================================

    /// Test tree ID (32 bytes; first 24 carry data, last 8 zero-padded for SPEL).
    const TREE_ID: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    // Test-specific constant
    const PRICE_PER_UNIT: u128 = 10_000;

    /// Genesis timestamp used when seeding test state. Chosen non-zero so that
    /// time-travel tests can reason about both past and future relative to genesis.
    const GENESIS_TIMESTAMP_MS: u64 = 1_700_000_000_000;

    /// Active-period length applied to newly registered memberships in tests
    /// (1 hour). Kept small so tests can exercise expiration without huge numbers.
    const DEFAULT_ACTIVE_DURATION_SEC: u32 = 3_600;

    /// Grace-period length applied to newly registered memberships in tests
    /// (10 minutes).
    const DEFAULT_GRACE_PERIOD_DURATION_SEC: u32 = 600;

    const ACTIVE_MS: u64 = rln_layouts::secs_to_millis(DEFAULT_ACTIVE_DURATION_SEC);
    const GRACE_MS: u64 = rln_layouts::secs_to_millis(DEFAULT_GRACE_PERIOD_DURATION_SEC);

    /// Returns a valid BN254 field element with `seed` in the lowest
    /// little-endian byte and zero-padding above. Used wherever a test needs a
    /// distinct, valid field element (id_commitment, identity_secret, ...).
    fn valid_field_element(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = seed;
        out
    }

    // ========================================================================
    // Program Loading
    // ========================================================================

    fn load_merkle_tree_program() -> Option<Program> {
        fs::read(merkle_tree_binary_path())
            .ok()
            .and_then(|bytecode| Program::new(bytecode.into()).ok())
    }

    fn load_rln_registration_program() -> Option<Program> {
        fs::read(rln_registration_binary_path())
            .ok()
            .and_then(|bytecode| Program::new(bytecode.into()).ok())
    }

    // ========================================================================
    // PDA Derivation Wrappers
    // ========================================================================

    fn derive_tree_main_pda(program_id: AccountId, tree_id: &[u8; 32]) -> AccountId {
        derive_tree_main_account(&program_id, tree_id)
    }

    fn derive_subtree_pda(program_id: AccountId, tree_id: &[u8; 32], subtree_id: u32) -> AccountId {
        derive_subtree_account(&program_id, tree_id, subtree_id)
    }

    fn derive_config_pda(program_id: AccountId, tree_id: &[u8; 32]) -> AccountId {
        derive_config_account(&program_id, tree_id)
    }

    fn derive_membership_pda(
        program_id: AccountId,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> AccountId {
        derive_membership_account(&program_id, tree_id, id_commitment)
    }

    // ========================================================================
    // State Setup Helpers
    // ========================================================================

    /// Creates a fresh state with both programs deployed.
    /// Returns (state, merkle_program, registration_program).
    fn state_with_programs() -> Option<(V03State, Program, Program)> {
        let merkle_bytecode = fs::read(merkle_tree_binary_path()).ok()?;
        let registration_bytecode = fs::read(rln_registration_binary_path()).ok()?;

        let merkle_program = Program::new(merkle_bytecode.clone().into()).ok()?;
        let registration_program = Program::new(registration_bytecode.clone().into()).ok()?;

        // rc6: V03State::new() replaces new_with_genesis_accounts(...). Seed
        // the builtin token + clock programs that registration init's chained
        // calls require, and seed the CLOCK_50 system account at the genesis
        // timestamp so the registration program's clock-reads succeed — both
        // were implicit in the rc5 genesis-accounts path.
        let mut state = V03State::new().with_programs([
            programs::token(),
            programs::clock(),
            merkle_program.clone(),
            registration_program.clone(),
        ]);
        set_clock_50(&mut state, GENESIS_TIMESTAMP_MS, 0);

        Some((state, merkle_program, registration_program))
    }

    /// Builds a public transaction for merkle tree initialization.
    fn build_merkle_init_tx(program: &Program, tree_id: &[u8; 32]) -> PublicTransaction {
        let tree_main_id =
            derive_tree_main_pda(crate::spel_seeds::program_account(&program.id()), tree_id);
        let instruction = vec![0u8]; // opcode 0 = init

        // PDA-only transaction: no nonces needed (accounts are program-derived)
        let message = Message::try_new(
            crate::spel_seeds::program_account(&program.id()),
            vec![tree_main_id],
            vec![], // Empty nonces for PDA-only transactions
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[]))
    }

    /// Builds a public transaction for merkle tree leaf insertion.
    ///
    /// Accounts: [tree_main, subtree] (subtree at index 1 for the merkle program).
    fn build_merkle_insert_tx(
        program: &Program,
        tree_id: &[u8; 32],
        expected_index: u64,
        leaf_value: [u8; 32],
    ) -> PublicTransaction {
        let tree_main_id =
            derive_tree_main_pda(crate::spel_seeds::program_account(&program.id()), tree_id);
        let sid = subtree_id_for_index(expected_index);
        let subtree_id = derive_subtree_pda(
            crate::spel_seeds::program_account(&program.id()),
            tree_id,
            sid,
        );

        let mut instruction = vec![1u8]; // opcode 1 = insert
        instruction.extend_from_slice(&expected_index.to_le_bytes());
        instruction.extend_from_slice(&leaf_value);

        // PDA-only transaction: no nonces needed (accounts are program-derived)
        let message = Message::try_new(
            crate::spel_seeds::program_account(&program.id()),
            vec![tree_main_id, subtree_id],
            vec![], // Empty nonces for PDA-only transactions
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[]))
    }

    // ========================================================================
    // Program Loading Tests
    // ========================================================================

    #[test]
    fn test_merkle_tree_program_loads() {
        let program = load_merkle_tree_program();
        assert!(
            program.is_some(),
            "Merkle tree program should load. Run: cargo risczero build --manifest-path methods/guest/Cargo.toml"
        );
    }

    #[test]
    fn test_rln_registration_program_loads() {
        let program = load_rln_registration_program();
        assert!(
            program.is_some(),
            "RLN registration program should load. Run: cargo risczero build --manifest-path methods/guest/Cargo.toml"
        );
    }

    // ========================================================================
    // PDA Derivation Tests
    // ========================================================================

    #[test]
    fn test_subtree_pdas_vary_by_id() {
        if let Some(program) = load_merkle_tree_program() {
            let subtree_0 = derive_subtree_pda(
                crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
                0,
            );
            let subtree_1 = derive_subtree_pda(
                crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
                1,
            );

            assert!(
                subtree_0 != subtree_1,
                "Different subtree IDs should have different PDAs"
            );
        }
    }

    #[test]
    fn test_all_registration_pdas_are_distinct() {
        if let Some(program) = load_rln_registration_program() {
            let tree_main =
                derive_tree_main_pda(crate::spel_seeds::program_account(&program.id()), &TREE_ID);
            let config =
                derive_config_pda(crate::spel_seeds::program_account(&program.id()), &TREE_ID);
            let membership = derive_membership_pda(
                crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
                &valid_field_element(0x42),
            );
            let subtree = derive_subtree_pda(
                crate::spel_seeds::program_account(&program.id()),
                &TREE_ID,
                0,
            );

            assert!(tree_main != config, "tree_main and config should differ");
            assert!(
                tree_main != membership,
                "tree_main and membership should differ"
            );
            assert!(tree_main != subtree, "tree_main and subtree should differ");
            assert!(config != membership, "config and membership should differ");
            assert!(config != subtree, "config and subtree should differ");
            assert!(
                membership != subtree,
                "membership and subtree should differ"
            );
        }
    }

    // ========================================================================
    // Authorization Tests (Architectural Constraint)
    // ========================================================================
    //
    // The merkle tree program requires authorization via `is_authorized` flag.
    // This authorization can only be set through chained calls from the
    // registration program. Direct calls to the merkle tree fail by design.
    //
    // These tests verify this architectural constraint is enforced.

    #[test]
    fn test_direct_merkle_init_blocked_by_authorization() {
        let (mut state, merkle, _) = state_with_programs()
            .expect("Programs should load. Run: cargo risczero build --manifest-path methods/guest/Cargo.toml");

        // Try to initialize merkle tree directly (not through registration program)
        let init_tx = build_merkle_init_tx(&merkle, &TREE_ID);
        let result = state.transition_from_public_transaction(&init_tx, 1, 0);
        assert!(
            result.is_err(),
            "Direct merkle tree init should fail due to authorization"
        );
    }

    #[test]
    fn test_direct_merkle_insert_blocked_by_authorization() {
        let (mut state, merkle, _) = state_with_programs()
            .expect("Programs should load. Run: cargo risczero build --manifest-path methods/guest/Cargo.toml");

        // Try to insert into merkle tree directly (not through registration program)
        let leaf_value = [0x42u8; 32];
        let insert_tx = build_merkle_insert_tx(&merkle, &TREE_ID, 0, leaf_value);
        let result = state.transition_from_public_transaction(&insert_tx, 1, 0);

        assert!(
            result.is_err(),
            "Direct merkle tree insert should fail due to authorization"
        );
    }

    // ========================================================================
    // Token Account Helpers
    // ========================================================================
    //
    // Token accounts cannot be directly inserted (force_insert_account is
    // private to nssa crate). These helpers create the data layouts for
    // verification after transactions.

    /// Creates borsh-serialized token holding account data for a fungible token.
    #[allow(dead_code)]
    fn create_token_holding_data(definition_id: &AccountId, balance: u128) -> Vec<u8> {
        let holding = TokenHolding::Fungible {
            definition_id: *definition_id,
            balance,
        };
        Data::from(&holding).as_ref().to_vec()
    }

    // ========================================================================
    // Keypair Helper
    // ========================================================================

    /// Creates a test keypair from a deterministic seed byte.
    /// AccountId is derived from the public key via SHA256 hash.
    fn create_test_keypair(seed: u8) -> (PrivateKey, AccountId) {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let private_key = PrivateKey::try_new(bytes).unwrap();
        let public_key = PublicKey::new_from_private_key(&private_key);
        let account_id = AccountId::from(&public_key);
        (private_key, account_id)
    }

    // ========================================================================
    // Private Account Keys
    // ========================================================================

    /// Keys for a privacy-preserving (private) account.
    ///
    /// The viewing key derives from the two-half FIPS-203 seed `(d, z)` via
    /// `ViewingPublicKey::from_seed`, and an `AccountId` binds all three of
    /// (npk, vpk, identifier) — the vpk joined the derivation in v0.2.5, so an
    /// account id cannot be computed from the nullifier key alone.
    ///
    /// The spending credential is the `AuthorizationSecretKey`: the nullifier
    /// secret key derives from it, and the circuit re-derives that relation
    /// before it will accept a private account as authorized. So the two are
    /// not independent inputs, and `nsk` is a function here rather than a
    /// field — a struct that let a caller set them separately would be
    /// describing a state the circuit rejects.
    #[cfg(feature = "rc5-state-tests-privacy")]
    struct PrivateAccountKeys {
        ask: AuthorizationSecretKey,
        d: [u8; 32],
        z: [u8; 32],
    }

    #[cfg(feature = "rc5-state-tests-privacy")]
    impl PrivateAccountKeys {
        fn nsk(&self) -> NullifierSecretKey {
            NullifierSecretKey::from(&self.ask)
        }

        fn npk(&self) -> NullifierPublicKey {
            NullifierPublicKey::from(&self.nsk())
        }

        fn vpk(&self) -> ViewingPublicKey {
            ViewingPublicKey::from_seed(&self.d, &self.z)
        }

        fn account_id(&self, identifier: Identifier) -> AccountId {
            AccountId::for_regular_private_account(&self.npk(), &self.vpk(), identifier)
        }
    }

    #[cfg(feature = "rc5-state-tests-privacy")]
    fn private_account_keys(seed1: u8, seed2: u8) -> PrivateAccountKeys {
        // ML-KEM-768 needs two 32-byte seed halves (d, z) for the FIPS-203
        // ViewingPublicKey derivation. Derive z deterministically from seed2 so
        // the helper's two-seed signature is preserved (call sites don't change).
        PrivateAccountKeys {
            ask: AuthorizationSecretKey({
                let mut b = [0u8; 32];
                b[0] = seed1;
                b
            }),
            d: {
                let mut b = [0u8; 32];
                b[0] = seed2;
                b
            },
            z: {
                let mut b = [0u8; 32];
                b[0] = seed2.wrapping_add(0x80);
                b[1] = seed2;
                b
            },
        }
    }

    // ========================================================================
    // Private Account Witnesses
    // ========================================================================
    //
    // v0.2.5 replaced the flat `InputAccountIdentity::Private*` variants with a
    // single `Private(PrivateWitness)` carrying the account's lifecycle in
    // `NullifierWitness` (Init vs Update) and its credential in `WitnessKind`.
    // The two constructors below are the only two shapes these tests need.

    /// Witness for a private account this transaction CREATES: no membership
    /// proof, and the pre-state must be `Account::default()`.
    ///
    /// `ask` is `None` because the party building the transaction is not the
    /// one who will own the account — it knows only the recipient's public
    /// keys. The circuit asserts `pre_state.is_authorized == ask.is_some()`, so
    /// the matching `AccountWithMetadata` must be built with `false`.
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn private_init_identity(
        keys: &PrivateAccountKeys,
        identifier: Identifier,
    ) -> InputAccountIdentity {
        InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0u8; 32],
            identifier,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })
    }

    /// Witness for a private account this transaction SPENDS FROM: the account
    /// already has a commitment on chain, so the nullifier is an `Update`
    /// proven against the commitment set, and `ask` is supplied — that is the
    /// credential the circuit checks against `nsk`, and the reason a private
    /// account may be debited at all. The matching `AccountWithMetadata` must
    /// be built with `is_authorized == true`.
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn private_update_identity(
        keys: &PrivateAccountKeys,
        identifier: Identifier,
        membership_proof: MembershipProof,
    ) -> InputAccountIdentity {
        InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0u8; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()),
                nsk: keys.nsk(),
                membership_proof,
            },
        })
    }

    // ========================================================================
    // Privacy-Preserving Token Transfer Helpers
    // ========================================================================

    /// Serializes a token Transfer instruction for use with execute_and_prove.
    #[allow(dead_code)]
    fn token_transfer_instruction_data(amount: u128) -> Vec<u8> {
        let instruction = token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        };
        Program::serialize_instruction(instruction).unwrap()
    }

    /// Constructs the Account state that results from a token transfer to a new
    /// (default) recipient. The token program claims the account and sets data.
    #[allow(dead_code)]
    fn token_holding_account(definition_id: &AccountId, balance: u128) -> Account {
        Account {
            program_owner: crate::spel_seeds::program_account(&programs::token().id()),
            balance: 0,
            nonce: Nonce(0),
            data: Data::try_from(create_token_holding_data(definition_id, balance)).unwrap(),
        }
    }

    /// Shields tokens: public token holding → new private token holding.
    /// Encryption is ML-KEM-768 and the ephemeral key is derived inside the
    /// circuit from the witness's `random_seed`, so the caller supplies neither
    /// a shared secret nor a ciphertext. The recipient's AccountId binds
    /// (npk, vpk, identifier=0).
    ///
    /// Returns (transaction, private_account_post_state).
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn shield_tokens(
        sender_key: &PrivateKey,
        sender_id: &AccountId,
        recipient_keys: &PrivateAccountKeys,
        amount: u128,
        state: &V03State,
    ) -> (PrivacyPreservingTransaction, Account) {
        let recipient_id = recipient_keys.account_id(0);
        let sender =
            AccountWithMetadata::new(state.get_account_by_id(*sender_id), true, *sender_id);
        let sender_nonce = sender.account.nonce;
        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0_u128),
        );

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            token_transfer_instruction_data(amount),
            vec![
                InputAccountIdentity::Public,
                private_init_identity(recipient_keys, 0),
            ],
            &programs::token().into(),
        )
        .expect("shield_tokens: execute_and_prove failed");

        // The public sender signs, so its nonce travels in the message; the
        // public account ids the old signature carried now come out of the
        // circuit's own public actions.
        let message = PrivacyMessage::from_circuit_output(vec![sender_nonce], output);

        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[sender_key]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute the recipient's post-state (what the token program produces)
        let sender_account = state.get_account_by_id(*sender_id);
        let sender_holding = TokenHolding::try_from(&sender_account.data)
            .expect("Sender should have valid token holding");
        let definition_id = sender_holding.definition_id();
        let recipient_post = Account {
            program_owner: crate::spel_seeds::program_account(&programs::token().id()),
            balance: 0,
            nonce: Nonce::private_account_nonce_init(&recipient_id),
            data: Data::try_from(create_token_holding_data(&definition_id, amount)).unwrap(),
        };

        (tx, recipient_post)
    }

    /// Transfers tokens between two private accounts.
    /// The sender spends an existing commitment (`Update`, with membership
    /// proof and credential); the recipient is a fresh `Init`. Both account_ids
    /// bind to (npk, vpk, 0).
    ///
    /// Returns (transaction, sender_post_state, recipient_post_state).
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn private_token_transfer(
        sender_keys: &PrivateAccountKeys,
        sender_account: &Account,
        recipient_keys: &PrivateAccountKeys,
        amount: u128,
        state: &V03State,
    ) -> (PrivacyPreservingTransaction, Account, Account) {
        let sender_id = sender_keys.account_id(0);
        let recipient_id = recipient_keys.account_id(0);
        let sender_commitment = Commitment::new(&sender_id, sender_account);
        let sender = AccountWithMetadata::new(
            sender_account.clone(),
            true,
            (&sender_keys.npk(), &sender_keys.vpk(), 0_u128),
        );
        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            (&recipient_keys.npk(), &recipient_keys.vpk(), 0_u128),
        );

        let sender_proof = state
            .get_proof_for_commitment(&sender_commitment)
            .expect("private_token_transfer: sender's commitment must be in state");

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            token_transfer_instruction_data(amount),
            vec![
                private_update_identity(sender_keys, 0, sender_proof),
                private_init_identity(recipient_keys, 0),
            ],
            &programs::token().into(),
        )
        .expect("private_token_transfer: execute_and_prove failed");

        // No public account takes part, so there is nothing to sign and no
        // nonce to carry.
        let message = PrivacyMessage::from_circuit_output(vec![], output);

        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute post-states
        let sender_holding = TokenHolding::try_from(&sender_account.data)
            .expect("Sender should have valid token holding");
        let definition_id = sender_holding.definition_id();
        let sender_balance = match &sender_holding {
            TokenHolding::Fungible { balance, .. } => *balance,
            TokenHolding::NftMaster { .. } | TokenHolding::NftPrintedCopy { .. } => {
                panic!("Expected fungible token holding")
            }
        };

        let sender_post = Account {
            program_owner: sender_account.program_owner,
            balance: 0,
            nonce: sender_account
                .nonce
                .private_account_nonce_increment(&sender_keys.nsk()),
            data: Data::try_from(create_token_holding_data(
                &definition_id,
                sender_balance - amount,
            ))
            .unwrap(),
        };
        let recipient_post = Account {
            program_owner: crate::spel_seeds::program_account(&programs::token().id()),
            balance: 0,
            nonce: Nonce::private_account_nonce_init(&recipient_id),
            data: Data::try_from(create_token_holding_data(&definition_id, amount)).unwrap(),
        };

        (tx, sender_post, recipient_post)
    }

    /// Deshields tokens: private token holding → public account.
    /// The sender spends an existing commitment (`Update`); the recipient is
    /// `Public` and unauthorized — it only receives, so it neither signs nor
    /// needs a nonce.
    ///
    /// Returns (transaction, sender_post_state).
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn deshield_tokens(
        sender_keys: &PrivateAccountKeys,
        sender_account: &Account,
        recipient_id: &AccountId,
        amount: u128,
        state: &V03State,
    ) -> (PrivacyPreservingTransaction, Account) {
        let sender_id = sender_keys.account_id(0);
        let sender_commitment = Commitment::new(&sender_id, sender_account);
        let sender = AccountWithMetadata::new(
            sender_account.clone(),
            true,
            (&sender_keys.npk(), &sender_keys.vpk(), 0_u128),
        );
        let recipient =
            AccountWithMetadata::new(state.get_account_by_id(*recipient_id), false, *recipient_id);

        let sender_proof = state
            .get_proof_for_commitment(&sender_commitment)
            .expect("deshield_tokens: sender's commitment must be in state");

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            token_transfer_instruction_data(amount),
            vec![
                private_update_identity(sender_keys, 0, sender_proof),
                InputAccountIdentity::Public,
            ],
            &programs::token().into(),
        )
        .expect("deshield_tokens: execute_and_prove failed");

        let message = PrivacyMessage::from_circuit_output(vec![], output);

        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute sender post-state
        let sender_holding = TokenHolding::try_from(&sender_account.data)
            .expect("Sender should have valid token holding");
        let definition_id = sender_holding.definition_id();
        let sender_balance = match &sender_holding {
            TokenHolding::Fungible { balance, .. } => *balance,
            TokenHolding::NftMaster { .. } | TokenHolding::NftPrintedCopy { .. } => {
                panic!("Expected fungible token holding")
            }
        };
        let sender_post = Account {
            program_owner: sender_account.program_owner,
            balance: 0,
            nonce: sender_account
                .nonce
                .private_account_nonce_increment(&sender_keys.nsk()),
            data: Data::try_from(create_token_holding_data(
                &definition_id,
                sender_balance - amount,
            ))
            .unwrap(),
        };

        (tx, sender_post)
    }

    // ========================================================================
    // Token Program Transaction Builders
    // ========================================================================

    /// Builds a token creation transaction.
    /// Creates a token definition and initial supply holder account.
    ///
    /// Instruction format: opcode(1) + total_supply(16) + name(6) = 23 bytes
    #[allow(dead_code)]
    fn build_token_create_tx(
        definition_id: &AccountId,
        definition_key: &PrivateKey,
        supply_holder_id: &AccountId,
        supply_holder_key: &PrivateKey,
        total_supply: u128,
        name: &[u8; 6],
    ) -> PublicTransaction {
        let instruction = token_core::Instruction::NewFungibleDefinition {
            name: String::from_utf8_lossy(name).to_string(),
            total_supply,
        };

        let message = Message::try_new(
            crate::spel_seeds::program_account(&programs::token().id()),
            vec![*definition_id, *supply_holder_id],
            vec![Nonce(0), Nonce(0)],
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[definition_key, supply_holder_key]),
        )
    }

    #[allow(dead_code)]
    fn build_token_transfer_tx(
        from_id: &AccountId,
        to_id: &AccountId,
        from_key: &PrivateKey,
        to_key: Option<&PrivateKey>,
        from_nonce: Nonce,
        to_nonce: Nonce,
        amount: u128,
    ) -> PublicTransaction {
        let instruction = token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        };

        let (nonces, keys): (Vec<Nonce>, Vec<&PrivateKey>) = if let Some(to_key) = to_key {
            (vec![from_nonce, to_nonce], vec![from_key, to_key])
        } else {
            (vec![from_nonce], vec![from_key])
        };

        let message = Message::try_new(
            crate::spel_seeds::program_account(&programs::token().id()),
            vec![*from_id, *to_id],
            nonces,
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &keys))
    }

    // ========================================================================
    // Registration Init Transaction Builder
    // ========================================================================

    // Test-specific constants for new config fields
    const DEFAULT_MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000; // 1 million total rate limit

    /// Native balance a test payer is seeded with. Covers a registration at the
    /// default rate limit plus a renewal of the same, with room left over so a
    /// debit is observable rather than exhausting the account.
    const DEFAULT_PAYER_BALANCE: u128 = 10_000_000;

    /// Builds the two transactions that together initialize the RLN registration
    /// program.
    ///
    /// Init is split into Initialize + InitializeMerkleTree so each chained call
    /// runs in its own session, fitting under the 32M-cycle per-session cap.
    fn build_registration_init_txs(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        price_per_unit: u128,
        treasury_id: &AccountId,
    ) -> [PublicTransaction; 2] {
        build_registration_init_txs_with_config(
            registration,
            merkle,
            tree_id,
            price_per_unit,
            treasury_id,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
        )
    }

    fn build_registration_init_txs_with_config(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        price_per_unit: u128,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
    ) -> [PublicTransaction; 2] {
        build_registration_init_txs_with_durations(
            registration,
            merkle,
            tree_id,
            price_per_unit,
            treasury_id,
            max_total_rate_limit,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_registration_init_txs_with_durations(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        price_per_unit: u128,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> [PublicTransaction; 2] {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );

        let init_config = build_public_tx(
            crate::spel_seeds::program_account(&registration.id()),
            vec![config_id],
            Instruction::Initialize {
                merkle_program_id: *crate::spel_seeds::program_account(&merkle.id()).value(),
                tree_id: *tree_id,
                price_per_unit,
                treasury_account_id: *treasury_id.value(),
                max_total_rate_limit,
                active_duration_for_new_memberships_sec: active_duration_sec,
                grace_period_duration_for_new_memberships_sec: grace_period_duration_sec,
            },
        );

        let init_merkle = build_public_tx(
            crate::spel_seeds::program_account(&registration.id()),
            vec![config_id, tree_main_id],
            Instruction::InitializeMerkleTree { tree_id: *tree_id },
        );

        [init_config, init_merkle]
    }

    fn build_public_tx(
        program_id: AccountId,
        accounts: Vec<AccountId>,
        instruction: Instruction,
    ) -> PublicTransaction {
        let message =
            Message::try_new(program_id, accounts, vec![], instruction).expect("valid message");
        let witness = WitnessSet::for_message(&message, &[]);
        PublicTransaction::new(message, witness)
    }

    /// Apply both init transactions; returns the first error if any, else Ok.
    fn apply_registration_init(
        state: &mut V03State,
        txs: &[PublicTransaction; 2],
    ) -> Result<(), nssa::error::LeeError> {
        for tx in txs {
            state.transition_from_public_transaction(tx, 1, 0)?;
        }
        Ok(())
    }

    // ========================================================================
    // Test Setup
    // ========================================================================

    /// Test setup with programs deployed, a funded payer, and registration
    /// initialized.
    #[allow(dead_code)]
    struct TestSetup {
        state: V03State,
        merkle: Program,
        registration: Program,
        /// The account the registry price is credited to. Deliberately never
        /// seeded: a native credit lands on an account that has never been
        /// written to, which is what `run_setup` relies on in a real
        /// deployment.
        treasury_id: AccountId,
        /// Signs the register/extend transaction and pays its price out of
        /// NATIVE balance. On-chain this account is also the fee payer.
        payer_id: AccountId,
        payer_key: PrivateKey,
    }

    /// Force-inserts a funded wallet account: plain native balance, no data,
    /// still owned by `DEFAULT_PROGRAM_OWNER` (`AccountId::default()`).
    ///
    /// That shape is the point — it is what a real funded wallet account looks
    /// like. No program can mint native balance, so a deployment's payer is
    /// funded at genesis, over the bridge, or by a transfer; there is no
    /// in-band instruction that could create this state, hence the escape
    /// hatch.
    fn fund_native(state: &mut V03State, account_id: &AccountId, balance: u128) {
        state.force_insert_account(
            *account_id,
            Account {
                balance,
                ..Account::default()
            },
        );
    }

    /// Native balance of an account, the counterpart of `get_token_balance`
    /// now that the registry moves the native asset rather than a token.
    fn native_balance(state: &V03State, account_id: &AccountId) -> u128 {
        state.get_account_by_id(*account_id).balance
    }

    /// Creates a state with programs deployed, a funded payer, and registration
    /// initialized with a caller-chosen rate-limit cap.
    #[allow(dead_code)]
    fn state_with_initialized_registration_config(max_total_rate_limit: u64) -> Option<TestSetup> {
        state_with_initialized_registration_durations(
            max_total_rate_limit,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
    }

    /// Creates a state with programs deployed, a funded payer, and registration
    /// initialized with default config. Returns None if any step fails.
    #[allow(dead_code)]
    fn state_with_initialized_registration() -> Option<TestSetup> {
        state_with_initialized_registration_config(DEFAULT_MAX_TOTAL_RATE_LIMIT)
    }

    /// Same as `state_with_initialized_registration_config` with caller-chosen durations.
    #[allow(dead_code)]
    fn state_with_initialized_registration_durations(
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> Option<TestSetup> {
        let (mut state, merkle, registration) = state_with_programs()?;

        let (_treasury_key, treasury_id) = create_test_keypair(1);
        let (payer_key, payer_id) = create_test_keypair(2);

        fund_native(&mut state, &payer_id, DEFAULT_PAYER_BALANCE);

        let init_txs = build_registration_init_txs_with_durations(
            &registration,
            &merkle,
            &TREE_ID,
            PRICE_PER_UNIT,
            &treasury_id,
            max_total_rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
        );
        apply_registration_init(&mut state, &init_txs).ok()?;

        Some(TestSetup {
            state,
            merkle,
            registration,
            treasury_id,
            payer_id,
            payer_key,
        })
    }

    // ========================================================================
    // State Reading Helpers
    // ========================================================================
    //
    // These helpers extract data from on-chain state, reducing code duplication
    // and making tests more readable.

    /// Gets total_registrations from config account.
    #[allow(dead_code)]
    fn get_total_registrations(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
    ) -> u64 {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let config = state.get_account_by_id(config_id);
        u64::from_le_bytes(
            config.data.as_ref()
                [CONFIG_OFFSET_TOTAL_REGISTRATIONS..CONFIG_OFFSET_TOTAL_REGISTRATIONS + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Gets current_total_rate_limit from config account.
    #[allow(dead_code)]
    fn get_current_total_rate_limit(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
    ) -> u64 {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let config = state.get_account_by_id(config_id);
        u64::from_le_bytes(
            config.data.as_ref()[CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT
                ..CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Gets next_index from tree main account.
    #[allow(dead_code)]
    fn get_tree_next_index(state: &V03State, registration: &Program, tree_id: &[u8; 32]) -> u64 {
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let tree = state.get_account_by_id(tree_main_id);
        u64::from_le_bytes(tree.data.as_ref()[1..9].try_into().unwrap())
    }

    /// Gets merkle root from tree main account.
    #[allow(dead_code)]
    fn get_tree_root(state: &V03State, registration: &Program, tree_id: &[u8; 32]) -> [u8; 32] {
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let tree = state.get_account_by_id(tree_main_id);
        tree.data.as_ref()[9..41].try_into().unwrap()
    }

    /// Gets token balance from a holding account.
    #[allow(dead_code)]
    fn get_token_balance(state: &V03State, account_id: &AccountId) -> u128 {
        let account = state.get_account_by_id(*account_id);
        let holding =
            TokenHolding::try_from(&account.data).expect("Failed to deserialize token holding");
        match holding {
            TokenHolding::Fungible { balance, .. } => balance,
            TokenHolding::NftMaster { print_balance, .. } => print_balance,
            TokenHolding::NftPrintedCopy { .. } => 0,
        }
    }

    /// Checks if a membership PDA exists (has non-empty data).
    #[allow(dead_code)]
    fn membership_exists(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> bool {
        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
            id_commitment,
        );
        let membership = state.get_account_by_id(membership_id);
        !membership.data.as_ref().is_empty()
    }

    /// Membership data extracted from PDA.
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct MembershipData {
        leaf_index: u64,
        rate_limit: u64,
        id_commitment: [u8; 32],
    }

    /// Gets membership data from PDA. Returns None if membership doesn't exist.
    #[allow(dead_code)]
    fn get_membership_data(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> Option<MembershipData> {
        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
            id_commitment,
        );
        let membership = state.get_account_by_id(membership_id);
        let data = membership.data.as_ref();
        if data.is_empty() || data.len() < MEMBERSHIP_SIZE {
            return None;
        }
        Some(MembershipData {
            leaf_index: u64::from_le_bytes(
                data[MEMBERSHIP_OFFSET_LEAF_INDEX..MEMBERSHIP_OFFSET_LEAF_INDEX + 8]
                    .try_into()
                    .unwrap(),
            ),
            rate_limit: u64::from_le_bytes(
                data[MEMBERSHIP_OFFSET_RATE_LIMIT..MEMBERSHIP_OFFSET_RATE_LIMIT + 8]
                    .try_into()
                    .unwrap(),
            ),
            id_commitment: data
                [MEMBERSHIP_OFFSET_ID_COMMITMENT..MEMBERSHIP_OFFSET_ID_COMMITMENT + 32]
                .try_into()
                .unwrap(),
        })
    }

    // ========================================================================
    // Identity Helpers
    // ========================================================================

    /// Derive id_commitment from identity_secret using Poseidon hash.
    /// Matches the single-input `hash_single` used by the guest's slash path.
    fn derive_id_commitment_from_secret(identity_secret: &[u8; 32]) -> [u8; 32] {
        use rln::prelude::{Hasher, PoseidonHash};

        use crate::fr_bytes::{bytes_le_to_fr, fr_to_bytes_le};

        let secret_fr = bytes_le_to_fr(identity_secret).expect("Invalid identity_secret");
        let hash_fr = Hasher::<PoseidonHash>::hash_single(secret_fr);
        fr_to_bytes_le(&hash_fr)
    }

    /// Creates a slashable identity (identity_secret and derived id_commitment).
    /// Uses the poseidon derivation that matches the guest program.
    #[allow(dead_code)]
    fn create_slashable_identity(seed: u8) -> ([u8; 32], [u8; 32]) {
        let mut identity_secret = [0u8; 32];
        identity_secret[0] = seed;
        let id_commitment = derive_id_commitment_from_secret(&identity_secret);
        (identity_secret, id_commitment)
    }

    // ========================================================================
    // Register Transaction Builder
    // ========================================================================

    /// What a whole register transaction costs, against the ceiling that
    /// actually rejects it.
    ///
    /// LEZ v0.2.5 meters a charged transaction by its declared `gas_limit`, one
    /// gas per cycle, and `fee_core::market::MAX_GAS_EXEC` caps that at ten
    /// million — a transaction over it can never be included in any block. The
    /// budget is per *transaction*, so it covers the registration guest and the
    /// chained merkle insert together. Measuring the merkle guest alone (see
    /// `cycle_harness`) understates it. The price no longer costs a chained
    /// call at all: it moves as two balance assignments inside `register`.
    ///
    /// Printed rather than only asserted: the number picks the tree depth, and
    /// the margin is what says whether the next depth up would fit.
    #[test]
    fn register_transaction_fits_the_gas_ceiling() {
        const MAX_GAS_EXEC: u64 = 10_000_000;

        let Some(setup) = state_with_initialized_registration() else {
            eprintln!("skipping gas measurement: guest .bin not built");
            return;
        };
        let tx = build_register_tx(
            &setup,
            &TREE_ID,
            valid_field_element(0x42),
            100,
            Nonce(0),
            0,
        );

        let (_diff, outcome) = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &tx,
            &setup.state,
            1,
            0,
            MAX_GAS_EXEC,
        )
        .expect("register should execute within the ceiling");

        let used = outcome.cycles;
        let pct = (used as f64 / MAX_GAS_EXEC as f64) * 100.0;
        println!(
            "register transaction: {used} cycles ({pct:.1}% of MAX_GAS_EXEC), \
             tree depth {}",
            crate::merkle_tree::TREE_DEPTH
        );

        assert!(
            used <= MAX_GAS_EXEC,
            "a register transaction costs {used} cycles against a {MAX_GAS_EXEC} ceiling — \
             the tree is too deep to register into"
        );
    }

    fn build_register_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        payer_nonce: Nonce,
        next_index: u64,
    ) -> PublicTransaction {
        build_register_tx_parts(
            &setup.registration,
            tree_id,
            &setup.payer_id,
            &setup.payer_key,
            &setup.treasury_id,
            id_commitment,
            rate_limit,
            payer_nonce,
            next_index,
        )
    }

    /// Builds a direct registration transaction.
    ///
    /// Account order:
    /// - pre_states[0]: Config
    /// - pre_states[1]: Tree main
    /// - pre_states[2]: Payer (signer; debited in NATIVE balance)
    /// - pre_states[3]: Treasury (credited in NATIVE balance)
    /// - pre_states[4]: Bottom subtree account
    /// - pre_states[5]: CLOCK_50 system account (read-only timestamp)
    /// - pre_states[6]: Membership PDA (init)
    ///
    /// Spelled out in parts rather than taken from a `TestSetup` so a test can
    /// point the transaction at a treasury or payer the config does not name.
    #[allow(clippy::too_many_arguments)]
    fn build_register_tx_parts(
        registration: &Program,
        tree_id: &[u8; 32],
        payer_id: &AccountId,
        payer_key: &PrivateKey,
        treasury_id: &AccountId,
        id_commitment: [u8; 32],
        rate_limit: u64,
        payer_nonce: Nonce,
        next_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let sid = subtree_id_for_index(next_index);
        let subtree_account_id = derive_subtree_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
            sid,
        );

        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
            &id_commitment,
        );
        let account_ids = vec![
            config_id,
            tree_main_id,
            *payer_id,
            *treasury_id,
            subtree_account_id,
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            membership_id,
        ];

        let instruction = Instruction::Register {
            tree_id: *tree_id,
            id_commitment,
            rate_limit,
            subtree_id: sid,
        };

        let message = Message::try_new(
            crate::spel_seeds::program_account(&registration.id()),
            account_ids,
            vec![payer_nonce], // nonce for the payer account (index 2)
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[payer_key]),
        )
    }

    /// Builds a slash transaction (opcode 4).
    ///
    /// Account order:
    /// - pre_states[0]: Config
    /// - pre_states[1]: Tree main
    /// - pre_states[2]: Membership PDA
    /// - pre_states[3]: Bottom subtree account
    #[allow(dead_code)]
    fn build_slash_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        identity_secret: [u8; 32],
        id_commitment: [u8; 32],
        leaf_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
        );
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
        );
        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
            &id_commitment,
        );
        let sid = subtree_id_for_index(leaf_index);
        let subtree_account_id = derive_subtree_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
            sid,
        );

        // Account list: config, tree_main, membership, subtree
        let account_ids = vec![config_id, tree_main_id, membership_id, subtree_account_id];

        let instruction = Instruction::Slash {
            tree_id: *tree_id,
            id_commitment,
            identity_secret,
            subtree_id: sid,
        };

        let message = Message::try_new(
            crate::spel_seeds::program_account(&setup.registration.id()),
            account_ids,
            vec![], // No nonces needed - no authorization required for slash
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[]))
    }

    // ========================================================================
    // Full Flow Tests - Registration Init
    // ========================================================================

    #[test]
    fn test_registration_init_succeeds() {
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

        // Create test account IDs for init
        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        let result = apply_registration_init(&mut state, &init_txs);

        assert!(
            result.is_ok(),
            "Registration init should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_registration_init_creates_config() {
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        apply_registration_init(&mut state, &init_txs).expect("Init should succeed");

        // Verify config account was created
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&registration.id()),
            &TREE_ID,
        );
        let config_account = state.get_account_by_id(config_id);

        // Config should exist and have data
        assert!(
            !config_account.data.as_ref().is_empty(),
            "Config account should have data"
        );

        // Verify the Borsh-encoded ConfigState layout field by field.
        //
        // The account's LENGTH is asserted exactly, not as a lower bound:
        // ConfigState carries no version discriminator, so its size is the only
        // thing that tells this 144-byte layout from the 296-byte one it
        // replaced. Read through the wrong table, an old config decodes as a
        // plausible wrong treasury rather than failing — every offset below is
        // meaningless unless this line holds first.
        let data = config_account.data.as_ref();
        assert_eq!(
            data.len(),
            CONFIG_SIZE,
            "config account must be exactly CONFIG_SIZE ({CONFIG_SIZE}) bytes"
        );

        let merkle_id_bytes: [u8; 32] = *crate::spel_seeds::program_account(&merkle.id()).value();
        assert_eq!(
            &data[CONFIG_OFFSET_MERKLE_PROGRAM_ID..CONFIG_OFFSET_MERKLE_PROGRAM_ID + 32],
            &merkle_id_bytes,
            "Config should store merkle program ID"
        );

        assert_eq!(
            &data[CONFIG_OFFSET_TREE_ID..CONFIG_OFFSET_TREE_ID + 32],
            &TREE_ID,
            "Config should store tree ID"
        );

        let stored_price = u128::from_le_bytes(
            data[CONFIG_OFFSET_PRICE_PER_UNIT..CONFIG_OFFSET_PRICE_PER_UNIT + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            stored_price, PRICE_PER_UNIT,
            "Config should store price per unit"
        );

        assert_eq!(
            &data[CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32],
            treasury_id.value(),
            "Config should store treasury ID"
        );

        let total_registrations = u64::from_le_bytes(
            data[CONFIG_OFFSET_TOTAL_REGISTRATIONS..CONFIG_OFFSET_TOTAL_REGISTRATIONS + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            total_registrations, 0,
            "Initial total_registrations should be 0"
        );

        let max_total_rate_limit = u64::from_le_bytes(
            data[CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT..CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            max_total_rate_limit, DEFAULT_MAX_TOTAL_RATE_LIMIT,
            "Config should store max_total_rate_limit"
        );

        let current_total_rate_limit = u64::from_le_bytes(
            data[CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT
                ..CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            current_total_rate_limit, 0,
            "Initial current_total_rate_limit should be 0"
        );

        let active_duration_sec = u32::from_le_bytes(
            data[CONFIG_OFFSET_ACTIVE_DURATION..CONFIG_OFFSET_ACTIVE_DURATION + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            active_duration_sec, DEFAULT_ACTIVE_DURATION_SEC,
            "Config should store active_duration_for_new_memberships_sec"
        );

        let grace_period_duration_sec = u32::from_le_bytes(
            data[CONFIG_OFFSET_GRACE_PERIOD_DURATION..CONFIG_OFFSET_GRACE_PERIOD_DURATION + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            grace_period_duration_sec, DEFAULT_GRACE_PERIOD_DURATION_SEC,
            "Config should store grace_period_duration_for_new_memberships_sec"
        );
    }

    #[test]
    fn test_registration_init_creates_tree_main() {
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        apply_registration_init(&mut state, &init_txs).expect("Init should succeed");

        // Verify tree main account was created via chained call
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&registration.id()),
            &TREE_ID,
        );
        let tree_main = state.get_account_by_id(tree_main_id);

        assert!(
            !tree_main.data.as_ref().is_empty(),
            "Tree main account should have data"
        );

        // Check tree depth at offset 0
        let data = tree_main.data.as_ref();
        assert_eq!(
            data[0], TREE_DEPTH as u8,
            "Tree main should have depth {}",
            TREE_DEPTH
        );

        // Check next_index at offset 1 (should be 0)
        let next_index = u64::from_le_bytes(data[1..9].try_into().unwrap());
        assert_eq!(next_index, 0, "Initial next_index should be 0");

        // Root at offset 9 (32 bytes) should be the default empty tree root
        // We don't check the exact value as it depends on Poseidon hash
        assert!(
            data.len() >= 41,
            "Tree main should have at least depth + next_index + root"
        );
    }

    #[test]
    fn test_registration_init_prevents_reinit() {
        // Re-initialization is prevented because the token program's create
        // instruction requires the definition account to be default/uninitialized.
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        // First init should succeed
        apply_registration_init(&mut state, &init_txs).expect("First init should succeed");

        // Second init should fail. With the 3-tx split, the InitializeConfig
        // re-claim of the existing config PDA is what blocks re-init.
        let result = apply_registration_init(&mut state, &init_txs);
        assert!(
            result.is_err(),
            "Re-initialization should fail (config already claimed)"
        );
    }

    // SECURITY (callee substitution): the merkle/token program a chained init
    // call targets comes from config, never from the caller. The instructions
    // no longer carry a program-id argument at all, so the only way to aim an
    // init at an attacker's program is to make config name it — which means
    // owning the tree_id's config PDA in the first place. Before the fix,
    // InitializeMerkleTree took merkle_program_id as an arg and handed it
    // pda_seeds authorizing it to claim this program's `main` PDA.
    #[test]
    fn test_init_merkle_uses_config_program_not_caller_arg() {
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            PRICE_PER_UNIT,
            &treasury_id,
        );
        apply_registration_init(&mut state, &init_txs).expect("Init should succeed");

        // Config binds the tree to `merkle`, so a second tree_id whose config
        // was never initialized has nothing to read: the init must fail rather
        // than fall back to a caller-named program.
        let other_tree_id = [0x99u8; 32];
        let orphan_tx = build_public_tx(
            crate::spel_seeds::program_account(&registration.id()),
            vec![
                derive_config_pda(
                    crate::spel_seeds::program_account(&registration.id()),
                    &other_tree_id,
                ),
                derive_tree_main_pda(
                    crate::spel_seeds::program_account(&registration.id()),
                    &other_tree_id,
                ),
            ],
            Instruction::InitializeMerkleTree {
                tree_id: other_tree_id,
            },
        );
        assert!(
            state
                .transition_from_public_transaction(&orphan_tx, 1, 0)
                .is_err(),
            "InitializeMerkleTree without an initialized config must fail"
        );
    }

    // SECURITY (tree reset): replaying InitializeMerkleTree alone must not
    // reset a live tree. The batch test above stops at the first tx and never
    // reaches the merkle one; this exercises that tx on its own, which is what
    // an attacker submits. Public transactions carry no signature, so the only
    // thing standing between anyone and a tree wipe is the init check on
    // tree_main (plus initialize_tree's own uninitialized assert). A reset
    // would zero next_index and the root history — invalidating every member's
    // proof — while the membership PDAs survive, so nobody could re-register.
    #[test]
    fn test_initialize_merkle_tree_cannot_reset_a_live_tree() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        // Put a real member in the tree, so a successful reset would be
        // observably destructive rather than a no-op on an empty tree.
        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            valid_field_element(0x42),
            300,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            &TREE_ID,
        );
        let before = setup
            .state
            .get_account_by_id(tree_main_id)
            .data
            .as_ref()
            .to_vec();
        assert_eq!(
            u64::from_le_bytes(before[1..9].try_into().unwrap()),
            1,
            "the member should be in the tree before the reset attempt"
        );

        let attack_tx = build_public_tx(
            crate::spel_seeds::program_account(&setup.registration.id()),
            vec![
                derive_config_pda(
                    crate::spel_seeds::program_account(&setup.registration.id()),
                    &TREE_ID,
                ),
                tree_main_id,
            ],
            Instruction::InitializeMerkleTree { tree_id: TREE_ID },
        );
        let result = setup
            .state
            .transition_from_public_transaction(&attack_tx, 1, 0);
        assert!(
            result.is_err(),
            "Re-initializing a live tree must fail, got: {result:?}"
        );

        let after = setup
            .state
            .get_account_by_id(tree_main_id)
            .data
            .as_ref()
            .to_vec();
        assert_eq!(
            before, after,
            "the rejected reset must leave the tree byte-identical"
        );
    }

    // ========================================================================
    // Full Flow Tests - Token Infrastructure
    // ========================================================================

    #[test]
    fn test_token_create_succeeds() {
        let (mut state, _merkle, _registration) =
            state_with_programs().expect("Programs should load");

        let (supply_holder_key, supply_holder_id) = create_test_keypair(1);
        let (definition_key, definition_id) = create_test_keypair(10);

        let create_tx = build_token_create_tx(
            &definition_id,
            &definition_key,
            &supply_holder_id,
            &supply_holder_key,
            1_000_000,
            b"TESTOK",
        );

        let result = state.transition_from_public_transaction(&create_tx, 1, 0);
        assert!(result.is_ok(), "Token create should succeed: {:?}", result);

        // Verify definition was created
        let def_account = state.get_account_by_id(definition_id);
        assert!(
            !def_account.data.as_ref().is_empty(),
            "Definition should have data"
        );

        // Verify supply holder was created with balance
        let balance = get_token_balance(&state, &supply_holder_id);
        assert_eq!(balance, 1_000_000, "Supply holder should have full supply");
    }

    #[test]
    fn test_token_transfer_succeeds() {
        let (mut state, _merkle, _registration) =
            state_with_programs().expect("Programs should load");

        let (from_key, from_id) = create_test_keypair(1);
        let (to_key, to_id) = create_test_keypair(2);
        let (definition_key, definition_id) = create_test_keypair(10);

        // Create token
        let create_tx = build_token_create_tx(
            &definition_id,
            &definition_key,
            &from_id,
            &from_key,
            1_000_000,
            b"TESTOK",
        );
        state
            .transition_from_public_transaction(&create_tx, 1, 0)
            .expect("Create should succeed");

        // Transfer
        let transfer_tx = build_token_transfer_tx(
            &from_id,
            &to_id,
            &from_key,
            Some(&to_key),
            Nonce(1), // nonce after create
            Nonce(0),
            100_000,
        );
        let result = state.transition_from_public_transaction(&transfer_tx, 1, 0);
        assert!(result.is_ok(), "Transfer should succeed: {:?}", result);

        // Verify balances
        let from_balance = get_token_balance(&state, &from_id);
        assert_eq!(from_balance, 900_000, "From should have 900k");

        let to_balance = get_token_balance(&state, &to_id);
        assert_eq!(to_balance, 100_000, "To should have 100k");
    }

    /// Shield → private-to-private transfer → deshield, with the value checked
    /// at every hop.
    ///
    /// The registry itself needs none of this: it is paid in native, and
    /// `register_from_a_private_payer` shows a private account can pay it
    /// directly. What this covers is the lifecycle AROUND such a registration —
    /// getting value into a private account, moving it between two accounts
    /// that both have no public state, and bringing it back out — and it is the
    /// only test that crosses the public/private boundary in either direction.
    ///
    /// Each private hop is asserted against a commitment rather than a balance,
    /// because a private account's post-state is only observable as its
    /// commitment. That also makes the helpers' predicted post-states part of
    /// what is under test: one that predicts wrongly fails here instead of
    /// silently handing a wrong pre-state to the next hop.
    #[test]
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn tokens_survive_a_shield_transfer_deshield_round_trip() {
        let (mut state, _merkle, _registration) =
            state_with_programs().expect("Programs should load");

        let (definition_key, definition_id) = create_test_keypair(10);
        let (funder_key, funder_id) = create_test_keypair(1);
        let (_exit_key, exit_id) = create_test_keypair(3);

        let create_tx = build_token_create_tx(
            &definition_id,
            &definition_key,
            &funder_id,
            &funder_key,
            1_000_000,
            b"ROUNDT",
        );
        state
            .transition_from_public_transaction(&create_tx, 1, 0)
            .expect("token create should succeed");

        // 1. Shield: a public holding pays into a private account.
        let alice = private_account_keys(0x31, 0x32);
        let alice_id = alice.account_id(0);
        let (shield_tx, alice_shielded) =
            shield_tokens(&funder_key, &funder_id, &alice, 400_000, &state);
        state
            .transition_from_privacy_preserving_transaction(&shield_tx, 1, 0)
            .expect("shield should succeed");

        assert_eq!(
            get_token_balance(&state, &funder_id),
            600_000,
            "the shielded amount left the public holding"
        );
        assert!(
            state
                .get_proof_for_commitment(&Commitment::new(&alice_id, &alice_shielded))
                .is_some(),
            "and arrived as a commitment to a private holding of exactly that amount"
        );

        // 2. Private → private: neither side has any public state.
        let bob = private_account_keys(0x41, 0x42);
        let bob_id = bob.account_id(0);
        let (transfer_tx, alice_after, bob_after) =
            private_token_transfer(&alice, &alice_shielded, &bob, 150_000, &state);
        state
            .transition_from_privacy_preserving_transaction(&transfer_tx, 1, 0)
            .expect("private transfer should succeed");

        assert!(
            state
                .get_proof_for_commitment(&Commitment::new(&alice_id, &alice_after))
                .is_some(),
            "the sender's remaining 250k is committed under a fresh commitment"
        );
        assert!(
            state
                .get_proof_for_commitment(&Commitment::new(&bob_id, &bob_after))
                .is_some(),
            "and the recipient's 150k under its own"
        );
        assert_eq!(
            state.get_account_by_id(bob_id),
            Account::default(),
            "a private recipient leaves nothing at its account id in public state"
        );

        // 3. Deshield: back out to a public account that never touched the funder.
        let (deshield_tx, bob_emptied) =
            deshield_tokens(&bob, &bob_after, &exit_id, 150_000, &state);
        state
            .transition_from_privacy_preserving_transaction(&deshield_tx, 1, 0)
            .expect("deshield should succeed");

        assert_eq!(
            get_token_balance(&state, &exit_id),
            150_000,
            "the whole private holding came back out to a public account"
        );
        assert!(
            state
                .get_proof_for_commitment(&Commitment::new(&bob_id, &bob_emptied))
                .is_some(),
            "and the emptied private account is committed at zero rather than vanishing"
        );
        assert_eq!(
            get_token_balance(&state, &funder_id),
            600_000,
            "the round trip moved value without minting any: the funder is untouched since the \
             shield"
        );
    }

    // ========================================================================
    // Full Flow Tests - Direct Registration
    // ========================================================================

    #[test]
    fn test_register_succeeds() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let rate_limit = 300u64;

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            rate_limit,
            Nonce(0), // user's nonce (first tx from this account on registration program)
            0,        // next_index
        );

        let result = setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0);
        assert!(result.is_ok(), "Register should succeed: {:?}", result);
    }

    #[test]
    fn test_register_increments_total_registrations() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Initial count should be 0"
        );

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            valid_field_element(0x42),
            300,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Count should be 1 after registration"
        );
    }

    #[test]
    fn test_register_inserts_leaf() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Initial next_index should be 0"
        );

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            valid_field_element(0x42),
            300,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should be 1 after registration"
        );
    }

    // ========================================================================
    // Membership PDA Tests
    // ========================================================================

    #[test]
    fn test_register_creates_membership_pda() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let rate_limit = 300u64;

        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let membership =
            get_membership_data(&setup.state, &setup.registration, &TREE_ID, &id_commitment)
                .expect("Membership PDA should exist");

        assert_eq!(membership.leaf_index, 0, "leaf_index should be 0");
        assert_eq!(membership.rate_limit, rate_limit, "rate_limit should match");
        assert_eq!(
            membership.id_commitment, id_commitment,
            "id_commitment should match"
        );
    }

    #[test]
    fn test_register_same_commitment_twice_fails() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);

        let register_tx1 = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx1, 1, 0)
            .expect("First register should succeed");

        assert!(membership_exists(
            &setup.state,
            &setup.registration,
            &TREE_ID,
            &id_commitment
        ));

        let register_tx2 = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(1), 1);
        let result = setup
            .state
            .transition_from_public_transaction(&register_tx2, 1, 0);
        assert!(
            result.is_err(),
            "Second registration with same id_commitment should fail"
        );
    }

    // ========================================================================
    // Slash Tests
    // ========================================================================

    #[test]
    fn test_slash_succeeds() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert!(membership_exists(
            &setup.state,
            &setup.registration,
            &TREE_ID,
            &id_commitment
        ));

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        let result = setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0);
        assert!(result.is_ok(), "Slash should succeed: {:?}", result);
    }

    #[test]
    fn test_slash_zeros_membership_pda() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert!(
            !membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            "Membership PDA should be zeroed after slash"
        );
    }

    #[test]
    fn test_slash_decrements_total_registrations() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Count should be 1 after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Count should be 0 after slash"
        );
    }

    #[test]
    fn test_slash_updates_merkle_root() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);
        let root_before_register = get_tree_root(&setup.state, &setup.registration, &TREE_ID);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let root_after_register = get_tree_root(&setup.state, &setup.registration, &TREE_ID);
        assert_ne!(
            root_after_register, root_before_register,
            "Root should change after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        let root_after_slash = get_tree_root(&setup.state, &setup.registration, &TREE_ID);
        assert_eq!(
            root_after_slash, root_before_register,
            "Root should return to empty root after slash"
        );
    }

    #[test]
    fn test_slash_does_not_change_next_index() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should be 1 after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should still be 1 after slash"
        );
    }

    #[test]
    fn test_slash_invalid_secret_fails() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (_, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Try to slash with a DIFFERENT identity_secret
        let (wrong_secret, _) = create_slashable_identity(0x99);
        let slash_tx = build_slash_tx(&setup, &TREE_ID, wrong_secret, id_commitment, 0);

        let result = setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0);
        assert!(
            result.is_err(),
            "Slash with wrong identity_secret should fail"
        );
    }

    #[test]
    fn test_slash_double_slash_fails() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("First slash should succeed");

        assert!(!membership_exists(
            &setup.state,
            &setup.registration,
            &TREE_ID,
            &id_commitment
        ));

        let slash_tx2 = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        let result = setup
            .state
            .transition_from_public_transaction(&slash_tx2, 1, 0);
        assert!(result.is_err(), "Double slash should fail");
    }

    // ========================================================================
    // Rate Limit Cap Tests
    // ========================================================================

    #[test]
    fn test_total_rate_limit_cap_enforced() {
        // Initialize with max_total_rate_limit = 500 (only allows one registration at rate 300)
        let mut setup = state_with_initialized_registration_config(
            500, // max_total_rate_limit - only 500 total allowed
        )
        .expect("Setup should succeed");

        // First registration with rate_limit=300 should succeed
        let id_commitment1 = [0x01u8; 32];
        let register_tx1 = build_register_tx(&setup, &TREE_ID, id_commitment1, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx1, 1, 0)
            .expect("First registration should succeed");

        // Second registration with rate_limit=300 should fail (would exceed 500 cap)
        let id_commitment2 = [0x02u8; 32];
        let register_tx2 = build_register_tx(&setup, &TREE_ID, id_commitment2, 300, Nonce(1), 1);
        let result = setup
            .state
            .transition_from_public_transaction(&register_tx2, 1, 0);
        assert!(
            result.is_err(),
            "Second registration should fail (exceeds max_total_rate_limit)"
        );
    }

    // ========================================================================
    // Native Payment Tests
    // ========================================================================
    //
    // The registry knows one asset and it is the native one. `register` and
    // `extend` move the price by assigning to the payer's and treasury's
    // `account.balance`, and the SPEL macro turns those assignments into
    // BalanceDiffs. What that buys is enforcement by consensus rather than by
    // the guest: the protocol resolves the payer's real pre-state, refuses a
    // decrease on an unauthorized account (UnauthorizedBalanceDecrease), and
    // refuses any diff whose credits do not equal its debits
    // (MismatchedTotalBalance).
    //
    // These four pin what is left for the guest to get wrong: the amounts, the
    // destination, the affordability check, and the conservation invariant.

    /// Every account a `Register` transaction declares, in the order
    /// `build_register_tx_parts` lists them. `MismatchedTotalBalance` is
    /// evaluated over exactly this set, so a conservation check has to sum over
    /// exactly this set too.
    fn register_account_ids(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
        next_index: u64,
    ) -> Vec<AccountId> {
        let program = crate::spel_seeds::program_account(&setup.registration.id());
        vec![
            derive_config_pda(program, tree_id),
            derive_tree_main_pda(program, tree_id),
            setup.payer_id,
            setup.treasury_id,
            derive_subtree_pda(program, tree_id, subtree_id_for_index(next_index)),
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            derive_membership_pda(program, tree_id, id_commitment),
        ]
    }

    /// The registration price leaves the payer and arrives at the treasury, to
    /// the unit, in native balance.
    ///
    /// The treasury is deliberately never seeded: no program can mint native
    /// balance, but a *credit* lands on an account that has never been written
    /// to, which is what lets a deployment name a treasury without creating it.
    #[test]
    fn register_debits_payer_and_credits_treasury_natively() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let rate_limit = 300u64;
        let price = u128::from(rate_limit) * PRICE_PER_UNIT;

        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let treasury_before = native_balance(&setup.state, &setup.treasury_id);
        assert_eq!(
            payer_before, DEFAULT_PAYER_BALANCE,
            "the payer starts with the balance it was funded with"
        );
        assert_eq!(
            treasury_before, 0,
            "the treasury account has never been written to"
        );

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            valid_field_element(0x42),
            rate_limit,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            payer_before - price,
            "the payer is debited exactly rate_limit * price_per_unit"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.treasury_id),
            treasury_before + price,
            "the treasury is credited exactly the same amount"
        );
    }

    /// SECURITY (payment routing): consensus decides that the price is paid and
    /// that it is paid by the signer, but not WHERE it lands. The treasury-id
    /// check in the guest is the only thing that does, and it is the only
    /// routing guarantee `register` still has — so it gets its own test.
    #[test]
    fn register_rejects_a_treasury_that_is_not_the_configured_one() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (_attacker_key, attacker_treasury) = create_test_keypair(9);
        assert_ne!(
            attacker_treasury, setup.treasury_id,
            "the substituted treasury must actually differ"
        );

        let register_tx = build_register_tx_parts(
            &setup.registration,
            &TREE_ID,
            &setup.payer_id,
            &setup.payer_key,
            &attacker_treasury,
            valid_field_element(0x42),
            300,
            Nonce(0),
            0,
        );
        let result = setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0);
        assert!(
            result.is_err(),
            "register must reject a treasury the config does not name; got Ok: {result:?}"
        );

        assert_eq!(
            native_balance(&setup.state, &attacker_treasury),
            0,
            "the substituted treasury must not have been paid"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE,
            "a rejected registration must not debit the payer"
        );
        assert!(
            !membership_exists(
                &setup.state,
                &setup.registration,
                &TREE_ID,
                &valid_field_element(0x42)
            ),
            "a rejected registration must not mint a membership"
        );
    }

    /// The `Insufficient balance` path, now native. One unit short of the price
    /// is enough: the assert is `>=`, and an off-by-one that made it `>` would
    /// otherwise pass every test that funds the payer generously.
    #[test]
    fn register_rejects_an_underfunded_payer() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let rate_limit = 300u64;
        let price = u128::from(rate_limit) * PRICE_PER_UNIT;
        let payer_id = setup.payer_id;
        fund_native(&mut setup.state, &payer_id, price - 1);

        let id_commitment = valid_field_element(0x42);
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        let result = setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0);
        assert!(
            result.is_err(),
            "a payer one unit short of the price must be refused; got Ok: {result:?}"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            price - 1,
            "the refused registration must leave the payer's balance alone"
        );
        assert!(
            !membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            "a refused registration must not mint a membership"
        );

        // Positive control: the same transaction against one more unit of
        // balance succeeds, so the rejection above is about the amount and not
        // about anything else this setup does.
        fund_native(&mut setup.state, &payer_id, price);
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("a payer holding exactly the price must be accepted");
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            0,
            "paying exactly the price empties the payer"
        );
    }

    /// The invariant `MismatchedTotalBalance` enforces, asserted from the
    /// outside: across the whole transaction, native balance is neither created
    /// nor destroyed.
    ///
    /// This is the one a future refactor breaks silently — a debit that forgets
    /// its matching credit still leaves a working registration behind, and
    /// every other test in this file would still pass.
    #[test]
    fn register_conserves_total_balance() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let accounts = register_account_ids(&setup, &TREE_ID, &id_commitment, 0);
        let total_before: u128 = accounts
            .iter()
            .map(|id| native_balance(&setup.state, id))
            .sum();

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let total_after: u128 = accounts
            .iter()
            .map(|id| native_balance(&setup.state, id))
            .sum();
        assert_eq!(
            total_after, total_before,
            "a registration must move native balance, never mint or burn it"
        );
        assert!(
            native_balance(&setup.state, &setup.treasury_id) > 0,
            "conservation is vacuous unless the transfer actually happened"
        );
    }

    /// A registration whose payer is a PRIVATE account.
    ///
    /// This is the capability the privacy helpers exist to prove, and the
    /// reason the native-payment rewrite did not cost the registry its
    /// unlinkability story. Privacy is transparent to guest logic: `pre_states`
    /// carries `is_authorized` whether an account is public or private, and a
    /// private account proves that authorization inside the circuit with its
    /// own credential instead of with a signature. So `register`'s
    /// `#[account(signer)] payer` and its `payer.account.balance -= price`
    /// work unchanged against an account that has no public state at all —
    /// `validate_execution` decides `UnauthorizedBalanceDecrease` without ever
    /// asking whether the account is public or private.
    ///
    /// What that buys: an unlinkable registration needs no intermediate credit
    /// token. The payer can stay private through the whole flow and never has
    /// to deshield in order to pay.
    #[test]
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn register_from_a_private_payer() {
        let Some(setup) = state_with_initialized_registration() else {
            eprintln!("skipping private-payer registration: guest .bin not built");
            return;
        };
        let TestSetup {
            mut state,
            merkle,
            registration,
            treasury_id,
            ..
        } = setup;

        let rate_limit = 300u64;
        let price = u128::from(rate_limit) * PRICE_PER_UNIT;
        let id_commitment = valid_field_element(0x43);
        let subtree_id = subtree_id_for_index(0);

        // The payer exists only as a commitment — seeded alongside the
        // nullifier its own init would have published, so the set has the shape
        // a real init leaves behind rather than a commitment from nowhere.
        let payer_keys = private_account_keys(0x21, 0x22);
        let payer_id = payer_keys.account_id(0);
        let payer_pre = Account {
            balance: DEFAULT_PAYER_BALANCE,
            nonce: Nonce::private_account_nonce_init(&payer_id),
            ..Account::default()
        };
        let payer_commitment = Commitment::new(&payer_id, &payer_pre);
        state = state.with_private_accounts([(
            payer_commitment,
            Nullifier::for_account_initialization(&payer_id),
        )]);

        assert_eq!(
            state.get_account_by_id(payer_id),
            Account::default(),
            "the payer holds its balance privately: nothing at its account id in public state"
        );
        assert_eq!(
            native_balance(&state, &treasury_id),
            0,
            "the treasury account has never been written to"
        );

        let program = crate::spel_seeds::program_account(&registration.id());
        let account_ids = [
            derive_config_pda(program, &TREE_ID),
            derive_tree_main_pda(program, &TREE_ID),
            payer_id,
            treasury_id,
            derive_subtree_pda(program, &TREE_ID, subtree_id),
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            derive_membership_pda(program, &TREE_ID, &id_commitment),
        ];

        // Only the payer is authorized. A public account in a
        // privacy-preserving transaction is authorized only by signing (see
        // `ValidatedStateDiff::from_privacy_preserving_transaction`, which
        // rebuilds these from the signer set), and none of these sign: the PDAs
        // are written by ownership, and the treasury is only credited — a
        // credit needs no authorization.
        let public_pre =
            |id: AccountId| AccountWithMetadata::new(state.get_account_by_id(id), false, id);
        let pre_states = vec![
            public_pre(account_ids[0]),
            public_pre(account_ids[1]),
            AccountWithMetadata::new(
                payer_pre.clone(),
                true,
                (&payer_keys.npk(), &payer_keys.vpk(), 0_u128),
            ),
            public_pre(account_ids[3]),
            public_pre(account_ids[4]),
            public_pre(account_ids[5]),
            public_pre(account_ids[6]),
        ];

        let payer_proof = state
            .get_proof_for_commitment(&payer_commitment)
            .expect("the payer's commitment was just seeded");
        let account_identities = vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
            private_update_identity(&payer_keys, 0, payer_proof),
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
            InputAccountIdentity::Public,
        ];

        let instruction_data = Program::serialize_instruction(Instruction::Register {
            tree_id: TREE_ID,
            id_commitment,
            rate_limit,
            subtree_id,
        })
        .expect("Register instruction should serialize");

        // The merkle program has to be declared: `register` chain-calls it to
        // insert the leaf, and the privacy circuit resolves a chained call only
        // against the dependencies it was handed.
        let program_with_dependencies = ProgramWithDependencies::new(
            registration.clone(),
            program,
            HashMap::from([(
                crate::spel_seeds::program_account(&merkle.id()),
                merkle.clone(),
            )]),
        );

        let (output, proof) = execute_and_prove(
            pre_states,
            instruction_data,
            account_identities,
            &program_with_dependencies,
        )
        .expect("a registration paid from a private account should execute and prove");

        // No public account signs, so the message carries no nonces and the
        // witness set no signatures — the only credential in the transaction is
        // the payer's, inside the proof.
        let message = PrivacyMessage::from_circuit_output(vec![], output);
        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        state
            .transition_from_privacy_preserving_transaction(&tx, 1, 0)
            .expect("the registry must accept a payer that is private");

        assert!(
            membership_exists(&state, &registration, &TREE_ID, &id_commitment),
            "the membership PDA must exist: a private payer registers like any other"
        );
        assert_eq!(
            native_balance(&state, &treasury_id),
            price,
            "the treasury is credited exactly the price, debited from an account with no public balance"
        );

        // The debit itself is only observable as a commitment: the post-state
        // the circuit committed to is the payer minus exactly the price, with
        // the nonce its own nsk advances to. If the guest had debited some
        // other amount, this commitment would not be in the set.
        let payer_post = Account {
            balance: DEFAULT_PAYER_BALANCE - price,
            nonce: payer_pre
                .nonce
                .private_account_nonce_increment(&payer_keys.nsk()),
            ..Account::default()
        };
        assert!(
            state
                .get_proof_for_commitment(&Commitment::new(&payer_id, &payer_post))
                .is_some(),
            "the payer's post-state commitment must be in the set — that is the whole record of \
             the debit, and it pins the amount"
        );
        assert_eq!(
            state.get_account_by_id(payer_id),
            Account::default(),
            "and the payer still has no public state: the registration did not deanonymize it"
        );
    }

    #[test]
    fn test_current_total_rate_limit_tracking() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        assert_eq!(
            get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Initial current_total_rate_limit should be 0"
        );

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);
        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID),
            300,
            "current_total_rate_limit should be 300 after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert_eq!(
            get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID),
            0,
            "current_total_rate_limit should be 0 after slash"
        );
    }

    // ========================================================================
    // RLN Proof Generation and Verification Tests
    // ========================================================================
    //
    // These tests verify that:
    // 1. Merkle proofs can be correctly extracted from on-chain state
    // 2. RLN proofs can be generated using zerokit
    // 3. Proofs verify correctly against the on-chain root
    //
    // The flow mirrors run_rln_proof.rs but operates directly on V03State
    // instead of fetching from a live network.

    use rand_chacha::ChaCha20Rng;
    use rln::prelude::{
        Fr, Hasher, IdentityKeys, PoseidonHash, RLNMerkleProof, RLNWitnessInput, hash_to_field_le,
    };

    use crate::{
        fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
        merkle_tree::{
            OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_ROOT, OFFSET_TOP_TREE_DATA, TOP_DEPTH,
            read_sparse_node,
        },
    };

    /// Computes rate_commitment = poseidon(id_commitment, rate_limit).
    /// This is the leaf value stored in the merkle tree.
    fn compute_rate_commitment(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
        let id_fr = bytes_le_to_fr(id_commitment).expect("Invalid id_commitment");
        let rate_fr = Fr::from(rate_limit);
        let hash_fr = Hasher::<PoseidonHash>::hash_pair(id_fr, rate_fr);
        fr_to_bytes_le(&hash_fr)
    }

    /// Fetches a node hash from on-chain state using the subtree model.
    ///
    /// For levels <= TOP_DEPTH (10), nodes are in the main account's top tree data (sparse format).
    /// For levels > TOP_DEPTH, nodes are in bottom subtree accounts (sparse format).
    /// Returns the cached default if the node doesn't exist.
    fn fetch_node_from_state(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        level: u8,
        node_index: u64,
        cached_defaults: &[[u8; 32]],
    ) -> [u8; 32] {
        let level = level as usize;

        if level <= TOP_DEPTH {
            // Node is in top tree (sparse format in main account after OFFSET_TOP_TREE_DATA)
            let tree_main_id = derive_tree_main_pda(
                crate::spel_seeds::program_account(&registration.id()),
                tree_id,
            );
            let main_account = state.get_account_by_id(tree_main_id);
            let data = main_account.data.as_ref();

            let top_tree_data = if data.len() > OFFSET_TOP_TREE_DATA {
                &data[OFFSET_TOP_TREE_DATA..]
            } else {
                &[]
            };
            read_sparse_node(
                top_tree_data,
                level,
                node_index as usize,
                &cached_defaults[level],
            )
        } else {
            // Node is in a bottom subtree (sparse format)
            let bottom_level = level - TOP_DEPTH;
            let nodes_per_subtree_at_level = 1usize << bottom_level;
            let sid = (node_index as usize / nodes_per_subtree_at_level) as u32;
            let local_index = node_index as usize % nodes_per_subtree_at_level;

            let subtree_account_id = derive_subtree_pda(
                crate::spel_seeds::program_account(&registration.id()),
                tree_id,
                sid,
            );
            let subtree_account = state.get_account_by_id(subtree_account_id);
            let data = subtree_account.data.as_ref();

            read_sparse_node(data, bottom_level, local_index, &cached_defaults[level])
        }
    }

    /// Extracts merkle proof from V03State for a given leaf index.
    fn get_merkle_proof_from_state(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        leaf_index: u64,
    ) -> (Vec<[u8; 32]>, Vec<u8>, [u8; 32], [u8; 32]) {
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
        );
        let tree_main = state.get_account_by_id(tree_main_id);
        let main_data = tree_main.data.as_ref();

        let depth = main_data[OFFSET_DEPTH] as usize;
        let root: [u8; 32] = main_data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();

        // Extract cached defaults
        let cached_defaults: Vec<[u8; 32]> = (0..=depth)
            .map(|i| {
                let start = OFFSET_CACHED_NODES + i * 32;
                main_data[start..start + 32].try_into().unwrap()
            })
            .collect();

        // Fetch the leaf
        let leaf = fetch_node_from_state(
            state,
            registration,
            tree_id,
            depth as u8,
            leaf_index,
            &cached_defaults,
        );

        // Collect sibling hashes
        let mut path_elements: Vec<[u8; 32]> = Vec::with_capacity(depth);
        let mut path_indices: Vec<u8> = Vec::with_capacity(depth);
        let mut current_index = leaf_index;

        for level in (1..=depth).rev() {
            let node_index = current_index;
            let is_right_child = (node_index % 2) as u8;
            path_indices.push(is_right_child);

            let sibling_index = if node_index.is_multiple_of(2) {
                node_index + 1
            } else {
                node_index - 1
            };

            let sibling = fetch_node_from_state(
                state,
                registration,
                tree_id,
                level as u8,
                sibling_index,
                &cached_defaults,
            );

            path_elements.push(sibling);
            current_index /= 2;
        }

        (path_elements, path_indices, root, leaf)
    }

    /// Verifies a merkle proof by recomputing the root.
    fn verify_merkle_proof_local(
        leaf: &[u8; 32],
        path_elements: &[[u8; 32]],
        path_indices: &[u8],
    ) -> [u8; 32] {
        let mut current = bytes_le_to_fr(leaf).expect("Invalid leaf");

        for (sibling_bytes, &path_index) in path_elements.iter().zip(path_indices.iter()) {
            let sibling = bytes_le_to_fr(sibling_bytes).expect("Invalid sibling");

            let (left, right) = if path_index == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };

            current = Hasher::<PoseidonHash>::hash_pair(left, right);
        }

        fr_to_bytes_le(&current)
    }

    #[test]
    fn test_merkle_proof_extraction_from_state() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let rate_limit = 300u64;

        // Register a member
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Extract merkle proof
        let (path_elements, path_indices, root, leaf) =
            get_merkle_proof_from_state(&setup.state, &setup.registration, &TREE_ID, 0);

        // Verify proof structure
        assert_eq!(
            path_elements.len(),
            TREE_DEPTH,
            "Path should have {} elements",
            TREE_DEPTH
        );
        assert_eq!(
            path_indices.len(),
            TREE_DEPTH,
            "Path indices should have {} elements",
            TREE_DEPTH
        );

        // Verify leaf matches expected rate commitment
        let expected_leaf = compute_rate_commitment(&id_commitment, rate_limit);
        assert_eq!(leaf, expected_leaf, "Leaf should match rate commitment");

        // Verify proof by recomputing root
        let computed_root = verify_merkle_proof_local(&leaf, &path_elements, &path_indices);
        assert_eq!(
            computed_root, root,
            "Computed root should match on-chain root"
        );
    }

    #[test]
    fn test_rln_proof_generation_and_verification() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        // Create identity using zerokit's seeded keygen (like run_rln_proof does)
        let seed = [0x42u8; 32]; // deterministic seed for testing
        let identity_keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&seed);
        let identity_secret = identity_keys.identity_secret();

        let id_commitment: [u8; 32] = fr_to_bytes_le(&identity_keys.id_commitment());
        let rate_limit = 300u64;

        // Register the identity
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Extract merkle proof from state
        let (path_elements_bytes, path_indices, root_bytes, leaf_bytes) =
            get_merkle_proof_from_state(&setup.state, &setup.registration, &TREE_ID, 0);

        // Convert to Fr types for zerokit, then lift both the path and the
        // root from the tree's depth to the circuit's — see `proof_circuit`.
        let mut path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
            .collect();
        let mut path_indices = path_indices;
        crate::proof_circuit::pad_path(&mut path_elements, &mut path_indices);
        let root =
            crate::proof_circuit::fold_root(bytes_le_to_fr(&root_bytes).expect("Invalid root"));

        // Verify the leaf matches what we expect
        let expected_leaf = compute_rate_commitment(&id_commitment, rate_limit);
        assert_eq!(
            leaf_bytes, expected_leaf,
            "On-chain leaf should match computed rate commitment"
        );

        // Create RLN witness
        let user_message_limit = Fr::from(rate_limit);
        let message_id = Fr::from(0u64);

        // Compute external nullifier = poseidon(epoch, rln_identifier)
        let epoch_fr = hash_to_field_le(b"test-epoch");
        let rln_identifier_fr = hash_to_field_le(b"lssa-rln-test");
        let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch_fr, rln_identifier_fr);

        // Compute signal hash (x) = hash of message
        let x = hash_to_field_le(b"Hello, RLN!");

        // Create RLN witness input
        let witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(user_message_limit)
            .merkle_proof(RLNMerkleProof::new(path_elements, path_indices))
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(message_id)
            .build()
            .expect("Failed to create RLN witness");

        // Initialize RLN instance
        let rln = crate::proof_circuit::engine();

        // Generate the proof
        let (rln_proof, proof_values) = rln
            .generate_proof(&witness)
            .expect("Failed to generate RLN proof");

        // Verify proof values match
        assert_eq!(
            proof_values.root(),
            root,
            "Proof root should match on-chain root"
        );

        // Verify the RLN proof with root check
        let is_valid = rln
            .verify_with_roots(&rln_proof, &proof_values, &x, &[root])
            .expect("Failed to verify proof");

        assert!(is_valid, "RLN proof should be valid");
    }

    #[test]
    fn test_rln_proof_with_multiple_registrations() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        // Use rate_limit = 100 for all to fit within user's 10M token budget
        // (3 registrations * 100 * 10,000 = 3M tokens)

        // Register first identity
        let seed1 = [0x01u8; 32];
        let identity_keys1 = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&seed1);
        let id_commitment1: [u8; 32] = fr_to_bytes_le(&identity_keys1.id_commitment());

        let register_tx1 = build_register_tx(&setup, &TREE_ID, id_commitment1, 100, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx1, 1, 0)
            .expect("First register should succeed");

        // Register second identity (this is the one we'll prove)
        let seed2 = [0x02u8; 32];
        let identity_keys2 = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&seed2);
        let identity_secret2 = identity_keys2.identity_secret();
        let id_commitment2: [u8; 32] = fr_to_bytes_le(&identity_keys2.id_commitment());
        let rate_limit2 = 100u64;

        let register_tx2 =
            build_register_tx(&setup, &TREE_ID, id_commitment2, rate_limit2, Nonce(1), 1);
        setup
            .state
            .transition_from_public_transaction(&register_tx2, 1, 0)
            .expect("Second register should succeed");

        // Register third identity
        let seed3 = [0x03u8; 32];
        let identity_keys3 = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&seed3);
        let id_commitment3: [u8; 32] = fr_to_bytes_le(&identity_keys3.id_commitment());

        let register_tx3 = build_register_tx(&setup, &TREE_ID, id_commitment3, 100, Nonce(2), 2);
        setup
            .state
            .transition_from_public_transaction(&register_tx3, 1, 0)
            .expect("Third register should succeed");

        // Extract merkle proof for second identity (index 1)
        let (path_elements_bytes, path_indices, root_bytes, leaf_bytes) =
            get_merkle_proof_from_state(&setup.state, &setup.registration, &TREE_ID, 1);

        // Convert to Fr types
        let mut path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
            .collect();
        // Lift path and root from the tree's depth to the circuit's.
        let mut path_indices = path_indices;
        crate::proof_circuit::pad_path(&mut path_elements, &mut path_indices);
        let root =
            crate::proof_circuit::fold_root(bytes_le_to_fr(&root_bytes).expect("Invalid root"));

        // Verify the leaf
        let expected_leaf = compute_rate_commitment(&id_commitment2, rate_limit2);
        assert_eq!(leaf_bytes, expected_leaf, "Leaf should match");

        // Create and verify RLN proof
        let user_message_limit = Fr::from(rate_limit2);
        let message_id = Fr::from(0u64);
        let epoch_fr = hash_to_field_le(b"test-epoch-2");
        let rln_identifier_fr = hash_to_field_le(b"lssa-rln-test");
        let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch_fr, rln_identifier_fr);
        let x = hash_to_field_le(b"Another message");

        let witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret2)
            .user_message_limit(user_message_limit)
            .merkle_proof(RLNMerkleProof::new(path_elements, path_indices))
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(message_id)
            .build()
            .expect("Failed to create RLN witness");

        let rln = crate::proof_circuit::engine();
        let (rln_proof, proof_values) = rln
            .generate_proof(&witness)
            .expect("Failed to generate RLN proof");

        assert_eq!(
            proof_values.root(),
            root,
            "Proof root should match on-chain root"
        );

        let is_valid = rln
            .verify_with_roots(&rln_proof, &proof_values, &x, &[root])
            .expect("Failed to verify proof");

        assert!(
            is_valid,
            "RLN proof should be valid with multiple registrations"
        );
    }

    #[test]
    fn test_rln_proof_invalid_after_slash() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        // Create identity using poseidon derivation (for slash compatibility)
        let identity_secret_bytes = valid_field_element(0x42);
        let id_commitment = derive_id_commitment_from_secret(&identity_secret_bytes);
        let rate_limit = 300u64;

        // Register
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Get root before slash
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            &TREE_ID,
        );
        let tree_before = setup.state.get_account_by_id(tree_main_id);
        let root_before: [u8; 32] = tree_before.data.as_ref()[9..41].try_into().unwrap();

        // Slash the member
        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret_bytes, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        // Get root after slash
        let tree_after = setup.state.get_account_by_id(tree_main_id);
        let root_after: [u8; 32] = tree_after.data.as_ref()[9..41].try_into().unwrap();

        // Root should have changed after slash
        assert_ne!(root_before, root_after, "Root should change after slash");

        // Extract merkle proof after slash
        let (_, _, root_bytes, leaf_bytes) =
            get_merkle_proof_from_state(&setup.state, &setup.registration, &TREE_ID, 0);

        // Leaf should now be the default (zero or cached default)
        let expected_rate_commitment = compute_rate_commitment(&id_commitment, rate_limit);
        assert_ne!(
            leaf_bytes, expected_rate_commitment,
            "Leaf should no longer match rate commitment after slash"
        );

        // Verify root changed to empty tree root (since this was the only member)
        let root_fr = bytes_le_to_fr(&root_bytes).expect("Invalid root");
        let root_before_register_fr = bytes_le_to_fr(&root_after).expect("Invalid root");
        assert_eq!(
            root_fr, root_before_register_fr,
            "Root should match empty tree root"
        );
    }

    #[test]
    fn test_rln_double_message_detection() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        // Create identity
        let seed = [0x99u8; 32];
        let identity_keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&seed);
        let identity_secret = identity_keys.identity_secret();
        let id_commitment: [u8; 32] = fr_to_bytes_le(&identity_keys.id_commitment());
        let rate_limit = 300u64;

        // Register
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Extract proof
        let (path_elements_bytes, path_indices, root_bytes, _) =
            get_merkle_proof_from_state(&setup.state, &setup.registration, &TREE_ID, 0);

        let mut path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
            .collect();
        // Lift path and root from the tree's depth to the circuit's.
        let mut path_indices = path_indices;
        crate::proof_circuit::pad_path(&mut path_elements, &mut path_indices);
        let root =
            crate::proof_circuit::fold_root(bytes_le_to_fr(&root_bytes).expect("Invalid root"));

        // Same epoch and message_id but different messages
        let user_message_limit = Fr::from(rate_limit);
        let message_id = Fr::from(0u64); // Same message_id for both

        let epoch_fr = hash_to_field_le(b"epoch-1");
        let rln_identifier_fr = hash_to_field_le(b"lssa-rln-test");
        let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch_fr, rln_identifier_fr);

        let merkle_proof = RLNMerkleProof::new(path_elements, path_indices);

        // First message
        let x1 = hash_to_field_le(b"First message");
        let witness1 = RLNWitnessInput::new_single()
            .identity_secret(identity_secret.clone())
            .user_message_limit(user_message_limit)
            .merkle_proof(merkle_proof.clone())
            .x(x1)
            .external_nullifier(external_nullifier)
            .message_id(message_id)
            .build()
            .expect("Failed to create witness 1");

        // Second message (different content, same message_id)
        let x2 = hash_to_field_le(b"Second message");
        let witness2 = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(user_message_limit)
            .merkle_proof(merkle_proof)
            .x(x2)
            .external_nullifier(external_nullifier)
            .message_id(message_id)
            .build()
            .expect("Failed to create witness 2");

        let rln = crate::proof_circuit::engine();

        // Generate both proofs
        let (proof1, values1) = rln
            .generate_proof(&witness1)
            .expect("Failed to generate proof 1");
        let (proof2, values2) = rln
            .generate_proof(&witness2)
            .expect("Failed to generate proof 2");

        // Both proofs should be individually valid
        let valid1 = rln
            .verify_with_roots(&proof1, &values1, &x1, &[root])
            .expect("Verify 1 failed");
        let valid2 = rln
            .verify_with_roots(&proof2, &values2, &x2, &[root])
            .expect("Verify 2 failed");
        assert!(valid1, "First proof should be valid");
        assert!(valid2, "Second proof should be valid");

        // But they should have the SAME nullifier (since same identity, epoch, message_id)
        assert_eq!(
            values1.nullifier().expect("single-mode proof"),
            values2.nullifier().expect("single-mode proof"),
            "Same identity + epoch + message_id should produce same nullifier"
        );

        // The shares (y) should be different because the signals (x) are different
        // This allows recovery of the identity secret using Shamir secret sharing
        // (This is how double-spend detection works in RLN)

        // The nullifier being the same is the detection mechanism
        // A relayer/verifier that sees two messages with the same nullifier knows
        // the sender is double-spending their rate limit
    }

    // ========================================================================
    // Expiration — time-travel helpers
    // ========================================================================

    /// Overwrite the CLOCK_50 system account with a specific timestamp so
    /// subsequent program invocations observe `now_ms == timestamp_ms`. Uses
    /// the `test-utils` `force_insert_account` escape hatch instead of issuing
    /// 50 clock-ticks, because CLOCK_50 only refreshes every 50 blocks.
    fn set_clock_50(state: &mut V03State, timestamp_ms: u64, block_id: u64) {
        use clock_core::{CLOCK_50_PROGRAM_ACCOUNT_ID, ClockAccountData};
        let data = ClockAccountData {
            block_id,
            timestamp: timestamp_ms,
        }
        .to_bytes();
        let clock_program_id = crate::spel_seeds::program_account(&programs::clock().id());
        state.force_insert_account(
            CLOCK_50_PROGRAM_ACCOUNT_ID,
            Account {
                program_owner: clock_program_id,
                data: data.try_into().expect("clock data fits"),
                ..Account::default()
            },
        );
    }

    fn read_membership(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&registration.id()),
            tree_id,
            id_commitment,
        );
        let bytes = state.get_account_by_id(membership_id).data.into_inner();
        if bytes.is_empty() { None } else { Some(bytes) }
    }

    fn read_grace_start_ms(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> u64 {
        let data = read_membership(state, registration, tree_id, id_commitment)
            .expect("membership must exist");
        u64::from_le_bytes(
            data[MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP
                ..MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP + 8]
                .try_into()
                .unwrap(),
        )
    }

    fn read_active_duration_sec(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> u32 {
        let data = read_membership(state, registration, tree_id, id_commitment)
            .expect("membership must exist");
        u32::from_le_bytes(
            data[MEMBERSHIP_OFFSET_ACTIVE_DURATION..MEMBERSHIP_OFFSET_ACTIVE_DURATION + 4]
                .try_into()
                .unwrap(),
        )
    }

    fn read_grace_duration_sec(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> u32 {
        let data = read_membership(state, registration, tree_id, id_commitment)
            .expect("membership must exist");
        u32::from_le_bytes(
            data[MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION
                ..MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION + 4]
                .try_into()
                .unwrap(),
        )
    }

    // ========================================================================
    // Expiration — transaction builders
    // ========================================================================

    /// Renewal is PAID (same price as registering the membership's rate
    /// limit), so the payer signs and is debited in native balance — extend is
    /// no longer a zero-signer transaction.
    fn build_extend_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        payer_nonce: Nonce,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
        );
        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
            &id_commitment,
        );

        let account_ids = vec![
            config_id,
            membership_id,
            setup.payer_id,
            setup.treasury_id,
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
        ];

        let instruction = Instruction::Extend {
            tree_id: *tree_id,
            id_commitment,
        };

        let message = Message::try_new(
            crate::spel_seeds::program_account(&setup.registration.id()),
            account_ids,
            vec![payer_nonce], // nonce for the payer (index 2)
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[&setup.payer_key]),
        )
    }

    fn build_erase_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        leaf_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
        );
        let tree_main_id = derive_tree_main_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
        );
        let membership_id = derive_membership_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
            &id_commitment,
        );
        let sid = subtree_id_for_index(leaf_index);
        let subtree_account_id = derive_subtree_pda(
            crate::spel_seeds::program_account(&setup.registration.id()),
            tree_id,
            sid,
        );

        let account_ids = vec![
            config_id,
            tree_main_id,
            membership_id,
            subtree_account_id,
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
        ];

        let instruction = Instruction::Erase {
            tree_id: *tree_id,
            id_commitment,
            subtree_id: sid,
        };

        let message = Message::try_new(
            crate::spel_seeds::program_account(&setup.registration.id()),
            account_ids,
            vec![],
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[]))
    }

    // ========================================================================
    // Expiration — state tests
    // ========================================================================

    /// Rate limit used across the expiration tests (within [MIN, MAX]).
    const EXP_RATE_LIMIT: u64 = 300;

    fn setup_with_expiration() -> Option<TestSetup> {
        state_with_initialized_registration_durations(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
    }

    fn register_for_expiration_test(setup: &mut TestSetup, id_commitment: [u8; 32]) {
        let register_tx =
            build_register_tx(setup, &TREE_ID, id_commitment, EXP_RATE_LIMIT, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("register should succeed");
    }

    #[test]
    fn test_register_snapshots_grace_period_start() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        let register_clock_ms = GENESIS_TIMESTAMP_MS + 500;
        set_clock_50(&mut setup.state, register_clock_ms, 50);

        let id_commitment = valid_field_element(0xA1);
        register_for_expiration_test(&mut setup, id_commitment);

        assert_eq!(
            read_grace_start_ms(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            register_clock_ms + ACTIVE_MS,
            "grace_period_start_timestamp_ms = now_ms + ACTIVE_MS",
        );
        assert_eq!(
            read_active_duration_sec(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            DEFAULT_ACTIVE_DURATION_SEC,
        );
        assert_eq!(
            read_grace_duration_sec(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        );
    }

    /// A fresh chain carries the genesis CLOCK_50 (timestamp 0) until the
    /// sequencer's first refresh of it at block 50. Registering against that
    /// would stamp the membership's whole lifetime in 1970 and expire it the
    /// moment the clock is first written, so the program refuses instead.
    #[test]
    fn test_register_is_refused_while_the_clock_reads_zero() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, 0, 0);

        let id_commitment = valid_field_element(0xB2);
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, EXP_RATE_LIMIT, Nonce(0), 0);
        assert!(
            setup
                .state
                .transition_from_public_transaction(&register_tx, 1, 0)
                .is_err(),
            "register must fail while CLOCK_50 still reads its genesis zero",
        );
        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment).is_none(),
            "no membership may exist after the refused registration",
        );
    }

    /// The production defaults, over a realistic wall-clock timeline.
    ///
    /// Regression guard for the bug that turned a 30-day membership into a
    /// 43-minute one. The rest of this suite runs on compressed durations
    /// where a 1000x error is invisible; this one pins real days.
    #[test]
    fn test_production_durations_span_real_days_of_chain_time() {
        use crate::rln::client::{
            DEFAULT_ACTIVE_DURATION_SECS, DEFAULT_GRACE_PERIOD_DURATION_SECS,
        };

        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

        let Some(mut setup) = state_with_initialized_registration_durations(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SECS,
            DEFAULT_GRACE_PERIOD_DURATION_SECS,
        ) else {
            return;
        };

        let registered_at_ms = GENESIS_TIMESTAMP_MS;
        set_clock_50(&mut setup.state, registered_at_ms, 50);
        let id_commitment = valid_field_element(0xB1);
        register_for_expiration_test(&mut setup, id_commitment);

        assert_eq!(
            read_grace_start_ms(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            registered_at_ms + 30 * DAY_MS,
            "the active period must span 30 DAYS of chain time",
        );

        // Day 29: still active, so extending is refused.
        set_clock_50(&mut setup.state, registered_at_ms + 29 * DAY_MS, 100);
        let too_early = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        assert!(
            setup
                .state
                .transition_from_public_transaction(&too_early, 2, 0)
                .is_err(),
            "membership must still be active 29 days after registration",
        );

        // Day 31: inside the 7-day grace period, so extending succeeds.
        set_clock_50(&mut setup.state, registered_at_ms + 31 * DAY_MS, 150);
        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 3, 0)
            .expect("extend must succeed 31 days in (grace period)");
        assert_eq!(
            read_grace_start_ms(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            registered_at_ms + (30 + 7 + 30) * DAY_MS,
            "extend adds one grace + one active period",
        );

        // Day 75: past the renewed active period AND its grace, so the
        // membership is erasable.
        set_clock_50(&mut setup.state, registered_at_ms + 75 * DAY_MS, 200);
        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 4, 0)
            .expect("erase must succeed once the renewed membership expired");
        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment).is_none(),
            "membership data should be cleared",
        );
    }

    #[test]
    fn test_extend_succeeds_in_grace_period() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA2);
        register_for_expiration_test(&mut setup, id_commitment);

        let grace_start_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS;
        let in_grace_ms = grace_start_ms + (GRACE_MS / 2);
        set_clock_50(&mut setup.state, in_grace_ms, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0)
            .expect("extend during grace must succeed");

        let new_grace_start_ms =
            read_grace_start_ms(&setup.state, &setup.registration, &TREE_ID, &id_commitment);
        let expected = grace_start_ms + GRACE_MS + ACTIVE_MS;
        assert_eq!(
            new_grace_start_ms, expected,
            "grace_start += grace + active"
        );
    }

    #[test]
    fn test_extend_fails_when_still_active() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA3);
        register_for_expiration_test(&mut setup, id_commitment);

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + 10, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        let result = setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0);
        assert!(
            result.is_err(),
            "extend during active period must fail, got {:?}",
            result
        );
    }

    #[test]
    fn test_extend_fails_when_expired() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA4);
        register_for_expiration_test(&mut setup, id_commitment);

        let expiration_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS;
        set_clock_50(&mut setup.state, expiration_ms + 1, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        let result = setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0);
        assert!(
            result.is_err(),
            "extend after expiration must fail, got {:?}",
            result
        );
    }

    // SECURITY (rate-limit pinning): extend deliberately does NOT check caller
    // identity — a membership records no owner, and letting a third party pay
    // for someone's renewal is harmless. What stops the grief is the PRICE.
    // While renewal was free, anyone could keep an abandoned membership alive
    // one cheap tx per grace window; `erase` only reclaims rate_limit once a
    // membership expires, so an attacker could pin current_total_rate_limit at
    // max_total_rate_limit and block every new registration indefinitely.
    #[test]
    fn test_extend_by_a_third_party_is_allowed_but_charged() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA5);
        register_for_expiration_test(&mut setup, id_commitment);

        let in_grace_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        set_clock_50(&mut setup.state, in_grace_ms, 100);

        let paid_before = native_balance(&setup.state, &setup.payer_id);
        let treasury_before = native_balance(&setup.state, &setup.treasury_id);
        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0)
            .expect("a paying third party may renew");

        let paid_after = native_balance(&setup.state, &setup.payer_id);
        let expected = EXP_RATE_LIMIT as u128 * PRICE_PER_UNIT;
        assert_eq!(
            paid_before - paid_after,
            expected,
            "renewal must cost the same as registering that rate limit"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.treasury_id) - treasury_before,
            expected,
            "and the renewal price must land on the configured treasury"
        );
        assert!(
            expected > 0,
            "a zero-priced renewal would restore the grief"
        );
    }

    /// The grief itself: without funds the renewal fails, so pinning a
    /// membership's rate limit forever is no longer free.
    #[test]
    fn test_extend_fails_when_payer_cannot_cover_the_price() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA7);
        register_for_expiration_test(&mut setup, id_commitment);

        // Drain the payer's native balance, keeping its nonce (the register
        // above already signed once), then try to renew.
        let in_grace_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        set_clock_50(&mut setup.state, in_grace_ms, 100);
        let prior = setup.state.get_account_by_id(setup.payer_id);
        setup.state.force_insert_account(
            setup.payer_id,
            Account {
                balance: 0,
                ..prior
            },
        );

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        assert!(
            setup
                .state
                .transition_from_public_transaction(&extend_tx, 2, 0)
                .is_err(),
            "an unfunded renewal must fail"
        );
    }

    #[test]
    fn test_erase_succeeds_when_expired() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA6);
        register_for_expiration_test(&mut setup, id_commitment);

        let expiration_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS;
        set_clock_50(&mut setup.state, expiration_ms + 1, 100);

        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0)
            .expect("erase of expired membership must succeed");

        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment).is_none(),
            "membership data should be cleared",
        );
    }

    #[test]
    fn test_erase_fails_when_active() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA7);
        register_for_expiration_test(&mut setup, id_commitment);

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + 1, 100);

        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        let result = setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0);
        assert!(
            result.is_err(),
            "erase during active period must fail, got {:?}",
            result
        );
    }

    #[test]
    fn test_erase_fails_in_grace_period() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xA8);
        register_for_expiration_test(&mut setup, id_commitment);

        let in_grace_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1;
        set_clock_50(&mut setup.state, in_grace_ms, 100);

        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        let result = setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0);
        assert!(
            result.is_err(),
            "erase during grace period must fail (use extend, or wait until expired)"
        );
    }

    #[test]
    fn test_erase_decrements_total_rate_limit() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let id_commitment = valid_field_element(0xAA);
        register_for_expiration_test(&mut setup, id_commitment);

        let before = get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID);
        assert_eq!(before, EXP_RATE_LIMIT);

        let expiration_ms = GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS;
        set_clock_50(&mut setup.state, expiration_ms + 1, 100);

        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0)
            .expect("erase must succeed");

        let after = get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID);
        assert_eq!(after, 0, "current_total_rate_limit must drop back to 0");
    }
}
