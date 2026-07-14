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
    use nssa::program::Program;
    use programs;
    use nssa::program_deployment_transaction::{Message as DeployMessage, ProgramDeploymentTransaction};
    use nssa::public_transaction::{Message, WitnessSet};
    use nssa::{PrivateKey, PublicKey};
    use nssa::{PublicTransaction, V03State};
    use nssa_core::account::{AccountId, Nonce};
    use std::fs;

    // Privacy-preserving transaction types — only used by the rc5-era
    // privacy-flow helpers/tests that are gated behind rc5-state-tests-privacy.
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa::{
        execute_and_prove, PrivacyPreservingTransaction, SharedSecretKey,
    };
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa::privacy_preserving_transaction::{
        message::Message as PrivacyMessage,
        witness_set::WitnessSet as PrivacyWitnessSet,
        circuit::ProgramWithDependencies,
    };
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::{
        Commitment, NullifierPublicKey, NullifierSecretKey,
    };
    use nssa_core::account::{Account, Data};
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::account::AccountWithMetadata;
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::encryption::ViewingPublicKey;
    #[cfg(feature = "rc5-state-tests-privacy")]
    use nssa_core::{EncryptedAccountData, InputAccountIdentity};
    use token_core::{TokenDefinition, TokenHolding};
    #[cfg(feature = "rc5-state-tests-privacy")]
    use std::collections::HashMap;

    // Import shared constants and PDA functions from rln module
    use crate::rln::{
        TREE_DEPTH,
        MEMBERSHIP_SIZE, MEMBERSHIP_OFFSET_LEAF_INDEX, MEMBERSHIP_OFFSET_RATE_LIMIT,
        MEMBERSHIP_OFFSET_ID_COMMITMENT,
        MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP,
        MEMBERSHIP_OFFSET_ACTIVE_DURATION,
        MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION,
        CONFIG_OFFSET_AUTHORIZED_REGISTRAR,
        CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT,
        CONFIG_OFFSET_FREE_QUOTA_REMAINING,
        CONFIG_OFFSET_MERKLE_PROGRAM_ID,
        CONFIG_OFFSET_TREE_ID,
        CONFIG_OFFSET_PAYMENT_TOKEN_ID,
        CONFIG_OFFSET_PRICE_PER_UNIT,
        CONFIG_OFFSET_TREASURY_ACCOUNT_ID,
        CONFIG_OFFSET_TOTAL_REGISTRATIONS,
        CONFIG_SIZE,
        CLOCK_50_ACCOUNT_ID_BYTES,
        derive_tree_main_account, derive_subtree_account,
        derive_config_account, derive_credit_token_account, derive_membership_account,
        subtree_id_for_index,
    };

    use crate::rln::Instruction;

    // ========================================================================
    // Program Paths
    // ========================================================================

    /// Get the repository root from CARGO_MANIFEST_DIR
    /// The manifest is at the repo root.
    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn merkle_tree_binary_path() -> std::path::PathBuf {
        repo_root().join("methods/guest/target/riscv32im-risc0-zkvm-elf/docker/incremental_merkle_tree.bin")
    }

    fn rln_registration_binary_path() -> std::path::PathBuf {
        repo_root().join("methods/guest/target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin")
    }

    // ========================================================================
    // Constants
    // ========================================================================

    /// Test tree ID (32 bytes; first 24 carry data, last 8 zero-padded for SPEL).
    const TREE_ID: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Test-specific constant
    const PRICE_PER_UNIT: u128 = 10_000;

    /// Genesis timestamp used when seeding test state. Chosen non-zero so that
    /// time-travel tests can reason about both past and future relative to genesis.
    const GENESIS_TIMESTAMP: u64 = 1_700_000_000;

    /// Active-period length applied to newly registered memberships in tests
    /// (1 hour). Kept small so tests can exercise expiration without huge numbers.
    const DEFAULT_ACTIVE_DURATION: u32 = 3_600;

    /// Grace-period length applied to newly registered memberships in tests
    /// (10 minutes).
    const DEFAULT_GRACE_PERIOD_DURATION: u32 = 600;

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

    fn derive_tree_main_pda(program_id: nssa_core::program::ProgramId, tree_id: &[u8; 32]) -> AccountId {
        derive_tree_main_account(&program_id, tree_id)
    }

    fn derive_subtree_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
        subtree_id: u32,
    ) -> AccountId {
        derive_subtree_account(&program_id, tree_id, subtree_id)
    }

    fn derive_config_pda(program_id: nssa_core::program::ProgramId, tree_id: &[u8; 32]) -> AccountId {
        derive_config_account(&program_id, tree_id)
    }

    fn derive_credit_token_pda(program_id: nssa_core::program::ProgramId, tree_id: &[u8; 32]) -> AccountId {
        derive_credit_token_account(&program_id, tree_id)
    }

    fn derive_credit_supply_pda(program_id: nssa_core::program::ProgramId, tree_id: &[u8; 32]) -> AccountId {
        crate::rln::derive_credit_supply_account(&program_id, tree_id)
    }

    fn derive_payment_token_pda(program_id: nssa_core::program::ProgramId, tree_id: &[u8; 32]) -> AccountId {
        crate::rln::derive_payment_token_account(&program_id, tree_id)
    }

    fn derive_payment_supply_pda(program_id: nssa_core::program::ProgramId, tree_id: &[u8; 32]) -> AccountId {
        crate::rln::derive_payment_supply_account(&program_id, tree_id)
    }

    fn derive_membership_pda(
        program_id: nssa_core::program::ProgramId,
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
        let mut state = V03State::new().with_programs([programs::token(), programs::clock()]);
        set_clock_50(&mut state, GENESIS_TIMESTAMP, 0);

        // Deploy merkle tree program
        let merkle_deploy_tx = ProgramDeploymentTransaction::new(
            DeployMessage::new(merkle_bytecode)
        );
        state.transition_from_program_deployment_transaction(&merkle_deploy_tx).ok()?;

        // Deploy registration program
        let registration_deploy_tx = ProgramDeploymentTransaction::new(
            DeployMessage::new(registration_bytecode)
        );
        state.transition_from_program_deployment_transaction(&registration_deploy_tx).ok()?;

        Some((state, merkle_program, registration_program))
    }

    /// Builds a public transaction for merkle tree initialization.
    fn build_merkle_init_tx(program: &Program, tree_id: &[u8; 32]) -> PublicTransaction {
        let tree_main_id = derive_tree_main_pda(program.id(), tree_id);
        let instruction = vec![0u8]; // opcode 0 = init

        // PDA-only transaction: no nonces needed (accounts are program-derived)
        let message = Message::try_new(
            program.id(),
            vec![tree_main_id],
            vec![], // Empty nonces for PDA-only transactions
            instruction,
        ).expect("valid message");

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
        let tree_main_id = derive_tree_main_pda(program.id(), tree_id);
        let sid = subtree_id_for_index(expected_index);
        let subtree_id = derive_subtree_pda(program.id(), tree_id, sid);

        let mut instruction = vec![1u8]; // opcode 1 = insert
        instruction.extend_from_slice(&expected_index.to_le_bytes());
        instruction.extend_from_slice(&leaf_value);

        // PDA-only transaction: no nonces needed (accounts are program-derived)
        let message = Message::try_new(
            program.id(),
            vec![tree_main_id, subtree_id],
            vec![], // Empty nonces for PDA-only transactions
            instruction,
        ).expect("valid message");

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
            let subtree_0 = derive_subtree_pda(program.id(), &TREE_ID, 0);
            let subtree_1 = derive_subtree_pda(program.id(), &TREE_ID, 1);

            assert!(subtree_0 != subtree_1, "Different subtree IDs should have different PDAs");
        }
    }

    #[test]
    fn test_all_registration_pdas_are_distinct() {
        if let Some(program) = load_rln_registration_program() {
            let tree_main = derive_tree_main_pda(program.id(), &TREE_ID);
            let config = derive_config_pda(program.id(), &TREE_ID);
            let credit_token = derive_credit_token_pda(program.id(), &TREE_ID);
            let subtree = derive_subtree_pda(program.id(), &TREE_ID, 0);

            assert!(tree_main != config, "tree_main and config should differ");
            assert!(tree_main != credit_token, "tree_main and credit_token should differ");
            assert!(tree_main != subtree, "tree_main and subtree should differ");
            assert!(config != credit_token, "config and credit_token should differ");
            assert!(config != subtree, "config and subtree should differ");
            assert!(credit_token != subtree, "credit_token and subtree should differ");
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
        assert!(result.is_err(), "Direct merkle tree init should fail due to authorization");
    }

    #[test]
    fn test_direct_merkle_insert_blocked_by_authorization() {
        let (mut state, merkle, _) = state_with_programs()
            .expect("Programs should load. Run: cargo risczero build --manifest-path methods/guest/Cargo.toml");

        // Try to insert into merkle tree directly (not through registration program)
        let leaf_value = [0x42u8; 32];
        let insert_tx = build_merkle_insert_tx(&merkle, &TREE_ID, 0, leaf_value);
        let result = state.transition_from_public_transaction(&insert_tx, 1, 0);

        assert!(result.is_err(), "Direct merkle tree insert should fail due to authorization");
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
    /// rc6: viewing key derives from the two-half FIPS 203 seed `(d, z)`
    /// via `ViewingPublicKey::from_seed`; AccountId is bound to (npk, identifier).
    #[allow(dead_code)]
    #[cfg(feature = "rc5-state-tests-privacy")]
    struct PrivateAccountKeys {
        nsk: NullifierSecretKey,
        d: [u8; 32],
        z: [u8; 32],
    }

    #[allow(dead_code)]
    #[cfg(feature = "rc5-state-tests-privacy")]
    impl PrivateAccountKeys {
        fn npk(&self) -> NullifierPublicKey {
            NullifierPublicKey::from(&self.nsk)
        }

        fn vpk(&self) -> ViewingPublicKey {
            ViewingPublicKey::from_seed(&self.d, &self.z)
        }

        fn account_id(&self, identifier: u128) -> AccountId {
            AccountId::for_regular_private_account(&self.npk(), identifier)
        }
    }

    #[allow(dead_code)]
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn private_account_keys(seed1: u8, seed2: u8) -> PrivateAccountKeys {
        // rc6: ML-KEM-768 needs two 32-byte seed halves (d, z) for the FIPS-203
        // ViewingPublicKey derivation. Derive z deterministically from seed2 so
        // the helper's two-seed signature is preserved (call sites don't change).
        PrivateAccountKeys {
            nsk: { let mut b = [0u8; 32]; b[0] = seed1; b },
            d: { let mut b = [0u8; 32]; b[0] = seed2; b },
            z: { let mut b = [0u8; 32]; b[0] = seed2.wrapping_add(0x80); b[1] = seed2; b },
        }
    }

    // ========================================================================
    // Privacy-Preserving Token Transfer Helpers
    // ========================================================================

    /// Serializes a token Transfer instruction for use with execute_and_prove.
    #[allow(dead_code)]
    fn token_transfer_instruction_data(amount: u128) -> Vec<u32> {
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
            program_owner: programs::token().id(),
            balance: 0,
            nonce: Nonce(0),
            data: Data::try_from(create_token_holding_data(definition_id, balance)).unwrap(),
        }
    }

    /// Shields tokens: public token holding → new private token holding.
    /// rc6: encryption is ML-KEM-768; account identities are typed via
    /// `InputAccountIdentity`; recipient's AccountId binds (npk, identifier=0).
    ///
    /// Returns (transaction, private_account_post_state).
    #[allow(dead_code)]
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn shield_tokens(
        sender_key: &PrivateKey,
        sender_id: &AccountId,
        recipient_keys: &PrivateAccountKeys,
        amount: u128,
        state: &V03State,
    ) -> (PrivacyPreservingTransaction, Account) {
        let recipient_id = recipient_keys.account_id(0);
        let sender = AccountWithMetadata::new(
            state.get_account_by_id(sender_id.clone()),
            true,
            *sender_id,
        );
        let sender_nonce = sender.account.nonce;
        let recipient = AccountWithMetadata::new(
            Account::default(),
            false,
            (&recipient_keys.npk(), 0_u128),
        );

        let (ssk, epk) =
            SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &[0_u8; 32], 0);
        let view_tag = EncryptedAccountData::compute_view_tag(
            &recipient_keys.npk(),
            &recipient_keys.vpk(),
        );

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            token_transfer_instruction_data(amount),
            vec![
                InputAccountIdentity::Public,
                InputAccountIdentity::PrivateUnauthorized {
                    epk,
                    view_tag,
                    npk: recipient_keys.npk(),
                    ssk,
                    identifier: 0,
                },
            ],
            &programs::token().into(),
        ).expect("shield_tokens: execute_and_prove failed");

        let message = PrivacyMessage::try_from_circuit_output(
            vec![*sender_id],
            vec![sender_nonce],
            output,
        ).expect("shield_tokens: message creation failed");

        let witness_set = PrivacyWitnessSet::for_message(
            &message, proof, &[sender_key],
        );
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute the recipient's post-state (what the token program produces)
        let sender_account = state.get_account_by_id(sender_id.clone());
        let sender_holding = TokenHolding::try_from(&sender_account.data)
            .expect("Sender should have valid token holding");
        let definition_id = sender_holding.definition_id();
        let recipient_post = Account {
            program_owner: programs::token().id(),
            balance: 0,
            nonce: Nonce::private_account_nonce_init(&recipient_id),
            data: Data::try_from(create_token_holding_data(&definition_id, amount)).unwrap(),
        };

        (tx, recipient_post)
    }

    /// Transfers tokens between two private accounts.
    /// rc6: sender is `PrivateAuthorizedUpdate` (has membership proof); recipient
    /// is `PrivateUnauthorized` (fresh init). Both account_ids bind to (npk, 0).
    ///
    /// Returns (transaction, sender_post_state, recipient_post_state).
    #[allow(dead_code)]
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
            sender_account.clone(), true, (&sender_keys.npk(), 0_u128),
        );
        let recipient = AccountWithMetadata::new(
            Account::default(), false, (&recipient_keys.npk(), 0_u128),
        );

        let (ssk_sender, epk_sender) =
            SharedSecretKey::encapsulate_deterministic(&sender_keys.vpk(), &[0_u8; 32], 0);
        let (ssk_recipient, epk_recipient) =
            SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &[0_u8; 32], 1);
        let sender_view_tag = EncryptedAccountData::compute_view_tag(
            &sender_keys.npk(), &sender_keys.vpk());
        let recipient_view_tag = EncryptedAccountData::compute_view_tag(
            &recipient_keys.npk(), &recipient_keys.vpk());
        let sender_proof = state
            .get_proof_for_commitment(&sender_commitment)
            .unwrap_or((0, vec![]));

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            token_transfer_instruction_data(amount),
            vec![
                InputAccountIdentity::PrivateAuthorizedUpdate {
                    epk: epk_sender,
                    view_tag: sender_view_tag,
                    ssk: ssk_sender,
                    nsk: sender_keys.nsk,
                    membership_proof: sender_proof,
                    identifier: 0,
                },
                InputAccountIdentity::PrivateUnauthorized {
                    epk: epk_recipient,
                    view_tag: recipient_view_tag,
                    npk: recipient_keys.npk(),
                    ssk: ssk_recipient,
                    identifier: 0,
                },
            ],
            &programs::token().into(),
        ).expect("private_token_transfer: execute_and_prove failed");

        let message = PrivacyMessage::try_from_circuit_output(
            vec![],
            vec![],
            output,
        ).expect("private_token_transfer: message creation failed");

        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute post-states
        let sender_holding = TokenHolding::try_from(&sender_account.data)
            .expect("Sender should have valid token holding");
        let definition_id = sender_holding.definition_id();
        let sender_balance = match &sender_holding {
            TokenHolding::Fungible { balance, .. } => *balance,
            _ => panic!("Expected fungible token holding"),
        };

        let sender_post = Account {
            program_owner: sender_account.program_owner,
            balance: 0,
            nonce: sender_account.nonce.private_account_nonce_increment(&sender_keys.nsk),
            data: Data::try_from(
                create_token_holding_data(&definition_id, sender_balance - amount)
            ).unwrap(),
        };
        let recipient_post = Account {
            program_owner: programs::token().id(),
            balance: 0,
            nonce: Nonce::private_account_nonce_init(&recipient_id),
            data: Data::try_from(
                create_token_holding_data(&definition_id, amount)
            ).unwrap(),
        };

        (tx, sender_post, recipient_post)
    }

    /// Deshields tokens: private token holding → public account.
    /// rc6: sender is `PrivateAuthorizedUpdate`; recipient is `Public`.
    ///
    /// Returns (transaction, sender_post_state).
    #[allow(dead_code)]
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
            sender_account.clone(), true, (&sender_keys.npk(), 0_u128),
        );
        let recipient = AccountWithMetadata::new(
            state.get_account_by_id(recipient_id.clone()), false, *recipient_id,
        );

        let (ssk, epk) =
            SharedSecretKey::encapsulate_deterministic(&sender_keys.vpk(), &[0_u8; 32], 0);
        let view_tag = EncryptedAccountData::compute_view_tag(
            &sender_keys.npk(), &sender_keys.vpk());
        let sender_proof = state
            .get_proof_for_commitment(&sender_commitment)
            .unwrap_or((0, vec![]));

        let (output, proof) = execute_and_prove(
            vec![sender, recipient],
            token_transfer_instruction_data(amount),
            vec![
                InputAccountIdentity::PrivateAuthorizedUpdate {
                    epk,
                    view_tag,
                    ssk,
                    nsk: sender_keys.nsk,
                    membership_proof: sender_proof,
                    identifier: 0,
                },
                InputAccountIdentity::Public,
            ],
            &programs::token().into(),
        ).expect("deshield_tokens: execute_and_prove failed");

        let message = PrivacyMessage::try_from_circuit_output(
            vec![*recipient_id],
            vec![],
            output,
        ).expect("deshield_tokens: message creation failed");

        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute sender post-state
        let sender_holding = TokenHolding::try_from(&sender_account.data)
            .expect("Sender should have valid token holding");
        let definition_id = sender_holding.definition_id();
        let sender_balance = match &sender_holding {
            TokenHolding::Fungible { balance, .. } => *balance,
            _ => panic!("Expected fungible token holding"),
        };
        let sender_post = Account {
            program_owner: sender_account.program_owner,
            balance: 0,
            nonce: sender_account.nonce.private_account_nonce_increment(&sender_keys.nsk),
            data: Data::try_from(
                create_token_holding_data(&definition_id, sender_balance - amount)
            ).unwrap(),
        };

        (tx, sender_post)
    }

    /// Runs buy_credits through a privacy-preserving circuit.
    ///
    /// The user's payment and credit accounts are private; config, credit_token_def,
    /// and treasury are public.
    ///
    /// Returns (transaction, payment_post_state, credit_post_state).
    #[allow(dead_code)]
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn private_buy_credits(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        payment_keys: &PrivateAccountKeys,
        payment_account: &Account,
        credit_keys: &PrivateAccountKeys,
        amount: u128,
        price_per_unit: u128,
        state: &V03State,
    ) -> (PrivacyPreservingTransaction, Account, Account) {
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let credit_token_id = derive_credit_token_pda(setup.registration.id(), tree_id);
        let payment_id = payment_keys.account_id(0);
        let credit_id = credit_keys.account_id(0);

        // Build pre_states: [config, credit_def, user_payment, treasury, user_credit]
        let config = AccountWithMetadata::new(
            state.get_account_by_id(config_id.clone()), false, config_id,
        );
        let credit_def = AccountWithMetadata::new(
            state.get_account_by_id(credit_token_id.clone()), false, credit_token_id,
        );
        let user_payment = AccountWithMetadata::new(
            payment_account.clone(), true, (&payment_keys.npk(), 0_u128),
        );
        let treasury = AccountWithMetadata::new(
            state.get_account_by_id(setup.treasury_id.clone()), false, setup.treasury_id,
        );
        let user_credit = AccountWithMetadata::new(
            Account::default(), false, (&credit_keys.npk(), 0_u128),
        );

        let payment_commitment = Commitment::new(&payment_id, payment_account);

        // buy_credits instruction
        let instruction = Instruction::BuyCredits { tree_id: *tree_id, amount };
        let instruction_data = Program::serialize_instruction(instruction).unwrap();

        // rc6: ML-KEM-768 encapsulation per private account.
        let (ssk_payment, epk_payment) =
            SharedSecretKey::encapsulate_deterministic(&payment_keys.vpk(), &[0_u8; 32], 0);
        let (ssk_credit, epk_credit) =
            SharedSecretKey::encapsulate_deterministic(&credit_keys.vpk(), &[0_u8; 32], 1);
        let payment_view_tag = EncryptedAccountData::compute_view_tag(
            &payment_keys.npk(), &payment_keys.vpk());
        let credit_view_tag = EncryptedAccountData::compute_view_tag(
            &credit_keys.npk(), &credit_keys.vpk());
        let payment_proof = state
            .get_proof_for_commitment(&payment_commitment)
            .unwrap_or((0, vec![]));

        // Dependencies: the RLN program chains to the token program
        let mut dependencies = HashMap::new();
        dependencies.insert(programs::token().id(), programs::token());
        let program_with_deps = ProgramWithDependencies::new(
            setup.registration.clone(), dependencies,
        );

        // visibility: [config=public, credit_def=public, payment=private_auth_update,
        //              treasury=public, credit=new_private]
        let (output, proof) = execute_and_prove(
            vec![config, credit_def, user_payment, treasury, user_credit],
            instruction_data,
            vec![
                InputAccountIdentity::Public,
                InputAccountIdentity::Public,
                InputAccountIdentity::PrivateAuthorizedUpdate {
                    epk: epk_payment,
                    view_tag: payment_view_tag,
                    ssk: ssk_payment,
                    nsk: payment_keys.nsk,
                    membership_proof: payment_proof,
                    identifier: 0,
                },
                InputAccountIdentity::Public,
                InputAccountIdentity::PrivateUnauthorized {
                    epk: epk_credit,
                    view_tag: credit_view_tag,
                    npk: credit_keys.npk(),
                    ssk: ssk_credit,
                    identifier: 0,
                },
            ],
            &program_with_deps,
        ).expect("private_buy_credits: execute_and_prove failed");

        // Public accounts: config_id, credit_token_id, treasury_id
        // (with nonces from state for any that are signers — none are signed here)
        let message = PrivacyMessage::try_from_circuit_output(
            vec![config_id, credit_token_id, setup.treasury_id],
            vec![],
            output,
        ).expect("private_buy_credits: message creation failed");

        let witness_set = PrivacyWitnessSet::for_message(&message, proof, &[]);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        // Compute private account post-states
        let payment_cost = price_per_unit * amount;
        let payment_holding = TokenHolding::try_from(&payment_account.data)
            .expect("Payment account should have valid token holding");
        let payment_def_id = payment_holding.definition_id();
        let payment_balance = match &payment_holding {
            TokenHolding::Fungible { balance, .. } => *balance,
            _ => panic!("Expected fungible token holding"),
        };

        let payment_post = Account {
            program_owner: payment_account.program_owner,
            balance: 0,
            nonce: payment_account.nonce.private_account_nonce_increment(&payment_keys.nsk),
            data: Data::try_from(
                create_token_holding_data(&payment_def_id, payment_balance - payment_cost)
            ).unwrap(),
        };

        // Credit token definition_id for the credit holding
        let credit_post = Account {
            program_owner: programs::token().id(),
            balance: 0,
            nonce: Nonce::private_account_nonce_init(&credit_id),
            data: Data::try_from(
                create_token_holding_data(&credit_token_id, amount)
            ).unwrap(),
        };

        (tx, payment_post, credit_post)
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
            programs::token().id(),
            vec![definition_id.clone(), supply_holder_id.clone()],
            vec![Nonce(0), Nonce(0)],
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[definition_key, supply_holder_key])
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
            programs::token().id(),
            vec![from_id.clone(), to_id.clone()],
            nonces,
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &keys)
        )
    }

    // ========================================================================
    // Registration Init Transaction Builder
    // ========================================================================

    // Test-specific constants for new config fields
    const DEFAULT_MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000; // 1 million total rate limit

    /// Builds the three transactions that together initialize the RLN registration program.
    ///
    /// Init is split into Initialize + InitializeCreditToken + InitializeMerkleTree so each
    /// chained call runs in its own session, fitting under the 32M-cycle per-session cap.
    fn build_registration_init_txs(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        payment_token_id: &AccountId,
        price_per_unit: u128,
        treasury_id: &AccountId,
    ) -> [PublicTransaction; 3] {
        build_registration_init_txs_with_config(
            registration,
            merkle,
            tree_id,
            payment_token_id,
            price_per_unit,
            treasury_id,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
        )
    }

    fn build_registration_init_txs_with_config(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        payment_token_id: &AccountId,
        price_per_unit: u128,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
    ) -> [PublicTransaction; 3] {
        build_registration_init_txs_with_durations(
            registration,
            merkle,
            tree_id,
            payment_token_id,
            price_per_unit,
            treasury_id,
            max_total_rate_limit,
            DEFAULT_ACTIVE_DURATION,
            DEFAULT_GRACE_PERIOD_DURATION,
        )
    }

    fn build_registration_init_txs_with_durations(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        payment_token_id: &AccountId,
        price_per_unit: u128,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration: u32,
        grace_period_duration: u32,
    ) -> [PublicTransaction; 3] {
        build_registration_init_txs_with_policy(
            registration,
            merkle,
            tree_id,
            payment_token_id,
            price_per_unit,
            treasury_id,
            max_total_rate_limit,
            active_duration,
            grace_period_duration,
            [0u8; 32], // no free-quota registrar
            0,         // no free quota
            0,         // faucet disabled (wallet-key funding)
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_registration_init_txs_with_policy(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        payment_token_id: &AccountId,
        price_per_unit: u128,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration: u32,
        grace_period_duration: u32,
        authorized_registrar: [u8; 32],
        free_quota: u64,
        faucet_claim_cap: u128,
    ) -> [PublicTransaction; 3] {
        let config_id = derive_config_pda(registration.id(), tree_id);
        let credit_token_id = derive_credit_token_pda(registration.id(), tree_id);
        let credit_supply_id = derive_credit_supply_pda(registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);

        let init_config = build_public_tx(
            registration.id(),
            vec![config_id, credit_token_id.clone()],
            Instruction::Initialize {
                merkle_program_id: bytemuck::cast(merkle.id()),
                tree_id: *tree_id,
                payment_token_id: *payment_token_id.value(),
                price_per_unit,
                treasury_account_id: *treasury_id.value(),
                token_program_id: bytemuck::cast(programs::token().id()),
                max_total_rate_limit,
                active_duration_for_new_memberships: active_duration,
                grace_period_duration_for_new_memberships: grace_period_duration,
                authorized_registrar,
                free_quota,
                faucet_claim_cap,
            },
        );

        let init_credit_token = build_public_tx(
            registration.id(),
            vec![credit_token_id, credit_supply_id],
            Instruction::InitializeCreditToken {
                token_program_id: bytemuck::cast(programs::token().id()),
                tree_id: *tree_id,
            },
        );

        let init_merkle = build_public_tx(
            registration.id(),
            vec![tree_main_id],
            Instruction::InitializeMerkleTree {
                merkle_program_id: bytemuck::cast(merkle.id()),
                tree_id: *tree_id,
            },
        );

        [init_config, init_credit_token, init_merkle]
    }

    fn build_public_tx(
        program_id: nssa_core::program::ProgramId,
        accounts: Vec<AccountId>,
        instruction: Instruction,
    ) -> PublicTransaction {
        let message = Message::try_new(program_id, accounts, vec![], instruction)
            .expect("valid message");
        let witness = WitnessSet::for_message(&message, &[]);
        PublicTransaction::new(message, witness)
    }

    /// Apply all three init transactions; returns the first error if any, else Ok.
    fn apply_registration_init(
        state: &mut V03State,
        txs: &[PublicTransaction; 3],
    ) -> Result<(), nssa::error::LeeError> {
        for tx in txs {
            state.transition_from_public_transaction(tx, 1, 0)?;
        }
        Ok(())
    }

    // ========================================================================
    // Test Setup with Token Infrastructure
    // ========================================================================

    /// Test setup with programs deployed, tokens created, and registration initialized.
    #[allow(dead_code)]
    struct TestSetup {
        state: V03State,
        merkle: Program,
        registration: Program,
        // Token accounts
        payment_def_id: AccountId,
        treasury_id: AccountId,
        treasury_key: PrivateKey,
        user_payment_id: AccountId,
        user_payment_key: PrivateKey,
    }

    /// Creates a state with programs deployed, payment token created, user funded,
    /// and registration initialized with custom config. Returns None if any step fails.
    #[allow(dead_code)]
    fn state_with_initialized_registration_config(
        max_total_rate_limit: u64,
    ) -> Option<TestSetup> {
        state_with_policy_registration(max_total_rate_limit, [0u8; 32], 0)
    }

    /// Force-inserts a wallet-key payment token: definition + treasury holding
    /// (total supply minus the user share) + funded user holding, bypassing
    /// public transactions (which require both parties to sign for
    /// Claim::Authorized on new accounts).
    fn insert_funded_payment_token(
        state: &mut V03State,
        payment_def_id: &AccountId,
        treasury_id: &AccountId,
        user_payment_id: &AccountId,
    ) {
        let total_supply: u128 = 1_000_000_000;
        let user_amount: u128 = 10_000_000;
        let token_id = programs::token().id();

        let token_definition = token_core::TokenDefinition::Fungible {
            name: String::from("PAYTKN"),
            total_supply,
            metadata_id: None,
        };
        state.force_insert_account(payment_def_id.clone(), Account {
            program_owner: token_id,
            data: Data::from(&token_definition),
            ..Account::default()
        });
        let treasury_holding = token_core::TokenHolding::Fungible {
            definition_id: payment_def_id.clone(),
            balance: total_supply - user_amount,
        };
        state.force_insert_account(treasury_id.clone(), Account {
            program_owner: token_id,
            data: Data::from(&treasury_holding),
            ..Account::default()
        });
        let user_holding = token_core::TokenHolding::Fungible {
            definition_id: payment_def_id.clone(),
            balance: user_amount,
        };
        state.force_insert_account(user_payment_id.clone(), Account {
            program_owner: token_id,
            data: Data::from(&user_holding),
            ..Account::default()
        });
    }

    /// Like `state_with_initialized_registration_config`, with the deployment
    /// policy knobs exposed (free-quota registrar). Wallet-key funding
    /// (faucet_claim_cap = 0) — the faucet path has its own setup below.
    #[allow(dead_code)]
    fn state_with_policy_registration(
        max_total_rate_limit: u64,
        authorized_registrar: [u8; 32],
        free_quota: u64,
    ) -> Option<TestSetup> {
        let (mut state, merkle, registration) = state_with_programs()?;

        // 1. Create keypairs for token accounts
        let (treasury_key, treasury_id) = create_test_keypair(1);
        let (user_payment_key, user_payment_id) = create_test_keypair(2);
        let payment_def_id = AccountId::new([10; 32]);

        // 2. Set up token accounts directly
        insert_funded_payment_token(&mut state, &payment_def_id, &treasury_id, &user_payment_id);

        // 4. Initialize registration with custom config + policy
        let init_txs = build_registration_init_txs_with_policy(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_def_id,
            PRICE_PER_UNIT,
            &treasury_id,
            max_total_rate_limit,
            DEFAULT_ACTIVE_DURATION,
            DEFAULT_GRACE_PERIOD_DURATION,
            authorized_registrar,
            free_quota,
            0, // wallet-key funding: faucet disabled
        );
        apply_registration_init(&mut state, &init_txs).ok()?;

        Some(TestSetup {
            state,
            merkle,
            registration,
            payment_def_id,
            treasury_id,
            treasury_key,
            user_payment_id,
            user_payment_key,
        })
    }

    /// Faucet-mode setup: the payment token is the registration program's own
    /// `payment` PDA (created via InitializePaymentToken) — no human mint key
    /// exists anywhere in this state.
    #[allow(dead_code)]
    fn state_with_faucet_registration(claim_cap: u128) -> Option<(V03State, Program)> {
        let (mut state, merkle, registration) = state_with_programs()?;

        let (_treasury_key, treasury_id) = create_test_keypair(1);
        let payment_def_id = derive_payment_token_pda(registration.id(), &TREE_ID);
        let payment_supply_id = derive_payment_supply_pda(registration.id(), &TREE_ID);

        let init_txs = build_registration_init_txs_with_policy(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_def_id,
            PRICE_PER_UNIT,
            &treasury_id,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION,
            DEFAULT_GRACE_PERIOD_DURATION,
            [0u8; 32],
            0,
            claim_cap,
        );
        apply_registration_init(&mut state, &init_txs).ok()?;

        // 4th init tx: create RLNTOK as a program-owned PDA definition.
        let init_payment = build_public_tx(
            registration.id(),
            vec![payment_def_id, payment_supply_id],
            Instruction::InitializePaymentToken {
                token_program_id: bytemuck::cast(programs::token().id()),
                tree_id: TREE_ID,
            },
        );
        state
            .transition_from_public_transaction(&init_payment, 1, 0)
            .ok()?;

        Some((state, registration))
    }

    /// Creates a state with programs deployed, payment token created, user funded,
    /// and registration initialized with default config. Returns None if any step fails.
    #[allow(dead_code)]
    fn state_with_initialized_registration() -> Option<TestSetup> {
        state_with_initialized_registration_config(DEFAULT_MAX_TOTAL_RATE_LIMIT)
    }

    /// Same as `state_with_initialized_registration_config` with caller-chosen durations.
    #[allow(dead_code)]
    fn state_with_initialized_registration_durations(
        max_total_rate_limit: u64,
        active_duration: u32,
        grace_period_duration: u32,
    ) -> Option<TestSetup> {
        let (mut state, merkle, registration) = state_with_programs()?;

        let (treasury_key, treasury_id) = create_test_keypair(1);
        let (user_payment_key, user_payment_id) = create_test_keypair(2);
        let payment_def_id = AccountId::new([10; 32]);

        insert_funded_payment_token(&mut state, &payment_def_id, &treasury_id, &user_payment_id);

        let init_txs = build_registration_init_txs_with_durations(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_def_id,
            PRICE_PER_UNIT,
            &treasury_id,
            max_total_rate_limit,
            active_duration,
            grace_period_duration,
        );
        apply_registration_init(&mut state, &init_txs).ok()?;

        Some(TestSetup {
            state,
            merkle,
            registration,
            payment_def_id,
            treasury_id,
            treasury_key,
            user_payment_id,
            user_payment_key,
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
    fn get_total_registrations(state: &V03State, registration: &Program, tree_id: &[u8; 32]) -> u64 {
        let config_id = derive_config_pda(registration.id(), tree_id);
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
    fn get_current_total_rate_limit(state: &V03State, registration: &Program, tree_id: &[u8; 32]) -> u64 {
        let config_id = derive_config_pda(registration.id(), tree_id);
        let config = state.get_account_by_id(config_id);
        u64::from_le_bytes(
            config.data.as_ref()[CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT..CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT + 8]
                .try_into().unwrap()
        )
    }

    /// Gets next_index from tree main account.
    #[allow(dead_code)]
    fn get_tree_next_index(state: &V03State, registration: &Program, tree_id: &[u8; 32]) -> u64 {
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
        let tree = state.get_account_by_id(tree_main_id);
        u64::from_le_bytes(tree.data.as_ref()[1..9].try_into().unwrap())
    }

    /// Gets merkle root from tree main account.
    #[allow(dead_code)]
    fn get_tree_root(state: &V03State, registration: &Program, tree_id: &[u8; 32]) -> [u8; 32] {
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
        let tree = state.get_account_by_id(tree_main_id);
        tree.data.as_ref()[9..41].try_into().unwrap()
    }

    /// Gets token balance from a holding account.
    #[allow(dead_code)]
    fn get_token_balance(state: &V03State, account_id: &AccountId) -> u128 {
        let account = state.get_account_by_id(account_id.clone());
        let holding = TokenHolding::try_from(&account.data)
            .expect("Failed to deserialize token holding");
        match holding {
            TokenHolding::Fungible { balance, .. } => balance,
            TokenHolding::NftMaster { print_balance, .. } => print_balance,
            TokenHolding::NftPrintedCopy { .. } => 0,
        }
    }

    /// Gets token total supply from a definition account.
    #[allow(dead_code)]
    fn get_token_supply(state: &V03State, definition_id: &AccountId) -> u128 {
        let account = state.get_account_by_id(definition_id.clone());
        let definition = TokenDefinition::try_from(&account.data)
            .expect("Failed to deserialize token definition");
        match definition {
            TokenDefinition::Fungible { total_supply, .. } => total_supply,
            TokenDefinition::NonFungible { printable_supply, .. } => printable_supply,
        }
    }

    /// Checks if a membership PDA exists (has non-empty data).
    #[allow(dead_code)]
    fn membership_exists(state: &V03State, registration: &Program, tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> bool {
        let membership_id = derive_membership_pda(registration.id(), tree_id, id_commitment);
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
    fn get_membership_data(state: &V03State, registration: &Program, tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> Option<MembershipData> {
        let membership_id = derive_membership_pda(registration.id(), tree_id, id_commitment);
        let membership = state.get_account_by_id(membership_id);
        let data = membership.data.as_ref();
        if data.is_empty() || data.len() < MEMBERSHIP_SIZE { return None; }
        Some(MembershipData {
            leaf_index: u64::from_le_bytes(data[MEMBERSHIP_OFFSET_LEAF_INDEX..MEMBERSHIP_OFFSET_LEAF_INDEX + 8].try_into().unwrap()),
            rate_limit: u64::from_le_bytes(data[MEMBERSHIP_OFFSET_RATE_LIMIT..MEMBERSHIP_OFFSET_RATE_LIMIT + 8].try_into().unwrap()),
            id_commitment: data[MEMBERSHIP_OFFSET_ID_COMMITMENT..MEMBERSHIP_OFFSET_ID_COMMITMENT + 32].try_into().unwrap(),
        })
    }

    // ========================================================================
    // Identity Helpers
    // ========================================================================

    /// Derive id_commitment from identity_secret using Poseidon hash.
    /// Matches the single-input `hash_single` used by the guest's slash path.
    fn derive_id_commitment_from_secret(identity_secret: &[u8; 32]) -> [u8; 32] {
        use rln::hashers::poseidon_hash;
        use rln::utils::{bytes_le_to_fr, fr_to_bytes_le};

        let (secret_fr, _) = bytes_le_to_fr(identity_secret).expect("Invalid identity_secret");
        let hash_fr = poseidon_hash(&[secret_fr]);
        fr_to_bytes_le(&hash_fr).try_into().unwrap()
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

    /// Builds a direct registration transaction (opcode 1).
    ///
    /// Account order:
    /// - pre_states[0]: Config
    /// - pre_states[1]: Tree main
    /// - pre_states[2]: User's payment token holding
    /// - pre_states[3]: Treasury payment token holding
    /// - pre_states[4]: Bottom subtree account
    /// - pre_states[5]: CLOCK_50 system account (read-only timestamp)
    /// (membership PDA is derived internally by guest)
    #[allow(dead_code)]
    fn build_register_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        user_nonce: Nonce,
        next_index: u64,
    ) -> PublicTransaction {
        build_register_tx_parts(
            &setup.registration,
            tree_id,
            &setup.user_payment_id,
            &setup.user_payment_key,
            &setup.treasury_id,
            id_commitment,
            rate_limit,
            user_nonce,
            next_index,
        )
    }

    /// `build_register_tx` for states without a `TestSetup` (e.g. faucet
    /// deployments, where the payer/treasury holdings are claim-seeded).
    #[allow(clippy::too_many_arguments)]
    fn build_register_tx_parts(
        registration: &Program,
        tree_id: &[u8; 32],
        user_payment_id: &AccountId,
        user_payment_key: &PrivateKey,
        treasury_id: &AccountId,
        id_commitment: [u8; 32],
        rate_limit: u64,
        user_nonce: Nonce,
        next_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
        let sid = subtree_id_for_index(next_index);
        let subtree_account_id = derive_subtree_pda(registration.id(), tree_id, sid);

        let membership_id = derive_membership_pda(registration.id(), tree_id, &id_commitment);
        let account_ids = vec![
            config_id,
            tree_main_id,
            user_payment_id.clone(),
            treasury_id.clone(),
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
            registration.id(),
            account_ids,
            vec![user_nonce], // nonce for user_payment account (index 2)
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[user_payment_key])
        )
    }

    /// Builds a free-quota registration transaction.
    ///
    /// Account order (no payment/treasury accounts — the registrar signs but
    /// pays nothing):
    /// - pre_states[0]: Config
    /// - pre_states[1]: Tree main
    /// - pre_states[2]: Authorized registrar (signer)
    /// - pre_states[3]: Bottom subtree account
    /// - pre_states[4]: CLOCK_50 system account
    /// - pre_states[5]: Membership PDA (init)
    #[allow(dead_code)]
    fn build_register_free_tx(
        registration: &Program,
        tree_id: &[u8; 32],
        registrar_id: &AccountId,
        registrar_key: &PrivateKey,
        id_commitment: [u8; 32],
        rate_limit: u64,
        registrar_nonce: Nonce,
        next_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
        let sid = subtree_id_for_index(next_index);
        let subtree_account_id = derive_subtree_pda(registration.id(), tree_id, sid);
        let membership_id = derive_membership_pda(registration.id(), tree_id, &id_commitment);

        let account_ids = vec![
            config_id,
            tree_main_id,
            registrar_id.clone(),
            subtree_account_id,
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            membership_id,
        ];

        let instruction = Instruction::RegisterFree {
            tree_id: *tree_id,
            id_commitment,
            rate_limit,
            subtree_id: sid,
        };

        let message = Message::try_new(
            registration.id(),
            account_ids,
            vec![registrar_nonce],
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[registrar_key]),
        )
    }

    /// Builds a faucet claim transaction. `dest_key = None` leaves the
    /// destination unsigned (must be rejected for fresh holdings).
    #[allow(dead_code)]
    fn build_claim_tokens_tx(
        registration: &Program,
        tree_id: &[u8; 32],
        dest_id: &AccountId,
        dest_key: Option<&PrivateKey>,
        amount: u128,
        dest_nonce: Nonce,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(registration.id(), tree_id);
        let payment_def_id = derive_payment_token_pda(registration.id(), tree_id);

        let account_ids = vec![config_id, payment_def_id, dest_id.clone()];
        let instruction = Instruction::ClaimTokens { tree_id: *tree_id, amount };

        let nonces = if dest_key.is_some() { vec![dest_nonce] } else { vec![] };
        let message = Message::try_new(registration.id(), account_ids, nonces, instruction)
            .expect("valid message");

        let keys: Vec<&PrivateKey> = dest_key.into_iter().collect();
        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &keys),
        )
    }

    // ========================================================================
    // Credit Flow Transaction Builders
    // ========================================================================

    /// Builds a buy_credits transaction (opcode 2).
    ///
    /// Account order:
    /// - pre_states[0]: Config
    /// - pre_states[1]: Credit token definition (PDA)
    /// - pre_states[2]: User's payment token holding (authorized)
    /// - pre_states[3]: Treasury payment token holding
    /// - pre_states[4]: User's credit token holding (receives minted credits)
    #[allow(dead_code)]
    fn build_buy_credits_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        user_credit_id: &AccountId,
        user_credit_key: &PrivateKey,
        amount: u128,
        user_payment_nonce: Nonce,
        user_credit_nonce: Nonce,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let credit_token_id = derive_credit_token_pda(setup.registration.id(), tree_id);

        let instruction = Instruction::BuyCredits { tree_id: *tree_id, amount };

        let message = Message::try_new(
            setup.registration.id(),
            vec![
                config_id,
                credit_token_id,
                setup.user_payment_id.clone(),
                setup.treasury_id.clone(),
                user_credit_id.clone(),
            ],
            vec![user_payment_nonce, user_credit_nonce],
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[&setup.user_payment_key, user_credit_key])
        )
    }

    /// Builds a register_with_credits transaction (opcode 3).
    ///
    /// Account order:
    /// - pre_states[0]: Config
    /// - pre_states[1]: Credit token definition (PDA)
    /// - pre_states[2]: Tree main
    /// - pre_states[3]: User's credit token holding (authorized)
    /// - pre_states[4]: Bottom subtree account
    /// - pre_states[5]: CLOCK_50 system account (read-only timestamp)
    /// (membership PDA is derived internally by guest)
    #[allow(dead_code)]
    fn build_register_with_credits_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        user_credit_id: &AccountId,
        user_credit_key: &PrivateKey,
        id_commitment: [u8; 32],
        amount_to_burn: u64,
        user_credit_nonce: Nonce,
        next_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let credit_token_id = derive_credit_token_pda(setup.registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(setup.registration.id(), tree_id);
        let sid = subtree_id_for_index(next_index);
        let subtree_account_id = derive_subtree_pda(setup.registration.id(), tree_id, sid);

        let membership_id = derive_membership_pda(setup.registration.id(), tree_id, &id_commitment);
        let account_ids = vec![
            config_id,
            credit_token_id,
            tree_main_id,
            user_credit_id.clone(),
            subtree_account_id,
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            membership_id,
        ];

        let instruction = Instruction::RegisterWithCredits {
            tree_id: *tree_id,
            id_commitment,
            amount_to_burn,
            subtree_id: sid,
        };

        let message = Message::try_new(
            setup.registration.id(),
            account_ids,
            vec![user_credit_nonce], // nonce for user_credit (index 3)
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[user_credit_key])
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
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(setup.registration.id(), tree_id);
        let membership_id = derive_membership_pda(setup.registration.id(), tree_id, &id_commitment);
        let sid = subtree_id_for_index(leaf_index);
        let subtree_account_id = derive_subtree_pda(setup.registration.id(), tree_id, sid);

        // Account list: config, tree_main, membership, subtree
        let account_ids = vec![
            config_id,
            tree_main_id,
            membership_id,
            subtree_account_id,
        ];

        let instruction = Instruction::Slash {
            tree_id: *tree_id,
            id_commitment,
            identity_secret,
            subtree_id: sid,
        };

        let message = Message::try_new(
            setup.registration.id(),
            account_ids,
            vec![], // No nonces needed - no authorization required for slash
            instruction,
        ).expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[])
        )
    }

    // ========================================================================
    // Full Flow Tests - Registration Init
    // ========================================================================

    #[test]
    fn test_registration_init_succeeds() {
        let (mut state, merkle, registration) = state_with_programs()
            .expect("Programs should load");

        // Create test account IDs for init
        let payment_token_id = AccountId::new([10; 32]);
        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_token_id,
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
        let (mut state, merkle, registration) = state_with_programs()
            .expect("Programs should load");

        let payment_token_id = AccountId::new([10; 32]);
        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_token_id,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        apply_registration_init(&mut state, &init_txs)
            .expect("Init should succeed");

        // Verify config account was created
        let config_id = derive_config_pda(registration.id(), &TREE_ID);
        let config_account = state.get_account_by_id(config_id);

        // Config should exist and have data
        assert!(
            !config_account.data.as_ref().is_empty(),
            "Config account should have data"
        );

        // Verify Borsh-encoded ConfigState layout (CONFIG_SIZE bytes under SPEL).
        let data = config_account.data.as_ref();
        assert!(data.len() >= CONFIG_SIZE, "Config should be at least {CONFIG_SIZE} bytes");

        let merkle_id_bytes: [u8; 32] = bytemuck::cast(merkle.id());
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

        assert_eq!(
            &data[CONFIG_OFFSET_PAYMENT_TOKEN_ID..CONFIG_OFFSET_PAYMENT_TOKEN_ID + 32],
            payment_token_id.value(),
            "Config should store payment token ID"
        );

        let stored_price = u128::from_le_bytes(
            data[CONFIG_OFFSET_PRICE_PER_UNIT..CONFIG_OFFSET_PRICE_PER_UNIT + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(stored_price, PRICE_PER_UNIT, "Config should store price per unit");

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
        assert_eq!(total_registrations, 0, "Initial total_registrations should be 0");
    }

    #[test]
    fn test_registration_init_creates_tree_main() {
        let (mut state, merkle, registration) = state_with_programs()
            .expect("Programs should load");

        let payment_token_id = AccountId::new([10; 32]);
        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_token_id,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        apply_registration_init(&mut state, &init_txs)
            .expect("Init should succeed");

        // Verify tree main account was created via chained call
        let tree_main_id = derive_tree_main_pda(registration.id(), &TREE_ID);
        let tree_main = state.get_account_by_id(tree_main_id);

        assert!(
            !tree_main.data.as_ref().is_empty(),
            "Tree main account should have data"
        );

        // Check tree depth at offset 0
        let data = tree_main.data.as_ref();
        assert_eq!(
            data[0], TREE_DEPTH as u8,
            "Tree main should have depth {}", TREE_DEPTH
        );

        // Check next_index at offset 1 (should be 0)
        let next_index = u64::from_le_bytes(data[1..9].try_into().unwrap());
        assert_eq!(
            next_index, 0,
            "Initial next_index should be 0"
        );

        // Root at offset 9 (32 bytes) should be the default empty tree root
        // We don't check the exact value as it depends on Poseidon hash
        assert!(
            data.len() >= 41,
            "Tree main should have at least depth + next_index + root"
        );
    }

    #[test]
    fn test_registration_init_creates_credit_token() {
        let (mut state, merkle, registration) = state_with_programs()
            .expect("Programs should load");

        let payment_token_id = AccountId::new([10; 32]);
        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_token_id,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        apply_registration_init(&mut state, &init_txs)
            .expect("Init should succeed");

        // Verify credit token definition was created
        let credit_token_id = derive_credit_token_pda(registration.id(), &TREE_ID);
        let credit_token = state.get_account_by_id(credit_token_id);

        assert!(
            !credit_token.data.as_ref().is_empty(),
            "Credit token definition should have data"
        );

        // Verify it's a fungible token with zero supply
        let definition = TokenDefinition::try_from(&credit_token.data)
            .expect("Credit token definition should deserialize");
        match definition {
            TokenDefinition::Fungible { total_supply, .. } => {
                assert_eq!(total_supply, 0, "Initial credit token supply should be 0");
            }
            _ => panic!("Credit token should be fungible"),
        }
    }

    #[test]
    fn test_registration_init_prevents_reinit() {
        // Re-initialization is prevented because the token program's create
        // instruction requires the definition account to be default/uninitialized.
        let (mut state, merkle, registration) = state_with_programs()
            .expect("Programs should load");

        let payment_token_id = AccountId::new([10; 32]);
        let treasury_id = AccountId::new([11; 32]);
        let init_txs = build_registration_init_txs(
            &registration,
            &merkle,
            &TREE_ID,
            &payment_token_id,
            PRICE_PER_UNIT,
            &treasury_id,
        );

        // First init should succeed
        apply_registration_init(&mut state, &init_txs)
            .expect("First init should succeed");

        // Second init should fail. With the 3-tx split, the InitializeConfig
        // re-claim of the existing config PDA is what blocks re-init.
        let result = apply_registration_init(&mut state, &init_txs);
        assert!(
            result.is_err(),
            "Re-initialization should fail (config already claimed)"
        );
    }

    // ========================================================================
    // Full Flow Tests - Token Infrastructure
    // ========================================================================

    #[test]
    fn test_token_create_succeeds() {
        let (mut state, _merkle, _registration) = state_with_programs()
            .expect("Programs should load");

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
        assert!(!def_account.data.as_ref().is_empty(), "Definition should have data");

        // Verify supply holder was created with balance
        let balance = get_token_balance(&state, &supply_holder_id);
        assert_eq!(balance, 1_000_000, "Supply holder should have full supply");
    }

    #[test]
    fn test_token_transfer_succeeds() {
        let (mut state, _merkle, _registration) = state_with_programs()
            .expect("Programs should load");

        let (from_key, from_id) = create_test_keypair(1);
        let (to_key, to_id) = create_test_keypair(2);
        let (definition_key, definition_id) = create_test_keypair(10);

        // Create token
        let create_tx = build_token_create_tx(
            &definition_id, &definition_key, &from_id, &from_key,
            1_000_000, b"TESTOK",
        );
        state.transition_from_public_transaction(&create_tx, 1, 0)
            .expect("Create should succeed");

        // Transfer
        let transfer_tx = build_token_transfer_tx(
            &from_id, &to_id, &from_key,
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

    // ========================================================================
    // Full Flow Tests - Direct Registration
    // ========================================================================

    #[test]
    fn test_register_succeeds() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let rate_limit = 300u64;

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            rate_limit,
            Nonce(0), // user's nonce (first tx from this account on registration program)
            0, // next_index
        );

        let result = setup.state.transition_from_public_transaction(&register_tx, 1, 0);
        assert!(
            result.is_ok(),
            "Register should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_register_increments_total_registrations() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Initial count should be 0"
        );

        let register_tx = build_register_tx(&setup, &TREE_ID, valid_field_element(0x42), 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Count should be 1 after registration"
        );
    }

    #[test]
    fn test_register_inserts_leaf() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Initial next_index should be 0"
        );

        let register_tx = build_register_tx(&setup, &TREE_ID, valid_field_element(0x42), 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should be 1 after registration"
        );
    }

    // ========================================================================
    // Full Flow Tests - Credit Flow
    // ========================================================================

    #[test]
    fn test_buy_credits_succeeds() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Create a credit holding account for user
        let (user_credit_key, user_credit_id) = create_test_keypair(10);

        let buy_tx = build_buy_credits_tx(
            &setup,
            &TREE_ID,
            &user_credit_id,
            &user_credit_key,
            300, // amount = 300 credits (valid rate limit)
            Nonce(0),
            Nonce(0), // user's payment nonce
        );

        let result = setup.state.transition_from_public_transaction(&buy_tx, 1, 0);
        assert!(
            result.is_ok(),
            "Buy credits should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_buy_credits_mints_credits() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (user_credit_key, user_credit_id) = create_test_keypair(10);

        let buy_tx = build_buy_credits_tx(&setup, &TREE_ID, &user_credit_id, &user_credit_key, 300, Nonce(0), Nonce(0));
        setup.state.transition_from_public_transaction(&buy_tx, 1, 0)
            .expect("Buy should succeed");

        assert_eq!(
            get_token_balance(&setup.state, &user_credit_id),
            300,
            "User should have 300 credits"
        );

        let credit_token_id = derive_credit_token_pda(setup.registration.id(), &TREE_ID);
        assert_eq!(
            get_token_supply(&setup.state, &credit_token_id),
            300,
            "Credit supply should be 300"
        );
    }

    #[test]
    fn test_buy_credits_transfers_payment() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let balance_before = get_token_balance(&setup.state, &setup.user_payment_id);
        let (user_credit_key, user_credit_id) = create_test_keypair(10);

        // Buy 300 credits at PRICE_PER_UNIT = 10,000 per unit
        // Total cost = 300 * 10,000 = 3,000,000
        let buy_tx = build_buy_credits_tx(&setup, &TREE_ID, &user_credit_id, &user_credit_key, 300, Nonce(0), Nonce(0));
        setup.state.transition_from_public_transaction(&buy_tx, 1, 0)
            .expect("Buy should succeed");

        let balance_after = get_token_balance(&setup.state, &setup.user_payment_id);
        let expected_cost = 300 * PRICE_PER_UNIT;
        assert_eq!(
            balance_before - balance_after,
            expected_cost,
            "User should have paid {} tokens",
            expected_cost
        );
    }

    #[test]
    fn test_register_with_credits_succeeds() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // First buy credits
        let (user_credit_key, user_credit_id) = create_test_keypair(10);
        let buy_tx = build_buy_credits_tx(
            &setup, &TREE_ID, &user_credit_id, &user_credit_key, 300, Nonce(0), Nonce(0),
        );
        setup.state.transition_from_public_transaction(&buy_tx, 1, 0)
            .expect("Buy should succeed");

        // Now register with credits
        let id_commitment = valid_field_element(0x42);
        let register_tx = build_register_with_credits_tx(
            &setup,
            &TREE_ID,
            &user_credit_id,
            &user_credit_key,
            id_commitment,
            300, // burn all credits as rate limit
            Nonce(1),   // credit account nonce (after buy_credits signed)
            0,   // next_index
        );

        let result = setup.state.transition_from_public_transaction(&register_tx, 1, 0);
        assert!(
            result.is_ok(),
            "Register with credits should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_register_with_credits_burns_credits() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (user_credit_key, user_credit_id) = create_test_keypair(10);
        let buy_tx = build_buy_credits_tx(&setup, &TREE_ID, &user_credit_id, &user_credit_key, 500, Nonce(0), Nonce(0));
        setup.state.transition_from_public_transaction(&buy_tx, 1, 0)
            .expect("Buy should succeed");

        let register_tx = build_register_with_credits_tx(
            &setup, &TREE_ID, &user_credit_id, &user_credit_key,
            valid_field_element(0x42), 300, Nonce(1), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_token_balance(&setup.state, &user_credit_id),
            200,
            "User should have 200 credits remaining"
        );

        let credit_token_id = derive_credit_token_pda(setup.registration.id(), &TREE_ID);
        assert_eq!(
            get_token_supply(&setup.state, &credit_token_id),
            200,
            "Credit supply should be 200 after burn"
        );
    }

    #[test]
    fn test_register_with_credits_inserts_leaf() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (user_credit_key, user_credit_id) = create_test_keypair(10);
        let buy_tx = build_buy_credits_tx(&setup, &TREE_ID, &user_credit_id, &user_credit_key, 300, Nonce(0), Nonce(0));
        setup.state.transition_from_public_transaction(&buy_tx, 1, 0)
            .expect("Buy should succeed");

        let register_tx = build_register_with_credits_tx(
            &setup, &TREE_ID, &user_credit_id, &user_credit_key,
            valid_field_element(0x42), 300, Nonce(1), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should be 1"
        );
        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            1,
            "total_registrations should be 1"
        );
    }

    // ========================================================================
    // Membership PDA Tests
    // ========================================================================

    #[test]
    fn test_register_creates_membership_pda() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let rate_limit = 300u64;

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let membership = get_membership_data(&setup.state, &setup.registration, &TREE_ID, &id_commitment)
            .expect("Membership PDA should exist");

        assert_eq!(membership.leaf_index, 0, "leaf_index should be 0");
        assert_eq!(membership.rate_limit, rate_limit, "rate_limit should match");
        assert_eq!(membership.id_commitment, id_commitment, "id_commitment should match");
    }

    #[test]
    fn test_register_same_commitment_twice_fails() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);

        let register_tx1 = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx1, 1, 0)
            .expect("First register should succeed");

        assert!(membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment));

        let register_tx2 = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(1), 1);
        let result = setup.state.transition_from_public_transaction(&register_tx2, 1, 0);
        assert!(result.is_err(), "Second registration with same id_commitment should fail");
    }

    #[test]
    fn test_register_with_credits_creates_membership_pda() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Buy and register
        let (user_credit_key, user_credit_id) = create_test_keypair(10);
        let id_commitment = valid_field_element(0x99);
        let rate_limit = 300u64;

        let buy_tx = build_buy_credits_tx(
            &setup, &TREE_ID, &user_credit_id, &user_credit_key, rate_limit as u128, Nonce(0), Nonce(0),
        );
        setup.state.transition_from_public_transaction(&buy_tx, 1, 0)
            .expect("Buy should succeed");

        let register_tx = build_register_with_credits_tx(
            &setup, &TREE_ID, &user_credit_id, &user_credit_key,
            id_commitment, rate_limit, Nonce(1), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Verify membership PDA was created
        let membership_id = derive_membership_pda(setup.registration.id(), &TREE_ID, &id_commitment);
        let membership = setup.state.get_account_by_id(membership_id);

        assert!(
            !membership.data.as_ref().is_empty(),
            "Membership PDA should have data"
        );

        // Check id_commitment in membership data
        let data = membership.data.as_ref();
        let stored_commitment: [u8; 32] = data[MEMBERSHIP_OFFSET_ID_COMMITMENT..MEMBERSHIP_OFFSET_ID_COMMITMENT + 32]
            .try_into().unwrap();
        assert_eq!(stored_commitment, id_commitment, "id_commitment should match");
    }

    // ========================================================================
    // Slash Tests
    // ========================================================================

    #[test]
    fn test_slash_succeeds() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert!(membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment));

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        let result = setup.state.transition_from_public_transaction(&slash_tx, 1, 0);
        assert!(result.is_ok(), "Slash should succeed: {:?}", result);
    }

    #[test]
    fn test_slash_zeros_membership_pda() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert!(
            !membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            "Membership PDA should be zeroed after slash"
        );
    }

    #[test]
    fn test_slash_decrements_total_registrations() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Count should be 1 after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Count should be 0 after slash"
        );
    }

    #[test]
    fn test_slash_updates_merkle_root() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);
        let root_before_register = get_tree_root(&setup.state, &setup.registration, &TREE_ID);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let root_after_register = get_tree_root(&setup.state, &setup.registration, &TREE_ID);
        assert_ne!(root_after_register, root_before_register, "Root should change after register");

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        let root_after_slash = get_tree_root(&setup.state, &setup.registration, &TREE_ID);
        assert_eq!(root_after_slash, root_before_register, "Root should return to empty root after slash");
    }

    #[test]
    fn test_slash_does_not_change_next_index() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should be 1 after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "next_index should still be 1 after slash"
        );
    }

    #[test]
    fn test_slash_invalid_secret_fails() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (_, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Try to slash with a DIFFERENT identity_secret
        let (wrong_secret, _) = create_slashable_identity(0x99);
        let slash_tx = build_slash_tx(&setup, &TREE_ID, wrong_secret, id_commitment, 0);

        let result = setup.state.transition_from_public_transaction(&slash_tx, 1, 0);
        assert!(result.is_err(), "Slash with wrong identity_secret should fail");
    }

    #[test]
    fn test_slash_double_slash_fails() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);

        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("First slash should succeed");

        assert!(!membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment));

        let slash_tx2 = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        let result = setup.state.transition_from_public_transaction(&slash_tx2, 1, 0);
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
        ).expect("Setup should succeed");

        // First registration with rate_limit=300 should succeed
        let id_commitment1 = [0x01u8; 32];
        let register_tx1 = build_register_tx(&setup, &TREE_ID, id_commitment1, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx1, 1, 0)
            .expect("First registration should succeed");

        // Second registration with rate_limit=300 should fail (would exceed 500 cap)
        let id_commitment2 = [0x02u8; 32];
        let register_tx2 = build_register_tx(&setup, &TREE_ID, id_commitment2, 300, Nonce(1), 1);
        let result = setup.state.transition_from_public_transaction(&register_tx2, 1, 0);
        assert!(result.is_err(), "Second registration should fail (exceeds max_total_rate_limit)");
    }

    // ========================================================================
    // Deployment Policy Tests — faucet funding + free-quota membership
    // ========================================================================

    fn read_holding(state: &V03State, id: &AccountId) -> Option<token_core::TokenHolding> {
        let account = state.get_account_by_id(id.clone());
        token_core::TokenHolding::try_from(&account.data).ok()
    }

    #[test]
    fn test_faucet_init_creates_program_owned_payment_token() {
        let (state, registration) = state_with_faucet_registration(10_000_000)
            .expect("Faucet setup should succeed");

        let payment_def_id = derive_payment_token_pda(registration.id(), &TREE_ID);
        let def_account = state.get_account_by_id(payment_def_id);
        assert_eq!(
            def_account.program_owner,
            programs::token().id(),
            "Payment token definition should be owned by the token program"
        );
        let def = token_core::TokenDefinition::try_from(&def_account.data)
            .expect("definition should decode");
        match def {
            token_core::TokenDefinition::Fungible { name, total_supply, .. } => {
                assert_eq!(name, "RLNTOK");
                assert_eq!(total_supply, 0, "Faucet token starts with zero supply");
            }
            token_core::TokenDefinition::NonFungible { .. } => {
                panic!("Payment token should be fungible")
            }
        }
    }

    #[test]
    fn test_claim_tokens_mints_to_fresh_account() {
        let (mut state, registration) = state_with_faucet_registration(10_000_000)
            .expect("Faucet setup should succeed");

        let (dest_key, dest_id) = create_test_keypair(21);
        let claim = build_claim_tokens_tx(
            &registration, &TREE_ID, &dest_id, Some(&dest_key), 1_000_000, Nonce(0),
        );
        state.transition_from_public_transaction(&claim, 1, 0)
            .expect("Claim should succeed");

        let holding = read_holding(&state, &dest_id).expect("dest holding should decode");
        match holding {
            token_core::TokenHolding::Fungible { definition_id, balance } => {
                assert_eq!(balance, 1_000_000, "Claimed amount should be credited");
                assert_eq!(
                    definition_id,
                    derive_payment_token_pda(registration.id(), &TREE_ID),
                    "Holding should reference the PDA definition"
                );
            }
            token_core::TokenHolding::NftMaster { .. }
            | token_core::TokenHolding::NftPrintedCopy { .. } => {
                panic!("Dest holding should be fungible")
            }
        }

        // Total supply tracks program-authority mints.
        let def_account = state.get_account_by_id(
            derive_payment_token_pda(registration.id(), &TREE_ID),
        );
        match token_core::TokenDefinition::try_from(&def_account.data).unwrap() {
            token_core::TokenDefinition::Fungible { total_supply, .. } => {
                assert_eq!(total_supply, 1_000_000);
            }
            token_core::TokenDefinition::NonFungible { .. } => {
                panic!("definition should stay fungible")
            }
        }
    }

    #[test]
    fn test_claim_tokens_rejects_over_cap() {
        let (mut state, registration) = state_with_faucet_registration(1_000_000)
            .expect("Faucet setup should succeed");

        let (dest_key, dest_id) = create_test_keypair(22);
        let claim = build_claim_tokens_tx(
            &registration, &TREE_ID, &dest_id, Some(&dest_key), 1_000_001, Nonce(0),
        );
        let result = state.transition_from_public_transaction(&claim, 1, 0);
        assert!(result.is_err(), "Claim above faucet_claim_cap should fail");
    }

    #[test]
    fn test_claim_tokens_rejects_when_faucet_disabled() {
        // Wallet-key deployment: faucet_claim_cap = 0.
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (dest_key, dest_id) = create_test_keypair(23);
        let claim = build_claim_tokens_tx(
            &setup.registration, &TREE_ID, &dest_id, Some(&dest_key), 1, Nonce(0),
        );
        let result = setup.state.transition_from_public_transaction(&claim, 1, 0);
        assert!(result.is_err(), "Claim should fail when the faucet is disabled");
    }

    #[test]
    fn test_claim_tokens_rejects_unsigned_destination() {
        let (mut state, registration) = state_with_faucet_registration(10_000_000)
            .expect("Faucet setup should succeed");

        let (_dest_key, dest_id) = create_test_keypair(24);
        let claim = build_claim_tokens_tx(
            &registration, &TREE_ID, &dest_id, None, 1_000_000, Nonce(0),
        );
        let result = state.transition_from_public_transaction(&claim, 1, 0);
        assert!(
            result.is_err(),
            "Minting into a fresh holding requires the destination's signature (Claim::Authorized)"
        );
    }

    #[test]
    fn test_register_free_succeeds_and_decrements_quota() {
        let (registrar_key, registrar_id) = create_test_keypair(31);
        let mut setup = state_with_policy_registration(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            *registrar_id.value(),
            2,
        ).expect("Setup should succeed");

        let tx = build_register_free_tx(
            &setup.registration, &TREE_ID, &registrar_id, &registrar_key,
            valid_field_element(0x51), 300, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&tx, 1, 0)
            .expect("Free registration should succeed");

        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Free registration should count in total_registrations"
        );
        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Free registration should insert a leaf"
        );

        let config = setup.state.get_account_by_id(
            derive_config_pda(setup.registration.id(), &TREE_ID),
        );
        let data = config.data.as_ref();
        let quota = u64::from_le_bytes(
            data[CONFIG_OFFSET_FREE_QUOTA_REMAINING..CONFIG_OFFSET_FREE_QUOTA_REMAINING + 8]
                .try_into().unwrap(),
        );
        assert_eq!(quota, 1, "free_quota_remaining should decrement");
        assert_eq!(
            &data[CONFIG_OFFSET_AUTHORIZED_REGISTRAR..CONFIG_OFFSET_AUTHORIZED_REGISTRAR + 32],
            registrar_id.value(),
            "Config should store the authorized registrar at its frozen offset"
        );
    }

    #[test]
    fn test_register_free_quota_exhaustion() {
        let (registrar_key, registrar_id) = create_test_keypair(32);
        let mut setup = state_with_policy_registration(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            *registrar_id.value(),
            1,
        ).expect("Setup should succeed");

        let tx1 = build_register_free_tx(
            &setup.registration, &TREE_ID, &registrar_id, &registrar_key,
            valid_field_element(0x52), 300, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&tx1, 1, 0)
            .expect("First free registration should succeed");

        let tx2 = build_register_free_tx(
            &setup.registration, &TREE_ID, &registrar_id, &registrar_key,
            valid_field_element(0x53), 300, Nonce(1), 1,
        );
        let result = setup.state.transition_from_public_transaction(&tx2, 1, 0);
        assert!(result.is_err(), "Second free registration should fail (quota exhausted)");
    }

    #[test]
    fn test_register_free_rejects_wrong_signer() {
        let (_registrar_key, registrar_id) = create_test_keypair(33);
        let (impostor_key, impostor_id) = create_test_keypair(34);
        let mut setup = state_with_policy_registration(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            *registrar_id.value(),
            5,
        ).expect("Setup should succeed");

        let tx = build_register_free_tx(
            &setup.registration, &TREE_ID, &impostor_id, &impostor_key,
            valid_field_element(0x54), 300, Nonce(0), 0,
        );
        let result = setup.state.transition_from_public_transaction(&tx, 1, 0);
        assert!(result.is_err(), "Non-registrar signer must be rejected");
    }

    #[test]
    fn test_register_free_rejects_without_registrar_config() {
        // Default deployment: no registrar, no quota.
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let (key, id) = create_test_keypair(35);
        let tx = build_register_free_tx(
            &setup.registration, &TREE_ID, &id, &key,
            valid_field_element(0x55), 300, Nonce(0), 0,
        );
        let result = setup.state.transition_from_public_transaction(&tx, 1, 0);
        assert!(result.is_err(), "RegisterFree must fail when no registrar is configured");
    }

    #[test]
    fn test_paid_register_still_works_in_quota_deployment() {
        // Additive policy: the paid path is unaffected by a configured quota.
        let (_registrar_key, registrar_id) = create_test_keypair(36);
        let mut setup = state_with_policy_registration(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            *registrar_id.value(),
            5,
        ).expect("Setup should succeed");

        let register_tx = build_register_tx(
            &setup, &TREE_ID, valid_field_element(0x56), 300, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Paid registration should still succeed in a quota deployment");
    }

    #[test]
    fn test_paid_register_works_in_faucet_deployment() {
        // Faucet deployments keep the paid path: both holdings are seeded by
        // claims (the treasury exactly as run_setup Step 5c does), then a
        // normal Register pays treasury from the user's claimed balance.
        let (mut state, registration) = state_with_faucet_registration(10_000_000)
            .expect("Faucet setup should succeed");

        // Same seed as state_with_faucet_registration's treasury (config
        // records this account id; create_test_keypair is deterministic).
        let (treasury_key, treasury_id) = create_test_keypair(1);
        let seed_treasury = build_claim_tokens_tx(
            &registration, &TREE_ID, &treasury_id, Some(&treasury_key), 1, Nonce(0),
        );
        state.transition_from_public_transaction(&seed_treasury, 1, 0)
            .expect("Treasury seed claim should succeed");

        let (user_key, user_id) = create_test_keypair(40);
        let fund_user = build_claim_tokens_tx(
            &registration, &TREE_ID, &user_id, Some(&user_key), 5_000_000, Nonce(0),
        );
        state.transition_from_public_transaction(&fund_user, 1, 0)
            .expect("User funding claim should succeed");

        let rate_limit = 300u64;
        let register_tx = build_register_tx_parts(
            &registration, &TREE_ID, &user_id, &user_key, &treasury_id,
            valid_field_element(0x57), rate_limit, Nonce(1), 0,
        );
        state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Paid registration should succeed in a faucet deployment");

        assert_eq!(
            get_total_registrations(&state, &registration, &TREE_ID),
            1,
            "Registration should be recorded in config"
        );
        let price = u128::from(rate_limit) * PRICE_PER_UNIT;
        match read_holding(&state, &treasury_id).expect("treasury holding should decode") {
            token_core::TokenHolding::Fungible { balance, .. } => assert_eq!(
                balance,
                1 + price,
                "Treasury should hold its claim seed plus the registration payment"
            ),
            token_core::TokenHolding::NftMaster { .. }
            | token_core::TokenHolding::NftPrintedCopy { .. } => {
                panic!("Treasury holding should be fungible")
            }
        }
    }

    #[test]
    fn test_current_total_rate_limit_tracking() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        assert_eq!(
            get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID),
            0,
            "Initial current_total_rate_limit should be 0"
        );

        let (identity_secret, id_commitment) = create_slashable_identity(0x42);
        let register_tx = build_register_tx(&setup, &TREE_ID, id_commitment, 300, Nonce(0), 0);
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        assert_eq!(
            get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID),
            300,
            "current_total_rate_limit should be 300 after register"
        );

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
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

    use crate::merkle_tree::{
        OFFSET_DEPTH, OFFSET_ROOT, OFFSET_CACHED_NODES, OFFSET_TOP_TREE_DATA, TOP_DEPTH,
        read_sparse_node,
    };
    use rln::prelude::{seeded_keygen, Fr, RLNWitnessInput, RLN, hash_to_field_le};
    use rln::hashers::poseidon_hash;
    use rln::utils::{bytes_le_to_fr, fr_to_bytes_le, IdSecret};

    /// Computes rate_commitment = poseidon(id_commitment, rate_limit).
    /// This is the leaf value stored in the merkle tree.
    fn compute_rate_commitment(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
        let (id_fr, _) = bytes_le_to_fr(id_commitment).expect("Invalid id_commitment");
        let rate_fr = Fr::from(rate_limit);
        let hash_fr = poseidon_hash(&[id_fr, rate_fr]);
        fr_to_bytes_le(&hash_fr).try_into().unwrap()
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
            let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
            let main_account = state.get_account_by_id(tree_main_id);
            let data = main_account.data.as_ref();

            let top_tree_data = if data.len() > OFFSET_TOP_TREE_DATA {
                &data[OFFSET_TOP_TREE_DATA..]
            } else {
                &[]
            };
            read_sparse_node(top_tree_data, level, node_index as usize, &cached_defaults[level])
        } else {
            // Node is in a bottom subtree (sparse format)
            let bottom_level = level - TOP_DEPTH;
            let nodes_per_subtree_at_level = 1usize << bottom_level;
            let sid = (node_index as usize / nodes_per_subtree_at_level) as u32;
            let local_index = node_index as usize % nodes_per_subtree_at_level;

            let subtree_account_id = derive_subtree_pda(registration.id(), tree_id, sid);
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
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
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
            state, registration, tree_id, depth as u8, leaf_index, &cached_defaults,
        );

        // Collect sibling hashes
        let mut path_elements: Vec<[u8; 32]> = Vec::with_capacity(depth);
        let mut path_indices: Vec<u8> = Vec::with_capacity(depth);
        let mut current_index = leaf_index;

        for level in (1..=depth).rev() {
            let node_index = current_index;
            let is_right_child = (node_index % 2) as u8;
            path_indices.push(is_right_child);

            let sibling_index = if node_index % 2 == 0 {
                node_index + 1
            } else {
                node_index - 1
            };

            let sibling = fetch_node_from_state(
                state, registration, tree_id, level as u8, sibling_index, &cached_defaults,
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
        let (mut current, _) = bytes_le_to_fr(leaf).expect("Invalid leaf");

        for (sibling_bytes, &path_index) in path_elements.iter().zip(path_indices.iter()) {
            let (sibling, _) = bytes_le_to_fr(sibling_bytes).expect("Invalid sibling");

            let (left, right) = if path_index == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };

            current = poseidon_hash(&[left, right]);
        }

        fr_to_bytes_le(&current).try_into().unwrap()
    }

    #[test]
    fn test_merkle_proof_extraction_from_state() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        let id_commitment = valid_field_element(0x42);
        let rate_limit = 300u64;

        // Register a member
        let register_tx = build_register_tx(
            &setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Extract merkle proof
        let (path_elements, path_indices, root, leaf) = get_merkle_proof_from_state(
            &setup.state, &setup.registration, &TREE_ID, 0,
        );

        // Verify proof structure
        assert_eq!(path_elements.len(), TREE_DEPTH, "Path should have {} elements", TREE_DEPTH);
        assert_eq!(path_indices.len(), TREE_DEPTH, "Path indices should have {} elements", TREE_DEPTH);

        // Verify leaf matches expected rate commitment
        let expected_leaf = compute_rate_commitment(&id_commitment, rate_limit);
        assert_eq!(leaf, expected_leaf, "Leaf should match rate commitment");

        // Verify proof by recomputing root
        let computed_root = verify_merkle_proof_local(&leaf, &path_elements, &path_indices);
        assert_eq!(computed_root, root, "Computed root should match on-chain root");
    }

    #[test]
    fn test_rln_proof_generation_and_verification() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Create identity using zerokit's seeded_keygen (like run_rln_proof does)
        let seed = [0x42u8; 32]; // deterministic seed for testing
        let (mut identity_secret_fr, id_commitment_fr) =
            seeded_keygen(&seed);
        let identity_secret = IdSecret::from(&mut identity_secret_fr);

        let id_commitment: [u8; 32] = fr_to_bytes_le(&id_commitment_fr).try_into().unwrap();
        let rate_limit = 300u64;

        // Register the identity
        let register_tx = build_register_tx(
            &setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Extract merkle proof from state
        let (path_elements_bytes, path_indices, root_bytes, leaf_bytes) = get_merkle_proof_from_state(
            &setup.state, &setup.registration, &TREE_ID, 0,
        );

        // Convert to Fr types for zerokit
        let path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element").0)
            .collect();
        let (root, _) = bytes_le_to_fr(&root_bytes).expect("Invalid root");

        // Verify the leaf matches what we expect
        let expected_leaf = compute_rate_commitment(&id_commitment, rate_limit);
        assert_eq!(leaf_bytes, expected_leaf, "On-chain leaf should match computed rate commitment");

        // Create RLN witness
        let user_message_limit = Fr::from(rate_limit);
        let message_id = Fr::from(0u64);

        // Compute external nullifier = poseidon(epoch, rln_identifier)
        let epoch_fr = hash_to_field_le(b"test-epoch");
        let rln_identifier_fr = hash_to_field_le(b"lssa-rln-test");
        let external_nullifier = poseidon_hash(&[epoch_fr, rln_identifier_fr]);

        // Compute signal hash (x) = hash of message
        let x = hash_to_field_le(b"Hello, RLN!");

        // Create RLN witness input
        let witness = RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements.clone(),
            path_indices.clone(),
            x,
            external_nullifier,
        ).expect("Failed to create RLN witness");

        // Initialize RLN instance
        let rln = RLN::new().expect("Failed to initialize RLN");

        // Generate the proof
        let (rln_proof, proof_values) = rln
            .generate_rln_proof(&witness)
            .expect("Failed to generate RLN proof");

        // Verify proof values match
        assert_eq!(*proof_values.root(), root, "Proof root should match on-chain root");

        // Verify the RLN proof with root check
        let is_valid = rln
            .verify_with_roots(&rln_proof, &proof_values, &x, &[root])
            .expect("Failed to verify proof");

        assert!(is_valid, "RLN proof should be valid");
    }

    #[test]
    fn test_rln_proof_with_multiple_registrations() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Use rate_limit = 100 for all to fit within user's 10M token budget
        // (3 registrations * 100 * 10,000 = 3M tokens)

        // Register first identity
        let seed1 = [0x01u8; 32];
        let (mut identity_secret_fr1, id_commitment_fr1) =
            seeded_keygen(&seed1);
        let _identity_secret1 = IdSecret::from(&mut identity_secret_fr1);
        let id_commitment1: [u8; 32] = fr_to_bytes_le(&id_commitment_fr1).try_into().unwrap();

        let register_tx1 = build_register_tx(
            &setup, &TREE_ID, id_commitment1, 100, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx1, 1, 0)
            .expect("First register should succeed");

        // Register second identity (this is the one we'll prove)
        let seed2 = [0x02u8; 32];
        let (mut identity_secret_fr2, id_commitment_fr2) =
            seeded_keygen(&seed2);
        let identity_secret2 = IdSecret::from(&mut identity_secret_fr2);
        let id_commitment2: [u8; 32] = fr_to_bytes_le(&id_commitment_fr2).try_into().unwrap();
        let rate_limit2 = 100u64;

        let register_tx2 = build_register_tx(
            &setup, &TREE_ID, id_commitment2, rate_limit2, Nonce(1), 1,
        );
        setup.state.transition_from_public_transaction(&register_tx2, 1, 0)
            .expect("Second register should succeed");

        // Register third identity
        let seed3 = [0x03u8; 32];
        let (mut identity_secret_fr3, id_commitment_fr3) =
            seeded_keygen(&seed3);
        let _identity_secret3 = IdSecret::from(&mut identity_secret_fr3);
        let id_commitment3: [u8; 32] = fr_to_bytes_le(&id_commitment_fr3).try_into().unwrap();

        let register_tx3 = build_register_tx(
            &setup, &TREE_ID, id_commitment3, 100, Nonce(2), 2,
        );
        setup.state.transition_from_public_transaction(&register_tx3, 1, 0)
            .expect("Third register should succeed");

        // Extract merkle proof for second identity (index 1)
        let (path_elements_bytes, path_indices, root_bytes, leaf_bytes) = get_merkle_proof_from_state(
            &setup.state, &setup.registration, &TREE_ID, 1,
        );

        // Convert to Fr types
        let path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element").0)
            .collect();
        let (root, _) = bytes_le_to_fr(&root_bytes).expect("Invalid root");

        // Verify the leaf
        let expected_leaf = compute_rate_commitment(&id_commitment2, rate_limit2);
        assert_eq!(leaf_bytes, expected_leaf, "Leaf should match");

        // Create and verify RLN proof
        let user_message_limit = Fr::from(rate_limit2);
        let message_id = Fr::from(0u64);
        let epoch_fr = hash_to_field_le(b"test-epoch-2");
        let rln_identifier_fr = hash_to_field_le(b"lssa-rln-test");
        let external_nullifier = poseidon_hash(&[epoch_fr, rln_identifier_fr]);
        let x = hash_to_field_le(b"Another message");

        let witness = RLNWitnessInput::new(
            identity_secret2,
            user_message_limit,
            message_id,
            path_elements,
            path_indices,
            x,
            external_nullifier,
        ).expect("Failed to create RLN witness");

        let rln = RLN::new().expect("Failed to initialize RLN");
        let (rln_proof, proof_values) = rln
            .generate_rln_proof(&witness)
            .expect("Failed to generate RLN proof");

        assert_eq!(*proof_values.root(), root, "Proof root should match on-chain root");

        let is_valid = rln
            .verify_with_roots(&rln_proof, &proof_values, &x, &[root])
            .expect("Failed to verify proof");

        assert!(is_valid, "RLN proof should be valid with multiple registrations");
    }

    #[test]
    fn test_rln_proof_invalid_after_slash() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Create identity using poseidon derivation (for slash compatibility)
        let identity_secret_bytes = valid_field_element(0x42);
        let id_commitment = derive_id_commitment_from_secret(&identity_secret_bytes);
        let rate_limit = 300u64;

        // Register
        let register_tx = build_register_tx(
            &setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Get root before slash
        let tree_main_id = derive_tree_main_pda(setup.registration.id(), &TREE_ID);
        let tree_before = setup.state.get_account_by_id(tree_main_id.clone());
        let root_before: [u8; 32] = tree_before.data.as_ref()[9..41].try_into().unwrap();

        // Slash the member
        let slash_tx = build_slash_tx(
            &setup, &TREE_ID, identity_secret_bytes, id_commitment, 0,
        );
        setup.state.transition_from_public_transaction(&slash_tx, 1, 0)
            .expect("Slash should succeed");

        // Get root after slash
        let tree_after = setup.state.get_account_by_id(tree_main_id);
        let root_after: [u8; 32] = tree_after.data.as_ref()[9..41].try_into().unwrap();

        // Root should have changed after slash
        assert_ne!(root_before, root_after, "Root should change after slash");

        // Extract merkle proof after slash
        let (_, _, root_bytes, leaf_bytes) = get_merkle_proof_from_state(
            &setup.state, &setup.registration, &TREE_ID, 0,
        );

        // Leaf should now be the default (zero or cached default)
        let expected_rate_commitment = compute_rate_commitment(&id_commitment, rate_limit);
        assert_ne!(leaf_bytes, expected_rate_commitment, "Leaf should no longer match rate commitment after slash");

        // Verify root changed to empty tree root (since this was the only member)
        let (root_fr, _) = bytes_le_to_fr(&root_bytes).expect("Invalid root");
        let (root_before_register_fr, _) = bytes_le_to_fr(&root_after).expect("Invalid root");
        assert_eq!(root_fr, root_before_register_fr, "Root should match empty tree root");
    }

    #[test]
    fn test_rln_double_message_detection() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Create identity
        let seed = [0x99u8; 32];
        let (mut identity_secret_fr, id_commitment_fr) =
            seeded_keygen(&seed);
        let identity_secret = IdSecret::from(&mut identity_secret_fr);
        let id_commitment: [u8; 32] = fr_to_bytes_le(&id_commitment_fr).try_into().unwrap();
        let rate_limit = 300u64;

        // Register
        let register_tx = build_register_tx(
            &setup, &TREE_ID, id_commitment, rate_limit, Nonce(0), 0,
        );
        setup.state.transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Register should succeed");

        // Extract proof
        let (path_elements_bytes, path_indices, root_bytes, _) = get_merkle_proof_from_state(
            &setup.state, &setup.registration, &TREE_ID, 0,
        );

        let path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element").0)
            .collect();
        let (root, _) = bytes_le_to_fr(&root_bytes).expect("Invalid root");

        // Same epoch and message_id but different messages
        let user_message_limit = Fr::from(rate_limit);
        let message_id = Fr::from(0u64); // Same message_id for both

        let epoch_fr = hash_to_field_le(b"epoch-1");
        let rln_identifier_fr = hash_to_field_le(b"lssa-rln-test");
        let external_nullifier = poseidon_hash(&[epoch_fr, rln_identifier_fr]);

        // First message
        let x1 = hash_to_field_le(b"First message");
        let witness1 = RLNWitnessInput::new(
            identity_secret.clone(),
            user_message_limit,
            message_id,
            path_elements.clone(),
            path_indices.clone(),
            x1,
            external_nullifier,
        ).expect("Failed to create witness 1");

        // Second message (different content, same message_id)
        let x2 = hash_to_field_le(b"Second message");
        let witness2 = RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            path_indices,
            x2,
            external_nullifier,
        ).expect("Failed to create witness 2");

        let rln = RLN::new().expect("Failed to initialize RLN");

        // Generate both proofs
        let (proof1, values1) = rln.generate_rln_proof(&witness1).expect("Failed to generate proof 1");
        let (proof2, values2) = rln.generate_rln_proof(&witness2).expect("Failed to generate proof 2");

        // Both proofs should be individually valid
        let valid1 = rln.verify_with_roots(&proof1, &values1, &x1, &[root]).expect("Verify 1 failed");
        let valid2 = rln.verify_with_roots(&proof2, &values2, &x2, &[root]).expect("Verify 2 failed");
        assert!(valid1, "First proof should be valid");
        assert!(valid2, "Second proof should be valid");

        // But they should have the SAME nullifier (since same identity, epoch, message_id)
        assert_eq!(
            values1.nullifier(), values2.nullifier(),
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
    // Private Credit Flow Test
    // ========================================================================

    #[test]
    #[cfg(feature = "rc5-state-tests-privacy")]
    fn test_private_credit_flow() {
        let mut setup = state_with_initialized_registration()
            .expect("Setup should succeed");

        // Key sets for private accounts
        let payment_private_keys = private_account_keys(13, 31);
        let credit_private_keys_1 = private_account_keys(14, 32);
        let credit_private_keys_2 = private_account_keys(15, 33);

        let credit_amount: u128 = 300; // credits to buy (also the rate_limit)

        // Step 0: Shield payment tokens (public → private)
        let shield_amount: u128 = credit_amount * PRICE_PER_UNIT; // exact amount needed
        let (shield_tx, private_payment) = shield_tokens(
            &setup.user_payment_key,
            &setup.user_payment_id,
            &payment_private_keys,
            shield_amount,
            &setup.state,
        );
        setup.state
            .transition_from_privacy_preserving_transaction(&shield_tx, 1, 0)
            .expect("Step 0: Shield payment tokens should succeed");

        // Step 1: Private buy_credits
        let (buy_tx, _payment_post, private_credits_1) = private_buy_credits(
            &setup,
            &TREE_ID,
            &payment_private_keys,
            &private_payment,
            &credit_private_keys_1,
            credit_amount,
            PRICE_PER_UNIT,
            &setup.state,
        );
        setup.state
            .transition_from_privacy_preserving_transaction(&buy_tx, 1, 0)
            .expect("Step 1: Private buy_credits should succeed");

        // Verify public state changes: credit supply increased
        let credit_token_id = derive_credit_token_pda(setup.registration.id(), &TREE_ID);
        assert_eq!(
            get_token_supply(&setup.state, &credit_token_id),
            credit_amount,
            "Credit supply should equal purchased amount"
        );

        // Step 2: Private credit transfer (private → private)
        let (transfer_tx, _credit_sender_post, private_credits_2) = private_token_transfer(
            &credit_private_keys_1,
            &private_credits_1,
            &credit_private_keys_2,
            credit_amount,
            &setup.state,
        );
        setup.state
            .transition_from_privacy_preserving_transaction(&transfer_tx, 1, 0)
            .expect("Step 2: Private credit transfer should succeed");

        // Step 3: Deshield credits (private → public)
        // Pre-create the recipient's token holding (Claim::Authorized on public accounts
        // requires the account to be authorized, which won't be the case in a deshield)
        let (deshield_credit_key, deshield_credit_id) = create_test_keypair(20);
        let credit_token_def_id = derive_credit_token_pda(setup.registration.id(), &TREE_ID);
        let empty_credit_holding = token_core::TokenHolding::Fungible {
            definition_id: credit_token_def_id,
            balance: 0,
        };
        setup.state.force_insert_account(deshield_credit_id.clone(), Account {
            program_owner: programs::token().id(),
            data: Data::from(&empty_credit_holding),
            ..Account::default()
        });
        let (deshield_tx, _credit_deshield_post) = deshield_tokens(
            &credit_private_keys_2,
            &private_credits_2,
            &deshield_credit_id,
            credit_amount,
            &setup.state,
        );
        setup.state
            .transition_from_privacy_preserving_transaction(&deshield_tx, 1, 0)
            .expect("Step 3: Deshield credits should succeed");

        // Verify credits landed in the public account
        assert_eq!(
            get_token_balance(&setup.state, &deshield_credit_id),
            credit_amount,
            "Deshielded credit account should have the full credit amount"
        );

        // Step 4: Public register_with_credits
        let id_commitment = valid_field_element(0x99);
        let register_tx = build_register_with_credits_tx(
            &setup,
            &TREE_ID,
            &deshield_credit_id,
            &deshield_credit_key,
            id_commitment,
            credit_amount as u64,
            Nonce(0), // credit account nonce (fresh public account)
            0, // next_index
        );
        let result = setup.state.transition_from_public_transaction(&register_tx, 1, 0);
        assert!(
            result.is_ok(),
            "Step 4: Public register_with_credits should succeed: {:?}",
            result
        );

        // Verify registration completed
        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            1,
            "Tree should have one leaf after registration"
        );
        assert!(
            membership_exists(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            "Membership PDA should exist"
        );

        // Verify credits were burned
        assert_eq!(
            get_token_balance(&setup.state, &deshield_credit_id),
            0,
            "Credit account should be empty after registration"
        );
    }

    // ========================================================================
    // Expiration — time-travel helpers
    // ========================================================================

    /// Overwrite the CLOCK_50 system account with a specific timestamp so
    /// subsequent program invocations observe `now == timestamp`. Uses the
    /// `test-utils` `force_insert_account` escape hatch instead of issuing
    /// 50 clock-ticks, because CLOCK_50 only refreshes every 50 blocks.
    fn set_clock_50(state: &mut V03State, timestamp: u64, block_id: u64) {
        use clock_core::{CLOCK_50_PROGRAM_ACCOUNT_ID, ClockAccountData};
        let data = ClockAccountData { block_id, timestamp }.to_bytes();
        let clock_program_id = programs::clock().id();
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
        let membership_id = derive_membership_pda(registration.id(), tree_id, id_commitment);
        let bytes = state.get_account_by_id(membership_id).data.into_inner();
        if bytes.is_empty() { None } else { Some(bytes) }
    }

    fn read_grace_start(
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

    fn read_active_duration(
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

    fn read_grace_duration(
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

    fn build_extend_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
    ) -> PublicTransaction {
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let membership_id = derive_membership_pda(setup.registration.id(), tree_id, &id_commitment);

        let account_ids = vec![
            config_id,
            membership_id,
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
        ];

        let instruction = Instruction::Extend {
            tree_id: *tree_id,
            id_commitment,
        };

        let message = Message::try_new(setup.registration.id(), account_ids, vec![], instruction)
            .expect("valid message");

        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[]))
    }

    fn build_erase_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        leaf_index: u64,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(setup.registration.id(), tree_id);
        let membership_id = derive_membership_pda(setup.registration.id(), tree_id, &id_commitment);
        let sid = subtree_id_for_index(leaf_index);
        let subtree_account_id = derive_subtree_pda(setup.registration.id(), tree_id, sid);

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

        let message = Message::try_new(setup.registration.id(), account_ids, vec![], instruction)
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
            DEFAULT_ACTIVE_DURATION,
            DEFAULT_GRACE_PERIOD_DURATION,
        )
    }

    fn register_for_expiration_test(setup: &mut TestSetup, id_commitment: [u8; 32]) {
        let register_tx = build_register_tx(
            setup, &TREE_ID, id_commitment, EXP_RATE_LIMIT, Nonce(0), 0,
        );
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("register should succeed");
    }

    #[test]
    fn test_register_snapshots_grace_period_start() {
        let Some(mut setup) = setup_with_expiration() else { return };

        let register_clock = GENESIS_TIMESTAMP + 500;
        set_clock_50(&mut setup.state, register_clock, 50);

        let id_commitment = valid_field_element(0xA1);
        register_for_expiration_test(&mut setup, id_commitment);

        assert_eq!(
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            register_clock + DEFAULT_ACTIVE_DURATION as u64,
            "grace_period_start_timestamp = now + active_duration",
        );
        assert_eq!(
            read_active_duration(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            DEFAULT_ACTIVE_DURATION,
        );
        assert_eq!(
            read_grace_duration(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            DEFAULT_GRACE_PERIOD_DURATION,
        );
    }

    #[test]
    fn test_extend_succeeds_in_grace_period() {
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA2);
        register_for_expiration_test(&mut setup, id_commitment);

        let grace_start = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64;
        let in_grace = grace_start + (DEFAULT_GRACE_PERIOD_DURATION as u64 / 2);
        set_clock_50(&mut setup.state, in_grace, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment);
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0)
            .expect("extend during grace must succeed");

        let new_grace_start =
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment);
        let expected = grace_start
            + DEFAULT_GRACE_PERIOD_DURATION as u64
            + DEFAULT_ACTIVE_DURATION as u64;
        assert_eq!(new_grace_start, expected, "grace_start += grace + active");
    }

    #[test]
    fn test_extend_fails_when_still_active() {
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA3);
        register_for_expiration_test(&mut setup, id_commitment);

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP + 10, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment);
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
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA4);
        register_for_expiration_test(&mut setup, id_commitment);

        let expiration = GENESIS_TIMESTAMP
            + DEFAULT_ACTIVE_DURATION as u64
            + DEFAULT_GRACE_PERIOD_DURATION as u64;
        set_clock_50(&mut setup.state, expiration + 1, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment);
        let result = setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0);
        assert!(
            result.is_err(),
            "extend after expiration must fail, got {:?}",
            result
        );
    }

    #[test]
    fn test_extend_by_any_caller_succeeds_in_grace() {
        // Sanity: Extend carries no authorization — the builder signs with no keys.
        // If this test fails, something is asserting caller identity.
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA5);
        register_for_expiration_test(&mut setup, id_commitment);

        let in_grace = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64 + 1;
        set_clock_50(&mut setup.state, in_grace, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment);
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0)
            .expect("extend with no signer must succeed");
    }

    #[test]
    fn test_erase_succeeds_when_expired() {
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA6);
        register_for_expiration_test(&mut setup, id_commitment);

        let expiration = GENESIS_TIMESTAMP
            + DEFAULT_ACTIVE_DURATION as u64
            + DEFAULT_GRACE_PERIOD_DURATION as u64;
        set_clock_50(&mut setup.state, expiration + 1, 100);

        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0)
            .expect("erase of expired membership must succeed");

        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment)
                .is_none(),
            "membership data should be cleared",
        );
    }

    #[test]
    fn test_erase_fails_when_active() {
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA7);
        register_for_expiration_test(&mut setup, id_commitment);

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP + 1, 100);

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
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA8);
        register_for_expiration_test(&mut setup, id_commitment);

        let in_grace = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64 + 1;
        set_clock_50(&mut setup.state, in_grace, 100);

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
        let Some(mut setup) = setup_with_expiration() else { return };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xAA);
        register_for_expiration_test(&mut setup, id_commitment);

        let before = get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID);
        assert_eq!(before, EXP_RATE_LIMIT);

        let expiration = GENESIS_TIMESTAMP
            + DEFAULT_ACTIVE_DURATION as u64
            + DEFAULT_GRACE_PERIOD_DURATION as u64;
        set_clock_50(&mut setup.state, expiration + 1, 100);

        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0)
            .expect("erase must succeed");

        let after = get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID);
        assert_eq!(after, 0, "current_total_rate_limit must drop back to 0");
    }
}
