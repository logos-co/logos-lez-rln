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
    use std::fs;

    use nssa::{
        PrivateKey, PublicKey, PublicTransaction, V03State,
        program::Program,
        program_deployment_transaction::{Message as DeployMessage, ProgramDeploymentTransaction},
        public_transaction::{Message, WitnessSet},
    };
    use nssa_core::account::{Account, AccountId, Data, Nonce};
    use programs;
    use token_core::{TokenDefinition, TokenHolding};

    use crate::rln::Instruction;
    // Import shared constants and PDA functions from rln module
    use crate::rln::{
        CLOCK_50_ACCOUNT_ID_BYTES, CONFIG_OFFSET_AUTHORIZED_REGISTRAR,
        CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT, CONFIG_OFFSET_FREE_QUOTA_REMAINING,
        CONFIG_OFFSET_MERKLE_PROGRAM_ID, CONFIG_OFFSET_PAYMENT_TOKEN_ID,
        CONFIG_OFFSET_PRICE_PER_UNIT, CONFIG_OFFSET_TOTAL_REGISTRATIONS,
        CONFIG_OFFSET_TREASURY_ACCOUNT_ID, CONFIG_OFFSET_TREE_ID, CONFIG_SIZE,
        MEMBERSHIP_OFFSET_ACTIVE_DURATION, MEMBERSHIP_OFFSET_DEPOSIT_AMOUNT,
        MEMBERSHIP_OFFSET_EXITING, MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION,
        MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP, MEMBERSHIP_OFFSET_HOLDER,
        MEMBERSHIP_OFFSET_ID_COMMITMENT, MEMBERSHIP_OFFSET_LEAF_INDEX,
        MEMBERSHIP_OFFSET_RATE_LIMIT, MEMBERSHIP_SIZE, TREE_DEPTH, derive_config_account,
        derive_membership_account, derive_subtree_account, derive_tree_main_account,
        subtree_id_for_index,
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

    fn derive_tree_main_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
    ) -> AccountId {
        derive_tree_main_account(&program_id, tree_id)
    }

    fn derive_subtree_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
        subtree_id: u32,
    ) -> AccountId {
        derive_subtree_account(&program_id, tree_id, subtree_id)
    }

    fn derive_config_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
    ) -> AccountId {
        derive_config_account(&program_id, tree_id)
    }

    fn derive_escrow_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
    ) -> AccountId {
        crate::rln::derive_escrow_account(&program_id, tree_id)
    }

    fn derive_payment_token_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
    ) -> AccountId {
        crate::rln::derive_payment_token_account(&program_id, tree_id)
    }

    fn derive_payment_supply_pda(
        program_id: nssa_core::program::ProgramId,
        tree_id: &[u8; 32],
    ) -> AccountId {
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
        let merkle_deploy_tx =
            ProgramDeploymentTransaction::new(DeployMessage::new(merkle_bytecode));
        state
            .transition_from_program_deployment_transaction(&merkle_deploy_tx)
            .ok()?;

        // Deploy registration program
        let registration_deploy_tx =
            ProgramDeploymentTransaction::new(DeployMessage::new(registration_bytecode));
        state
            .transition_from_program_deployment_transaction(&registration_deploy_tx)
            .ok()?;

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
            let subtree_0 = derive_subtree_pda(program.id(), &TREE_ID, 0);
            let subtree_1 = derive_subtree_pda(program.id(), &TREE_ID, 1);

            assert!(
                subtree_0 != subtree_1,
                "Different subtree IDs should have different PDAs"
            );
        }
    }

    #[test]
    fn test_all_registration_pdas_are_distinct() {
        if let Some(program) = load_rln_registration_program() {
            let tree_main = derive_tree_main_pda(program.id(), &TREE_ID);
            let config = derive_config_pda(program.id(), &TREE_ID);
            let subtree = derive_subtree_pda(program.id(), &TREE_ID, 0);

            assert!(tree_main != config, "tree_main and config should differ");
            assert!(tree_main != subtree, "tree_main and subtree should differ");
            assert!(config != subtree, "config and subtree should differ");
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
            programs::token().id(),
            vec![from_id.clone(), to_id.clone()],
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

    /// Builds the two transactions that together initialize the RLN registration program.
    ///
    /// Init is split into Initialize + InitializeMerkleTree so each chained call
    /// runs in its own session, fitting under the 32M-cycle per-call cap.
    fn build_registration_init_txs(
        registration: &Program,
        merkle: &Program,
        tree_id: &[u8; 32],
        payment_token_id: &AccountId,
        price_per_unit: u128,
        treasury_id: &AccountId,
    ) -> [PublicTransaction; 2] {
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
    ) -> [PublicTransaction; 2] {
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
    ) -> [PublicTransaction; 2] {
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
    ) -> [PublicTransaction; 2] {
        let config_id = derive_config_pda(registration.id(), tree_id);
        let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);

        let init_config = build_public_tx(
            registration.id(),
            vec![config_id.clone()],
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

        let init_merkle = build_public_tx(
            registration.id(),
            vec![config_id, tree_main_id],
            Instruction::InitializeMerkleTree { tree_id: *tree_id },
        );

        [init_config, init_merkle]
    }

    fn build_public_tx(
        program_id: nssa_core::program::ProgramId,
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
    fn state_with_initialized_registration_config(max_total_rate_limit: u64) -> Option<TestSetup> {
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
        state.force_insert_account(
            payment_def_id.clone(),
            Account {
                program_owner: token_id,
                data: Data::from(&token_definition),
                ..Account::default()
            },
        );
        let treasury_holding = token_core::TokenHolding::Fungible {
            definition_id: payment_def_id.clone(),
            balance: total_supply - user_amount,
        };
        state.force_insert_account(
            treasury_id.clone(),
            Account {
                program_owner: token_id,
                data: Data::from(&treasury_holding),
                ..Account::default()
            },
        );
        let user_holding = token_core::TokenHolding::Fungible {
            definition_id: payment_def_id.clone(),
            balance: user_amount,
        };
        state.force_insert_account(
            user_payment_id.clone(),
            Account {
                program_owner: token_id,
                data: Data::from(&user_holding),
                ..Account::default()
            },
        );
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
            vec![
                derive_config_pda(registration.id(), &TREE_ID),
                payment_def_id,
                payment_supply_id,
            ],
            Instruction::InitializePaymentToken { tree_id: TREE_ID },
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
    fn get_total_registrations(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
    ) -> u64 {
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
    fn get_current_total_rate_limit(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
    ) -> u64 {
        let config_id = derive_config_pda(registration.id(), tree_id);
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
        let holding =
            TokenHolding::try_from(&account.data).expect("Failed to deserialize token holding");
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
            TokenDefinition::NonFungible {
                printable_supply, ..
            } => printable_supply,
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
    fn get_membership_data(
        state: &V03State,
        registration: &Program,
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> Option<MembershipData> {
        let membership_id = derive_membership_pda(registration.id(), tree_id, id_commitment);
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
            derive_escrow_pda(registration.id(), tree_id),
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
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[user_payment_key]),
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
    /// Make the registrar a program-owned account.
    ///
    /// `register_free` requires this, and LEZ is why: the registrar is a
    /// declared account, so it is echoed into the program output, and rule 7
    /// only tolerates echoing a DEFAULT-owned account while it is pristine.
    /// Signing bumps the nonce, so a plain-wallet registrar would pass once
    /// and then have every later RegisterFree silently dropped at inclusion.
    /// Deployments seed the registrar by claiming tokens into it before first
    /// use; tests do it directly.
    fn seed_program_owned_registrar(
        state: &mut V03State,
        payment_def_id: &AccountId,
        registrar_id: &AccountId,
    ) {
        let holding = token_core::TokenHolding::Fungible {
            definition_id: payment_def_id.clone(),
            balance: 0,
        };
        state.force_insert_account(
            registrar_id.clone(),
            Account {
                program_owner: programs::token().id(),
                data: Data::from(&holding),
                ..Account::default()
            },
        );
    }

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
        )
        .expect("valid message");

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
        let instruction = Instruction::ClaimTokens {
            tree_id: *tree_id,
            amount,
        };

        let nonces = if dest_key.is_some() {
            vec![dest_nonce]
        } else {
            vec![]
        };
        let message = Message::try_new(registration.id(), account_ids, nonces, instruction)
            .expect("valid message");

        let keys: Vec<&PrivateKey> = dest_key.into_iter().collect();
        PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &keys))
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

        // Account list: config, tree_main, membership, subtree, escrow, payment def
        let account_ids = vec![
            config_id,
            tree_main_id,
            membership_id,
            subtree_account_id,
            derive_escrow_pda(setup.registration.id(), tree_id),
            setup.payment_def_id.clone(),
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
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

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

        apply_registration_init(&mut state, &init_txs).expect("Init should succeed");

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
        assert!(
            data.len() >= CONFIG_SIZE,
            "Config should be at least {CONFIG_SIZE} bytes"
        );

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
    }

    #[test]
    fn test_registration_init_creates_tree_main() {
        let (mut state, merkle, registration) =
            state_with_programs().expect("Programs should load");

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

        apply_registration_init(&mut state, &init_txs).expect("Init should succeed");

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
        apply_registration_init(&mut state, &init_txs).expect("Init should succeed");

        // Config binds the tree to `merkle`, so a second tree_id whose config
        // was never initialized has nothing to read: the init must fail rather
        // than fall back to a caller-named program.
        let other_tree_id = [0x99u8; 32];
        let orphan_tx = build_public_tx(
            registration.id(),
            vec![
                derive_config_pda(registration.id(), &other_tree_id),
                derive_tree_main_pda(registration.id(), &other_tree_id),
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

        let tree_main_id = derive_tree_main_pda(setup.registration.id(), &TREE_ID);
        let before = setup
            .state
            .get_account_by_id(tree_main_id.clone())
            .data
            .as_ref()
            .to_vec();
        assert_eq!(
            u64::from_le_bytes(before[1..9].try_into().unwrap()),
            1,
            "the member should be in the tree before the reset attempt"
        );

        let attack_tx = build_public_tx(
            setup.registration.id(),
            vec![
                derive_config_pda(setup.registration.id(), &TREE_ID),
                tree_main_id.clone(),
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

    // SECURITY (free-registration exploit): `register` must reject a payment
    // holding whose data looks valid (right definition, huge balance) but which
    // is owned by a program OTHER than the configured token program. Pre-fix,
    // the payment Transfer was dispatched to the holding's OWN program_owner, so
    // an attacker's no-op program let registration mint a membership while the
    // treasury was never paid. Positive control: `test_register_succeeds` runs
    // the identical flow with a token-program-owned holding and passes.
    #[test]
    fn test_register_rejects_holding_owned_by_foreign_program() {
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        // Forge the payer: valid token-holding bytes and an unlimited balance,
        // but owned by the merkle program (any non-token program stands in for
        // the attacker's).
        let forged = TokenHolding::Fungible {
            definition_id: setup.payment_def_id.clone(),
            balance: u128::MAX,
        };
        setup.state.force_insert_account(
            setup.user_payment_id.clone(),
            Account {
                program_owner: setup.merkle.id(),
                data: Data::from(&forged),
                ..Account::default()
            },
        );

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
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
            "register must reject a payment holding not owned by the configured \
             token program (free-registration exploit); got Ok: {result:?}"
        );
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
    // Deployment Policy Tests — faucet funding + free-quota membership
    // ========================================================================

    fn read_holding(state: &V03State, id: &AccountId) -> Option<token_core::TokenHolding> {
        let account = state.get_account_by_id(id.clone());
        token_core::TokenHolding::try_from(&account.data).ok()
    }

    #[test]
    fn test_faucet_init_creates_program_owned_payment_token() {
        let (state, registration) =
            state_with_faucet_registration(10_000_000).expect("Faucet setup should succeed");

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
            token_core::TokenDefinition::Fungible {
                name, total_supply, ..
            } => {
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
        let (mut state, registration) =
            state_with_faucet_registration(10_000_000).expect("Faucet setup should succeed");

        let (dest_key, dest_id) = create_test_keypair(21);
        let claim = build_claim_tokens_tx(
            &registration,
            &TREE_ID,
            &dest_id,
            Some(&dest_key),
            1_000_000,
            Nonce(0),
        );
        state
            .transition_from_public_transaction(&claim, 1, 0)
            .expect("Claim should succeed");

        let holding = read_holding(&state, &dest_id).expect("dest holding should decode");
        match holding {
            token_core::TokenHolding::Fungible {
                definition_id,
                balance,
            } => {
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
        let def_account =
            state.get_account_by_id(derive_payment_token_pda(registration.id(), &TREE_ID));
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
        let (mut state, registration) =
            state_with_faucet_registration(1_000_000).expect("Faucet setup should succeed");

        let (dest_key, dest_id) = create_test_keypair(22);
        let claim = build_claim_tokens_tx(
            &registration,
            &TREE_ID,
            &dest_id,
            Some(&dest_key),
            1_000_001,
            Nonce(0),
        );
        let result = state.transition_from_public_transaction(&claim, 1, 0);
        assert!(result.is_err(), "Claim above faucet_claim_cap should fail");
    }

    #[test]
    fn test_claim_tokens_rejects_when_faucet_disabled() {
        // Wallet-key deployment: faucet_claim_cap = 0.
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (dest_key, dest_id) = create_test_keypair(23);
        let claim = build_claim_tokens_tx(
            &setup.registration,
            &TREE_ID,
            &dest_id,
            Some(&dest_key),
            1,
            Nonce(0),
        );
        let result = setup.state.transition_from_public_transaction(&claim, 1, 0);
        assert!(
            result.is_err(),
            "Claim should fail when the faucet is disabled"
        );
    }

    #[test]
    fn test_claim_tokens_rejects_unsigned_destination() {
        let (mut state, registration) =
            state_with_faucet_registration(10_000_000).expect("Faucet setup should succeed");

        let (_dest_key, dest_id) = create_test_keypair(24);
        let claim =
            build_claim_tokens_tx(&registration, &TREE_ID, &dest_id, None, 1_000_000, Nonce(0));
        let result = state.transition_from_public_transaction(&claim, 1, 0);
        assert!(
            result.is_err(),
            "Minting into a fresh holding requires the destination's signature (Claim::Authorized)"
        );
    }

    #[test]
    fn test_register_free_succeeds_and_decrements_quota() {
        let (registrar_key, registrar_id) = create_test_keypair(31);
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 2)
                .expect("Setup should succeed");
        seed_program_owned_registrar(&mut setup.state, &setup.payment_def_id, &registrar_id);

        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            valid_field_element(0x51),
            300,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
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

        let config = setup
            .state
            .get_account_by_id(derive_config_pda(setup.registration.id(), &TREE_ID));
        let data = config.data.as_ref();
        let quota = u64::from_le_bytes(
            data[CONFIG_OFFSET_FREE_QUOTA_REMAINING..CONFIG_OFFSET_FREE_QUOTA_REMAINING + 8]
                .try_into()
                .unwrap(),
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
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 1)
                .expect("Setup should succeed");
        seed_program_owned_registrar(&mut setup.state, &setup.payment_def_id, &registrar_id);

        let tx1 = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            valid_field_element(0x52),
            300,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&tx1, 1, 0)
            .expect("First free registration should succeed");

        let tx2 = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            valid_field_element(0x53),
            300,
            Nonce(1),
            1,
        );
        let result = setup.state.transition_from_public_transaction(&tx2, 1, 0);
        assert!(
            result.is_err(),
            "Second free registration should fail (quota exhausted)"
        );
    }

    // SECURITY (registrar reuse): the registrar signs, so LEZ increments its
    // nonce after every free registration. Because the registrar is a declared
    // account and therefore echoed into the program output, rule 7
    // (NonDefaultAccountWithDefaultOwner) rejects the echo of a DEFAULT-owned
    // account that is no longer pristine — a plain-wallet registrar works
    // exactly ONCE and then every RegisterFree is dropped at block inclusion,
    // visible only in the sequencer log. A program-owned registrar is exempt
    // (rule 7 is skipped) and must keep working indefinitely.
    //
    // test_register_free_quota_exhaustion cannot catch this: it sets
    // free_quota = 1, so its second tx panics inside the guest on the quota
    // assert before validation is reached, and it only asserts is_err().
    #[test]
    fn test_register_free_works_repeatedly_for_one_registrar() {
        let (registrar_key, registrar_id) = create_test_keypair(35);
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 3)
                .expect("Setup should succeed");
        seed_program_owned_registrar(&mut setup.state, &setup.payment_def_id, &registrar_id);

        for (i, commitment) in [0x61u8, 0x62, 0x63].iter().enumerate() {
            let tx = build_register_free_tx(
                &setup.registration,
                &TREE_ID,
                &registrar_id,
                &registrar_key,
                valid_field_element(*commitment),
                300,
                Nonce(i as u128),
                i as u64,
            );
            setup
                .state
                .transition_from_public_transaction(&tx, 1, 0)
                .unwrap_or_else(|e| panic!("free registration #{} must succeed, got {e:?}", i + 1));
        }
    }

    // The same trap, asserted from the other side: a DEFAULT-owned (plain
    // wallet) registrar is refused up front with a clear message, rather than
    // succeeding once and then failing opaquely forever.
    #[test]
    fn test_register_free_rejects_a_plain_wallet_registrar() {
        let (registrar_key, registrar_id) = create_test_keypair(36);
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 2)
                .expect("Setup should succeed");
        // Deliberately NOT seeded as program-owned.

        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            valid_field_element(0x64),
            300,
            Nonce(0),
            0,
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&tx, 1, 0)
                .is_err(),
            "a plain-wallet registrar must be rejected on the FIRST call"
        );
    }

    #[test]
    fn test_register_free_rejects_wrong_signer() {
        let (_registrar_key, registrar_id) = create_test_keypair(33);
        let (impostor_key, impostor_id) = create_test_keypair(34);
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 5)
                .expect("Setup should succeed");
        seed_program_owned_registrar(&mut setup.state, &setup.payment_def_id, &registrar_id);

        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &impostor_id,
            &impostor_key,
            valid_field_element(0x54),
            300,
            Nonce(0),
            0,
        );
        let result = setup.state.transition_from_public_transaction(&tx, 1, 0);
        assert!(result.is_err(), "Non-registrar signer must be rejected");
    }

    #[test]
    fn test_register_free_rejects_without_registrar_config() {
        // Default deployment: no registrar, no quota.
        let mut setup = state_with_initialized_registration().expect("Setup should succeed");

        let (key, id) = create_test_keypair(35);
        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &id,
            &key,
            valid_field_element(0x55),
            300,
            Nonce(0),
            0,
        );
        let result = setup.state.transition_from_public_transaction(&tx, 1, 0);
        assert!(
            result.is_err(),
            "RegisterFree must fail when no registrar is configured"
        );
    }

    #[test]
    fn test_paid_register_still_works_in_quota_deployment() {
        // Additive policy: the paid path is unaffected by a configured quota.
        let (_registrar_key, registrar_id) = create_test_keypair(36);
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 5)
                .expect("Setup should succeed");
        seed_program_owned_registrar(&mut setup.state, &setup.payment_def_id, &registrar_id);

        let register_tx = build_register_tx(
            &setup,
            &TREE_ID,
            valid_field_element(0x56),
            300,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Paid registration should still succeed in a quota deployment");
    }

    #[test]
    fn test_paid_register_works_in_faucet_deployment() {
        // Faucet deployments keep the paid path: the user's holding is seeded
        // by a claim, then a normal Register escrows the deposit out of it.
        let (mut state, registration) =
            state_with_faucet_registration(10_000_000).expect("Faucet setup should succeed");

        let (user_key, user_id) = create_test_keypair(40);
        let fund_user = build_claim_tokens_tx(
            &registration,
            &TREE_ID,
            &user_id,
            Some(&user_key),
            5_000_000,
            Nonce(0),
        );
        state
            .transition_from_public_transaction(&fund_user, 1, 0)
            .expect("User funding claim should succeed");

        let rate_limit = 300u64;
        let register_tx = build_register_tx_parts(
            &registration,
            &TREE_ID,
            &user_id,
            &user_key,
            valid_field_element(0x57),
            rate_limit,
            Nonce(1),
            0,
        );
        state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("Paid registration should succeed in a faucet deployment");

        assert_eq!(
            get_total_registrations(&state, &registration, &TREE_ID),
            1,
            "Registration should be recorded in config"
        );
        let deposit = u128::from(rate_limit) * PRICE_PER_UNIT;
        let escrow_id = derive_escrow_pda(registration.id(), &TREE_ID);
        match read_holding(&state, &escrow_id).expect("escrow holding should decode") {
            token_core::TokenHolding::Fungible { balance, .. } => assert_eq!(
                balance, deposit,
                "Escrow should hold exactly the registration deposit"
            ),
            token_core::TokenHolding::NftMaster { .. }
            | token_core::TokenHolding::NftPrintedCopy { .. } => {
                panic!("Escrow holding should be fungible")
            }
        }
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
        Fr, Hasher, IdentityKeys, PoseidonHash, RLNBuilder, RLNMerkleProof, RLNWitnessInput,
        hash_to_field_le,
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
            let tree_main_id = derive_tree_main_pda(registration.id(), tree_id);
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

            let sibling_index = if node_index % 2 == 0 {
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

        // Convert to Fr types for zerokit
        let path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
            .collect();
        let root = bytes_le_to_fr(&root_bytes).expect("Invalid root");

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
        let rln = RLNBuilder::stateless().build();

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
        let path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
            .collect();
        let root = bytes_le_to_fr(&root_bytes).expect("Invalid root");

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

        let rln = RLNBuilder::stateless().build();
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
        let tree_main_id = derive_tree_main_pda(setup.registration.id(), &TREE_ID);
        let tree_before = setup.state.get_account_by_id(tree_main_id.clone());
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

        let path_elements: Vec<Fr> = path_elements_bytes
            .iter()
            .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
            .collect();
        let root = bytes_le_to_fr(&root_bytes).expect("Invalid root");

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

        let rln = RLNBuilder::stateless().build();

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
    /// subsequent program invocations observe `now == timestamp`. Uses the
    /// `test-utils` `force_insert_account` escape hatch instead of issuing
    /// 50 clock-ticks, because CLOCK_50 only refreshes every 50 blocks.
    fn set_clock_50(state: &mut V03State, timestamp: u64, block_id: u64) {
        use clock_core::{CLOCK_50_PROGRAM_ACCOUNT_ID, ClockAccountData};
        let data = ClockAccountData {
            block_id,
            timestamp,
        }
        .to_bytes();
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

    /// Renewal is PAID (same price as registering the membership's rate
    /// limit), so the payer holding signs and is debited — extend is no longer
    /// a zero-signer transaction.
    fn build_extend_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        payer_nonce: Nonce,
    ) -> PublicTransaction {
        let config_id = derive_config_pda(setup.registration.id(), tree_id);
        let membership_id = derive_membership_pda(setup.registration.id(), tree_id, &id_commitment);

        let account_ids = vec![
            config_id,
            membership_id,
            setup.user_payment_id.clone(),
            setup.treasury_id.clone(),
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
        ];

        let instruction = Instruction::Extend {
            tree_id: *tree_id,
            id_commitment,
        };

        let message = Message::try_new(
            setup.registration.id(),
            account_ids,
            vec![payer_nonce], // nonce for the payer holding (index 2)
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[&setup.user_payment_key]),
        )
    }

    /// `holder_id` must be the membership's recorded depositor; tests pass a
    /// different account deliberately to exercise the rejection.
    fn build_erase_tx_to(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        leaf_index: u64,
        holder_id: &AccountId,
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
            derive_escrow_pda(setup.registration.id(), tree_id),
            holder_id.clone(),
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

    /// Erase refunding to the account that registered in `TestSetup`.
    fn build_erase_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        leaf_index: u64,
    ) -> PublicTransaction {
        let holder = setup.user_payment_id.clone();
        build_erase_tx_to(setup, tree_id, id_commitment, leaf_index, &holder)
    }

    fn build_force_expire_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        id_commitment: [u8; 32],
        holder_id: &AccountId,
        holder_key: &PrivateKey,
        holder_nonce: Nonce,
    ) -> PublicTransaction {
        let membership_id = derive_membership_pda(setup.registration.id(), tree_id, &id_commitment);

        let account_ids = vec![
            membership_id,
            holder_id.clone(),
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
        ];

        let instruction = Instruction::ForceExpire {
            tree_id: *tree_id,
            id_commitment,
        };

        let message = Message::try_new(
            setup.registration.id(),
            account_ids,
            vec![holder_nonce],
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[holder_key]),
        )
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
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA2);
        register_for_expiration_test(&mut setup, id_commitment);

        let grace_start = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64;
        let in_grace = grace_start + (DEFAULT_GRACE_PERIOD_DURATION as u64 / 2);
        set_clock_50(&mut setup.state, in_grace, 100);

        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0)
            .expect("extend during grace must succeed");

        let new_grace_start =
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment);
        let expected =
            grace_start + DEFAULT_GRACE_PERIOD_DURATION as u64 + DEFAULT_ACTIVE_DURATION as u64;
        assert_eq!(new_grace_start, expected, "grace_start += grace + active");
    }

    #[test]
    fn test_extend_fails_when_still_active() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA3);
        register_for_expiration_test(&mut setup, id_commitment);

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP + 10, 100);

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

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA4);
        register_for_expiration_test(&mut setup, id_commitment);

        let expiration = GENESIS_TIMESTAMP
            + DEFAULT_ACTIVE_DURATION as u64
            + DEFAULT_GRACE_PERIOD_DURATION as u64;
        set_clock_50(&mut setup.state, expiration + 1, 100);

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

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA5);
        register_for_expiration_test(&mut setup, id_commitment);

        let in_grace = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64 + 1;
        set_clock_50(&mut setup.state, in_grace, 100);

        let paid_before = get_token_balance(&setup.state, &setup.user_payment_id);
        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(1));
        setup
            .state
            .transition_from_public_transaction(&extend_tx, 2, 0)
            .expect("a paying third party may renew");

        let paid_after = get_token_balance(&setup.state, &setup.user_payment_id);
        let expected = EXP_RATE_LIMIT as u128 * PRICE_PER_UNIT;
        assert_eq!(
            paid_before - paid_after,
            expected,
            "renewal must cost the same as registering that rate limit"
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

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xA7);
        register_for_expiration_test(&mut setup, id_commitment);

        // Empty the payer's holding (keeping it a valid token-owned holding),
        // then try to renew.
        let in_grace = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64 + 1;
        set_clock_50(&mut setup.state, in_grace, 100);
        let empty = token_core::TokenHolding::Fungible {
            definition_id: setup.payment_def_id.clone(),
            balance: 0,
        };
        let prior = setup.state.get_account_by_id(setup.user_payment_id.clone());
        setup.state.force_insert_account(
            setup.user_payment_id.clone(),
            Account {
                data: Data::from(&empty),
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
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment).is_none(),
            "membership data should be cleared",
        );
    }

    #[test]
    fn test_erase_fails_when_active() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

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
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

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
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };

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

    // ========================================================================
    // Deposits — escrow, refund, burn
    // ========================================================================

    /// Deposit for `EXP_RATE_LIMIT` at the suite's configured price.
    const EXP_DEPOSIT: u128 = EXP_RATE_LIMIT as u128 * PRICE_PER_UNIT;

    /// Escrow balance, treating an uninitialized escrow as empty — a tree with
    /// only free registrations never creates one.
    fn escrow_balance(setup: &TestSetup) -> u128 {
        let escrow_id = derive_escrow_pda(setup.registration.id(), &TREE_ID);
        match read_holding(&setup.state, &escrow_id) {
            Some(token_core::TokenHolding::Fungible { balance, .. }) => balance,
            Some(_) => panic!("escrow must be a fungible holding"),
            None => 0,
        }
    }

    fn read_deposit_amount(setup: &TestSetup, id_commitment: &[u8; 32]) -> u128 {
        let data = read_membership(&setup.state, &setup.registration, &TREE_ID, id_commitment)
            .expect("membership must exist");
        u128::from_le_bytes(
            data[MEMBERSHIP_OFFSET_DEPOSIT_AMOUNT..MEMBERSHIP_OFFSET_DEPOSIT_AMOUNT + 16]
                .try_into()
                .unwrap(),
        )
    }

    fn read_holder(setup: &TestSetup, id_commitment: &[u8; 32]) -> [u8; 32] {
        let data = read_membership(&setup.state, &setup.registration, &TREE_ID, id_commitment)
            .expect("membership must exist");
        data[MEMBERSHIP_OFFSET_HOLDER..MEMBERSHIP_OFFSET_HOLDER + 32]
            .try_into()
            .unwrap()
    }

    fn read_exiting(setup: &TestSetup, id_commitment: &[u8; 32]) -> u8 {
        let data = read_membership(&setup.state, &setup.registration, &TREE_ID, id_commitment)
            .expect("membership must exist");
        data[MEMBERSHIP_OFFSET_EXITING]
    }

    /// Advance the clock past a membership registered at `GENESIS_TIMESTAMP`.
    fn advance_past_expiry(setup: &mut TestSetup) {
        let expiration = GENESIS_TIMESTAMP
            + DEFAULT_ACTIVE_DURATION as u64
            + DEFAULT_GRACE_PERIOD_DURATION as u64;
        set_clock_50(&mut setup.state, expiration + 1, 100);
    }

    #[test]
    fn test_register_escrows_the_deposit_and_leaves_the_treasury_alone() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);

        let user_before = get_token_balance(&setup.state, &setup.user_payment_id);
        let treasury_before = get_token_balance(&setup.state, &setup.treasury_id);

        register_for_expiration_test(&mut setup, valid_field_element(0xD0));

        assert_eq!(
            escrow_balance(&setup),
            EXP_DEPOSIT,
            "escrow must hold exactly the deposit"
        );
        assert_eq!(
            user_before - get_token_balance(&setup.state, &setup.user_payment_id),
            EXP_DEPOSIT,
            "the depositor must be debited exactly the deposit"
        );
        assert_eq!(
            get_token_balance(&setup.state, &setup.treasury_id),
            treasury_before,
            "registration must not pay the treasury"
        );
    }

    #[test]
    fn test_register_records_holder_and_deposit() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xD1);
        register_for_expiration_test(&mut setup, id_commitment);

        assert_eq!(
            read_holder(&setup, &id_commitment),
            *setup.user_payment_id.value(),
            "the paying holding must be recorded as the holder"
        );
        assert_eq!(read_deposit_amount(&setup, &id_commitment), EXP_DEPOSIT);
        assert_eq!(read_exiting(&setup, &id_commitment), 0);
    }

    #[test]
    fn test_erase_refunds_the_deposit_to_the_recorded_holder() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xD2);

        let user_before = get_token_balance(&setup.state, &setup.user_payment_id);
        register_for_expiration_test(&mut setup, id_commitment);
        advance_past_expiry(&mut setup);

        // Erase carries no signature: the refund follows the record, not the
        // submitter.
        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0)
            .expect("erase of an expired membership must succeed");

        assert_eq!(
            get_token_balance(&setup.state, &setup.user_payment_id),
            user_before,
            "the holder must be made whole"
        );
        assert_eq!(escrow_balance(&setup), 0, "escrow must be drained");
    }

    #[test]
    fn test_erase_rejects_a_refund_to_a_non_holder() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xD3);
        register_for_expiration_test(&mut setup, id_commitment);
        advance_past_expiry(&mut setup);

        // A real funded holding of the same token; it just did not pay this
        // deposit.
        let treasury_id = setup.treasury_id.clone();
        let thief_tx = build_erase_tx_to(&setup, &TREE_ID, id_commitment, 0, &treasury_id);
        assert!(
            setup
                .state
                .transition_from_public_transaction(&thief_tx, 2, 0)
                .is_err(),
            "erase must refuse to pay a holding that is not the membership's holder"
        );
        assert_eq!(
            escrow_balance(&setup),
            EXP_DEPOSIT,
            "a refused erase must leave the deposit escrowed"
        );
    }

    #[test]
    fn test_slash_burns_the_deposit() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);

        let identity_secret = valid_field_element(0xD4);
        let id_commitment = derive_id_commitment_from_secret(&identity_secret);
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, EXP_RATE_LIMIT, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("register should succeed");

        let user_after_register = get_token_balance(&setup.state, &setup.user_payment_id);
        let supply_before = get_token_supply(&setup.state, &setup.payment_def_id);

        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 2, 0)
            .expect("slash should succeed");

        assert_eq!(escrow_balance(&setup), 0, "escrow must be drained");
        assert_eq!(
            get_token_supply(&setup.state, &setup.payment_def_id),
            supply_before - EXP_DEPOSIT,
            "a slashed deposit must be destroyed, not moved"
        );
        assert_eq!(
            get_token_balance(&setup.state, &setup.user_payment_id),
            user_after_register,
            "a slashed member must not be refunded"
        );
    }

    #[test]
    fn test_slash_during_wind_down_still_burns_the_deposit() {
        // Why the deposit is held until expiry: exiting does not outrun a slash.
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);

        let identity_secret = valid_field_element(0xD5);
        let id_commitment = derive_id_commitment_from_secret(&identity_secret);
        let register_tx =
            build_register_tx(&setup, &TREE_ID, id_commitment, EXP_RATE_LIMIT, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&register_tx, 1, 0)
            .expect("register should succeed");

        let holder_id = setup.user_payment_id.clone();
        let holder_key = setup.user_payment_key.clone();
        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &holder_id,
            &holder_key,
            Nonce(1),
        );
        setup
            .state
            .transition_from_public_transaction(&force_tx, 2, 0)
            .expect("force-expire should succeed");

        let supply_before = get_token_supply(&setup.state, &setup.payment_def_id);
        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 3, 0)
            .expect("slash must still succeed mid wind-down");

        assert_eq!(
            get_token_supply(&setup.state, &setup.payment_def_id),
            supply_before - EXP_DEPOSIT,
            "the deposit must still be burnable while the holder is exiting"
        );
    }

    #[test]
    fn test_escrow_returns_to_zero_after_erasing_every_membership() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);

        let commitments = [
            valid_field_element(0xD6),
            valid_field_element(0xD7),
            valid_field_element(0xD8),
        ];
        for (i, id_commitment) in commitments.iter().enumerate() {
            let tx = build_register_tx(
                &setup,
                &TREE_ID,
                *id_commitment,
                EXP_RATE_LIMIT,
                Nonce(i as u128),
                i as u64,
            );
            setup
                .state
                .transition_from_public_transaction(&tx, 1, 0)
                .expect("register should succeed");
        }
        assert_eq!(
            escrow_balance(&setup),
            EXP_DEPOSIT * commitments.len() as u128
        );

        advance_past_expiry(&mut setup);
        for (i, id_commitment) in commitments.iter().enumerate() {
            let tx = build_erase_tx(&setup, &TREE_ID, *id_commitment, i as u64);
            setup
                .state
                .transition_from_public_transaction(&tx, 2, 0)
                .expect("erase should succeed");
        }

        assert_eq!(
            escrow_balance(&setup),
            0,
            "escrow must conserve: every deposit in, every deposit out"
        );
    }

    // ========================================================================
    // Holder-initiated exit
    // ========================================================================

    #[test]
    fn test_force_expire_starts_the_grace_period_now() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xE0);
        register_for_expiration_test(&mut setup, id_commitment);

        assert_eq!(
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64,
        );

        let exit_at = GENESIS_TIMESTAMP + 100;
        set_clock_50(&mut setup.state, exit_at, 60);
        let holder_id = setup.user_payment_id.clone();
        let holder_key = setup.user_payment_key.clone();
        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &holder_id,
            &holder_key,
            Nonce(1),
        );
        setup
            .state
            .transition_from_public_transaction(&force_tx, 2, 0)
            .expect("the holder must be able to force expiry");

        assert_eq!(
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            exit_at,
            "grace must start at the moment of the request"
        );
        assert_eq!(read_exiting(&setup, &id_commitment), 1);
    }

    #[test]
    fn test_force_expire_rejects_a_non_holder() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xE1);
        register_for_expiration_test(&mut setup, id_commitment);

        let other_id = setup.treasury_id.clone();
        let other_key = setup.treasury_key.clone();
        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &other_id,
            &other_key,
            Nonce(0),
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&force_tx, 2, 0)
                .is_err(),
            "only the membership's holder may wind it down"
        );
    }

    #[test]
    fn test_force_expire_never_postpones_expiry() {
        // `min`: from inside grace this is a no-op, never a fresh window.
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xE2);
        register_for_expiration_test(&mut setup, id_commitment);

        let grace_start = GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64;
        set_clock_50(&mut setup.state, grace_start + 10, 60);

        let holder_id = setup.user_payment_id.clone();
        let holder_key = setup.user_payment_key.clone();
        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &holder_id,
            &holder_key,
            Nonce(1),
        );
        setup
            .state
            .transition_from_public_transaction(&force_tx, 2, 0)
            .expect("force-expire in grace should succeed");

        assert_eq!(
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            grace_start,
            "an in-grace exit must not move the expiry out"
        );
    }

    #[test]
    fn test_extend_is_rejected_once_the_holder_is_exiting() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xE3);
        register_for_expiration_test(&mut setup, id_commitment);

        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP + 100, 60);
        let holder_id = setup.user_payment_id.clone();
        let holder_key = setup.user_payment_key.clone();
        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &holder_id,
            &holder_key,
            Nonce(1),
        );
        setup
            .state
            .transition_from_public_transaction(&force_tx, 2, 0)
            .expect("force-expire should succeed");

        // In the grace window the exit just opened, so only `exiting` refuses.
        let extend_tx = build_extend_tx(&setup, &TREE_ID, id_commitment, Nonce(2));
        assert!(
            setup
                .state
                .transition_from_public_transaction(&extend_tx, 3, 0)
                .is_err(),
            "a third party must not be able to reverse a holder's exit"
        );
    }

    #[test]
    fn test_force_expire_then_erase_returns_the_full_deposit() {
        let Some(mut setup) = setup_with_expiration() else {
            return;
        };
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        let id_commitment = valid_field_element(0xE4);

        let user_before = get_token_balance(&setup.state, &setup.user_payment_id);
        register_for_expiration_test(&mut setup, id_commitment);

        let exit_at = GENESIS_TIMESTAMP + 100;
        set_clock_50(&mut setup.state, exit_at, 60);
        let holder_id = setup.user_payment_id.clone();
        let holder_key = setup.user_payment_key.clone();
        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &holder_id,
            &holder_key,
            Nonce(1),
        );
        setup
            .state
            .transition_from_public_transaction(&force_tx, 2, 0)
            .expect("force-expire should succeed");

        // The deposit stays locked for the grace window the exit started.
        let too_early = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        assert!(
            setup
                .state
                .transition_from_public_transaction(&too_early, 3, 0)
                .is_err(),
            "the deposit must stay escrowed until the wind-down window closes"
        );

        set_clock_50(
            &mut setup.state,
            exit_at + DEFAULT_GRACE_PERIOD_DURATION as u64 + 1,
            70,
        );
        let erase_tx = build_erase_tx(&setup, &TREE_ID, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 4, 0)
            .expect("erase after the wind-down window must succeed");

        assert_eq!(
            get_token_balance(&setup.state, &setup.user_payment_id),
            user_before,
            "the exiting holder must get the whole deposit back"
        );
    }

    /// A deployment with a free-quota registrar, clock at genesis.
    fn free_membership_setup(registrar_id: &AccountId) -> Option<TestSetup> {
        let mut setup =
            state_with_policy_registration(DEFAULT_MAX_TOTAL_RATE_LIMIT, *registrar_id.value(), 2)?;
        seed_program_owned_registrar(&mut setup.state, &setup.payment_def_id, registrar_id);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);
        Some(setup)
    }

    #[test]
    fn test_free_membership_records_no_deposit_and_erases_without_a_refund() {
        let (registrar_key, registrar_id) = create_test_keypair(37);
        let Some(mut setup) = free_membership_setup(&registrar_id) else {
            return;
        };

        let id_commitment = valid_field_element(0xE5);
        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            id_commitment,
            EXP_RATE_LIMIT,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("free registration should succeed");

        assert_eq!(read_deposit_amount(&setup, &id_commitment), 0);
        assert_eq!(
            read_holder(&setup, &id_commitment),
            *registrar_id.value(),
            "a free membership stands its registrar as holder"
        );
        assert_eq!(
            escrow_balance(&setup),
            0,
            "a free registration must not touch escrow"
        );

        advance_past_expiry(&mut setup);
        let erase_tx = build_erase_tx_to(&setup, &TREE_ID, id_commitment, 0, &registrar_id);
        setup
            .state
            .transition_from_public_transaction(&erase_tx, 2, 0)
            .expect("a zero-deposit membership must erase with no token leg");

        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment).is_none(),
            "membership data should be cleared"
        );
    }

    #[test]
    fn test_free_membership_slashes_without_a_burn() {
        let (registrar_key, registrar_id) = create_test_keypair(38);
        let Some(mut setup) = free_membership_setup(&registrar_id) else {
            return;
        };

        let identity_secret = valid_field_element(0xE6);
        let id_commitment = derive_id_commitment_from_secret(&identity_secret);
        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            id_commitment,
            EXP_RATE_LIMIT,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("free registration should succeed");

        let supply_before = get_token_supply(&setup.state, &setup.payment_def_id);
        let slash_tx = build_slash_tx(&setup, &TREE_ID, identity_secret, id_commitment, 0);
        setup
            .state
            .transition_from_public_transaction(&slash_tx, 2, 0)
            .expect("a zero-deposit membership must slash with no token leg");

        assert_eq!(
            get_token_supply(&setup.state, &setup.payment_def_id),
            supply_before,
            "there is no deposit to burn for a free membership"
        );
        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &id_commitment).is_none(),
            "membership data should be cleared"
        );
    }

    #[test]
    fn test_force_expire_rejects_a_free_membership() {
        // Without a deposit guard, the registrar recorded as `holder` would
        // gain a revocation power over everything it ever gifted.
        let (registrar_key, registrar_id) = create_test_keypair(39);
        let Some(mut setup) = free_membership_setup(&registrar_id) else {
            return;
        };

        let id_commitment = valid_field_element(0xE7);
        let tx = build_register_free_tx(
            &setup.registration,
            &TREE_ID,
            &registrar_id,
            &registrar_key,
            id_commitment,
            EXP_RATE_LIMIT,
            Nonce(0),
            0,
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("free registration should succeed");

        let force_tx = build_force_expire_tx(
            &setup,
            &TREE_ID,
            id_commitment,
            &registrar_id,
            &registrar_key,
            Nonce(1),
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&force_tx, 2, 0)
                .is_err(),
            "a membership with no escrowed deposit has nothing to force-expire"
        );
        assert_eq!(
            read_grace_start(&setup.state, &setup.registration, &TREE_ID, &id_commitment),
            GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64,
            "the gifted membership's lifecycle must be untouched"
        );
    }

    // ========================================================================
    // Replace-on-register
    // ========================================================================

    /// A funded holding for a second party; `insert_funded_payment_token`
    /// seeds only the treasury and one user.
    fn insert_funded_holding(
        state: &mut V03State,
        payment_def_id: &AccountId,
        account_id: &AccountId,
        balance: u128,
    ) {
        let holding = token_core::TokenHolding::Fungible {
            definition_id: payment_def_id.clone(),
            balance,
        };
        state.force_insert_account(
            account_id.clone(),
            Account {
                program_owner: programs::token().id(),
                data: Data::from(&holding),
                ..Account::default()
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn build_register_replacing_tx(
        setup: &TestSetup,
        tree_id: &[u8; 32],
        payer_id: &AccountId,
        payer_key: &PrivateKey,
        id_commitment: [u8; 32],
        rate_limit: u64,
        id_commitment_to_replace: [u8; 32],
        old_leaf_index: u64,
        old_holder_id: &AccountId,
        payer_nonce: Nonce,
    ) -> PublicTransaction {
        let sid = subtree_id_for_index(old_leaf_index);
        let account_ids = vec![
            derive_config_pda(setup.registration.id(), tree_id),
            derive_tree_main_pda(setup.registration.id(), tree_id),
            payer_id.clone(),
            derive_escrow_pda(setup.registration.id(), tree_id),
            derive_subtree_pda(setup.registration.id(), tree_id, sid),
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            derive_membership_pda(setup.registration.id(), tree_id, &id_commitment),
            derive_membership_pda(setup.registration.id(), tree_id, &id_commitment_to_replace),
            old_holder_id.clone(),
        ];

        let instruction = Instruction::RegisterReplacing {
            tree_id: *tree_id,
            id_commitment,
            rate_limit,
            subtree_id: sid,
            id_commitment_to_replace,
        };

        let message = Message::try_new(
            setup.registration.id(),
            account_ids,
            vec![payer_nonce],
            instruction,
        )
        .expect("valid message");

        PublicTransaction::new(
            message.clone(),
            WitnessSet::for_message(&message, &[payer_key]),
        )
    }

    fn read_leaf_index(setup: &TestSetup, id_commitment: &[u8; 32]) -> u64 {
        let data = read_membership(&setup.state, &setup.registration, &TREE_ID, id_commitment)
            .expect("membership must exist");
        u64::from_le_bytes(
            data[MEMBERSHIP_OFFSET_LEAF_INDEX..MEMBERSHIP_OFFSET_LEAF_INDEX + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// A full pool (one membership at the cap) plus a second funded party.
    fn setup_with_a_full_pool() -> Option<(TestSetup, [u8; 32], AccountId, PrivateKey)> {
        // Cap at one membership so "full" is one tx away.
        let mut setup = state_with_policy_registration(EXP_RATE_LIMIT, [0u8; 32], 0)?;
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP, 50);

        let incumbent = valid_field_element(0xF0);
        let tx = build_register_tx(&setup, &TREE_ID, incumbent, EXP_RATE_LIMIT, Nonce(0), 0);
        setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("the incumbent should register");

        let (challenger_key, challenger_id) = create_test_keypair(60);
        let payment_def_id = setup.payment_def_id.clone();
        insert_funded_holding(
            &mut setup.state,
            &payment_def_id,
            &challenger_id,
            10_000_000,
        );

        Some((setup, incumbent, challenger_id, challenger_key))
    }

    #[test]
    fn test_replace_lets_a_registrant_in_when_the_pool_is_full() {
        // The reason this instruction exists: at max_total_rate_limit a plain
        // Register has no remedy, and a standalone Erase frees capacity that
        // anyone can take before the erasing party registers.
        let Some((mut setup, incumbent, challenger_id, challenger_key)) = setup_with_a_full_pool()
        else {
            return;
        };
        advance_past_expiry(&mut setup);

        let newcomer = valid_field_element(0xF1);
        let blocked = build_register_tx_parts(
            &setup.registration,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            Nonce(0),
            1,
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&blocked, 2, 0)
                .is_err(),
            "a plain register must still be refused while the pool is full"
        );

        let replacing = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &setup.user_payment_id.clone(),
            Nonce(0),
        );
        setup
            .state
            .transition_from_public_transaction(&replacing, 2, 0)
            .expect("replacing an expired membership must get the newcomer in");

        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &newcomer).is_some(),
            "the newcomer should now hold a membership"
        );
        assert!(
            read_membership(&setup.state, &setup.registration, &TREE_ID, &incumbent).is_none(),
            "the displaced membership should be cleared"
        );
    }

    #[test]
    fn test_replace_reuses_the_displaced_leaf_index() {
        let Some((mut setup, incumbent, challenger_id, challenger_key)) = setup_with_a_full_pool()
        else {
            return;
        };
        let next_index_before = get_tree_next_index(&setup.state, &setup.registration, &TREE_ID);
        advance_past_expiry(&mut setup);

        let newcomer = valid_field_element(0xF2);
        let tx = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &setup.user_payment_id.clone(),
            Nonce(0),
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 2, 0)
            .expect("replace should succeed");

        assert_eq!(
            read_leaf_index(&setup, &newcomer),
            0,
            "the newcomer must take the displaced membership's slot"
        );
        assert_eq!(
            get_tree_next_index(&setup.state, &setup.registration, &TREE_ID),
            next_index_before,
            "reusing a slot must not consume a fresh index"
        );
    }

    #[test]
    fn test_replace_refunds_the_displaced_holder_and_escrows_the_newcomer() {
        let Some((mut setup, incumbent, challenger_id, challenger_key)) = setup_with_a_full_pool()
        else {
            return;
        };
        advance_past_expiry(&mut setup);

        let displaced_holder = setup.user_payment_id.clone();
        let holder_before = get_token_balance(&setup.state, &displaced_holder);
        let challenger_before = get_token_balance(&setup.state, &challenger_id);
        let escrow_before = escrow_balance(&setup);

        let newcomer = valid_field_element(0xF3);
        let tx = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &displaced_holder,
            Nonce(0),
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 2, 0)
            .expect("replace should succeed");

        assert_eq!(
            get_token_balance(&setup.state, &displaced_holder) - holder_before,
            EXP_DEPOSIT,
            "the displaced member must be made whole"
        );
        assert_eq!(
            challenger_before - get_token_balance(&setup.state, &challenger_id),
            EXP_DEPOSIT,
            "the newcomer must be debited their own deposit"
        );
        // Nets flat at equal rate limits — what the threaded pre-state predicts.
        assert_eq!(
            escrow_balance(&setup),
            escrow_before,
            "escrow must end holding the newcomer's deposit in place of the old one"
        );
    }

    #[test]
    fn test_replace_keeps_the_rate_limit_and_registration_totals_straight() {
        let Some((mut setup, incumbent, challenger_id, challenger_key)) = setup_with_a_full_pool()
        else {
            return;
        };
        let total_before = get_total_registrations(&setup.state, &setup.registration, &TREE_ID);
        let rate_before = get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID);
        advance_past_expiry(&mut setup);

        let newcomer = valid_field_element(0xF4);
        let tx = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &setup.user_payment_id.clone(),
            Nonce(0),
        );
        setup
            .state
            .transition_from_public_transaction(&tx, 2, 0)
            .expect("replace should succeed");

        assert_eq!(
            get_current_total_rate_limit(&setup.state, &setup.registration, &TREE_ID),
            rate_before,
            "one slot out, one in, at equal size"
        );
        assert_eq!(
            get_total_registrations(&setup.state, &setup.registration, &TREE_ID),
            total_before,
            "the membership count is unchanged by a replacement"
        );
    }

    #[test]
    fn test_replace_refuses_a_membership_that_has_not_expired() {
        // Must never become a way to evict a live member.
        let Some((mut setup, incumbent, challenger_id, challenger_key)) = setup_with_a_full_pool()
        else {
            return;
        };

        let newcomer = valid_field_element(0xF5);
        let still_active = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &setup.user_payment_id.clone(),
            Nonce(0),
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&still_active, 2, 0)
                .is_err(),
            "an active membership must not be displaceable"
        );

        // Grace is not enough either — only full expiry frees the slot.
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP + DEFAULT_ACTIVE_DURATION as u64 + 1,
            60,
        );
        let in_grace = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &setup.user_payment_id.clone(),
            Nonce(0),
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&in_grace, 3, 0)
                .is_err(),
            "a membership in its grace period must not be displaceable"
        );
    }

    #[test]
    fn test_replace_refuses_to_pay_the_refund_to_a_non_holder() {
        let Some((mut setup, incumbent, challenger_id, challenger_key)) = setup_with_a_full_pool()
        else {
            return;
        };
        advance_past_expiry(&mut setup);

        // A real funded holding that simply did not pay the displaced deposit.
        let newcomer = valid_field_element(0xF6);
        let tx = build_register_replacing_tx(
            &setup,
            &TREE_ID,
            &challenger_id,
            &challenger_key,
            newcomer,
            EXP_RATE_LIMIT,
            incumbent,
            0,
            &setup.treasury_id.clone(),
            Nonce(0),
        );
        assert!(
            setup
                .state
                .transition_from_public_transaction(&tx, 2, 0)
                .is_err(),
            "the refund must follow the displaced membership's own record"
        );
    }
}
