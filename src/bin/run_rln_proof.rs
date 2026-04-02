//! End-to-end RLN proof demonstration.
//!
//! Run repeatedly with `cargo run --bin run_rln_proof` to register new memberships.
//! First run deploys programs and initializes the tree; subsequent runs add members.
//!
//! Build the guest programs first:
//! ```bash
//! cargo risczero build --manifest-path methods/guest/Cargo.toml
//! ```
use nssa::{AccountId, PublicTransaction, ProgramDeploymentTransaction, program::Program, public_transaction::{Message, WitnessSet}, program_deployment_transaction};
use logos_lez_rln::merkle_tree::{
    TREE_DEPTH, SUBTREE_LEAVES,
    get_merkle_proof, proof_to_fr, wait_for_leaf,
};
use logos_lez_rln::rln::{
    CONFIG_OFFSET_TREASURY_ACCOUNT_ID, CONFIG_OFFSET_PRICE_PER_UNIT,
    derive_config_account,
    derive_tree_main_account,
    derive_subtree_account,
    layouts::Instruction,
};
use std::path::PathBuf;
use rln::hashers::poseidon_hash;
use rln::prelude::{hash_to_field_le, seeded_keygen, Fr, RLNWitnessInput, RLN};
use rln::utils::{fr_to_bytes_le, IdSecret};
use std::time::Duration;
use common::transaction::NSSATransaction;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;
use wallet::program_facades::token::Token;

// Program binaries
const REGISTRATION_BINARY: &str = "target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin";
const MERKLE_TREE_BINARY: &str = "target/riscv32im-risc0-zkvm-elf/docker/incremental_merkle_tree.bin";

// Tree configuration
const TREE_ID: [u8; 24] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];

// Setup constants
const PRICE_PER_UNIT: u128 = 10_000;
const TOKEN_SUPPLY: u128 = 1_000_000_000;
const USER_FUNDING: u128 = 100_000_000;
const MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

// RLN proof constants
const USER_MESSAGE_LIMIT: u64 = 100;
const MESSAGE_ID: u64 = 0;
const MESSAGE: &str = "Hello, RLN!";
const EPOCH: &str = "1231028105";
const RLN_IDENTIFIER: &str = "rln/logos-rln-relay/v2.0.0";

#[tokio::main]
async fn main() {
    let mut wallet_core = WalletCore::from_env().unwrap();

    // Load programs
    let registration_bytecode = std::fs::read(REGISTRATION_BINARY)
        .expect("Failed to read registration program binary");
    let registration_program = Program::new(registration_bytecode)
        .expect("Failed to parse registration program");

    let merkle_bytecode = std::fs::read(MERKLE_TREE_BINARY)
        .expect("Failed to read merkle tree program binary");
    let merkle_program = Program::new(merkle_bytecode)
        .expect("Failed to parse merkle tree program");

    println!("=== RLN Proof Demo ===\n");

    // Check if registration is already initialized
    let config_id = derive_config_account(&registration_program.id(), &TREE_ID);
    let is_initialized = wallet_core
        .get_account_public(config_id.clone())
        .await
        .map(|acc| !acc.data.as_ref().is_empty())
        .unwrap_or(false);

    // Get or create funded user
    let user_holding_id: AccountId = if is_initialized {
        println!("Registration already initialized, creating new user...\n");
        create_funded_user(&mut wallet_core, &TREE_ID).await
    } else {
        println!("First run, setting up...\n");
        run_setup(&mut wallet_core, &registration_program, &merkle_program, &TREE_ID).await
    };

    // Step 1: Create identity using zerokit
    println!("Step 1: Creating identity...");
    let (identity_secret, _id_commitment, id_commitment_bytes, leaf_bytes) =
        create_identity(&mut wallet_core, USER_MESSAGE_LIMIT).await;
    println!("  Identity commitment: {}", hex::encode(&id_commitment_bytes));

    // Step 2: Register via the registration program
    println!("\nStep 2: Registering...");
    let leaf_index = register_identity(
        &wallet_core,
        &registration_program,
        &TREE_ID,
        &id_commitment_bytes,
        &user_holding_id,
        USER_MESSAGE_LIMIT,
    ).await;
    println!("  Registered at index: {}", leaf_index);

    // Wait for transaction to be finalized
    let finalized = wait_for_leaf(
        &wallet_core,
        &registration_program,
        &TREE_ID,
        leaf_index,
        &leaf_bytes,
        30,
        Duration::from_millis(500),
    ).await;
    if !finalized {
        panic!("Timeout waiting for leaf to appear on-chain");
    }

    // Step 3: Get the merkle proof from chain
    println!("\nStep 3: Fetching merkle proof...");
    let proof = get_merkle_proof(&wallet_core, &registration_program, &TREE_ID, leaf_index).await;
    let (path_elements, path_indices, root) = proof_to_fr(&proof);

    assert_eq!(leaf_bytes, proof.leaf, "Leaf mismatch - transaction may not be finalized");

    // Step 4: Generate RLN proof
    println!("\nStep 4: Generating RLN proof...");
    let user_message_limit_fr = Fr::from(USER_MESSAGE_LIMIT);
    let message_id_fr = Fr::from(MESSAGE_ID);

    // Compute external nullifier = poseidon(epoch, rln_identifier)
    let epoch_fr = hash_to_field_le(EPOCH.as_bytes()).expect("Failed to hash epoch");
    let rln_identifier_fr = hash_to_field_le(RLN_IDENTIFIER.as_bytes())
        .expect("Failed to hash rln_identifier");
    let external_nullifier = poseidon_hash(&[epoch_fr, rln_identifier_fr])
        .expect("Failed to compute external nullifier");

    // Compute signal hash (x)
    let x = hash_to_field_le(MESSAGE.as_bytes()).expect("Failed to hash message");

    // Create RLN witness input
    let witness = RLNWitnessInput::new(
        identity_secret,
        user_message_limit_fr,
        message_id_fr,
        path_elements.clone(),
        path_indices.clone(),
        x,
        external_nullifier,
    )
    .expect("Failed to create RLN witness");

    // Initialize RLN instance (we use it just for proof generation/verification)
    // The internal tree is not used - we provide our own merkle proof
    let rln = RLN::new(TREE_DEPTH, "").expect("Failed to initialize RLN");

    // Generate the proof
    let (rln_proof, proof_values) = rln
        .generate_rln_proof(&witness)
        .expect("Failed to generate RLN proof");

    println!("  Proof generated successfully!");
    println!("  Nullifier: {}", hex::encode(fr_to_bytes_le(&proof_values.nullifier)));
    println!("  Root in proof: {}", hex::encode(fr_to_bytes_le(&proof_values.root)));

    // Step 5: Verify the RLN proof
    println!("\nStep 5: Verifying RLN proof...");

    let is_valid = rln
        .verify_with_roots(&rln_proof, &proof_values, &x, &[root])
        .expect("Failed to verify proof");

    if is_valid {
        println!("  Proof verified successfully!");
    } else {
        println!("  Proof verification FAILED!");
    }

    // Summary
    println!("\n=== Summary ===");
    println!("Identity inserted at index: {}", leaf_index);
    println!("On-chain root: {}", hex::encode(fr_to_bytes_le(&root)));
    println!("Proof valid: {}", is_valid);
    println!("External nullifier: {}", hex::encode(fr_to_bytes_le(&external_nullifier)));
    println!("Nullifier: {}", hex::encode(fr_to_bytes_le(&proof_values.nullifier)));

    if !is_valid {
        panic!("RLN proof verification failed!");
    }
}

// ============================================================================
// Setup Functions
// ============================================================================

/// Wait for an account to have non-empty data.
async fn wait_for_account_data(wallet_core: &WalletCore, account_id: &AccountId, max_attempts: u32) {
    for _ in 0..max_attempts {
        let account = wallet_core
            .get_account_public(account_id.clone())
            .await
            .expect("Failed to fetch account");
        if !account.data.as_ref().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("Timeout waiting for account {} to be initialized", account_id);
}

/// Get the path to the supply holding file for a given tree_id.
fn get_supply_holding_path(tree_id: &[u8; 24]) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".logos-lez-rln")
        .join(format!("supply_holding_{}.txt", hex::encode(tree_id)))
}

/// Save the supply holding account ID for later reuse.
fn save_supply_holding(tree_id: &[u8; 24], supply_holding_id: &AccountId) {
    let path = get_supply_holding_path(tree_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, supply_holding_id.to_string())
        .expect("Failed to save supply holding ID");
}

/// Load a previously saved supply holding account ID.
fn load_supply_holding(tree_id: &[u8; 24]) -> Option<AccountId> {
    let path = get_supply_holding_path(tree_id);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Check if a program is deployed by checking if an account owned by it exists.
/// Returns true if the account exists and is owned by the expected program.
async fn is_program_deployed(
    wallet_core: &WalletCore,
    program: &Program,
    account_id: &AccountId,
) -> bool {
    match wallet_core.get_account_public(account_id.clone()).await {
        Ok(account) => account.program_owner == program.id(),
        Err(_) => false,
    }
}

/// Deploy a program if not already deployed.
/// Returns true if deployed (either now or previously), false on error.
async fn ensure_program_deployed(
    wallet_core: &WalletCore,
    program: &Program,
    bytecode_path: &str,
    program_name: &str,
    check_account: &AccountId,
) -> bool {
    // Check if already deployed by looking for an account owned by this program
    if is_program_deployed(wallet_core, program, check_account).await {
        println!("  {} already deployed (program ID: {:?})", program_name, program.id());
        return true;
    }

    // Read bytecode and verify it matches the expected program ID
    let bytecode = std::fs::read(bytecode_path)
        .unwrap_or_else(|_| panic!("Failed to read {} binary from {}", program_name, bytecode_path));

    let loaded_program = Program::new(bytecode.clone())
        .unwrap_or_else(|_| panic!("Failed to parse {} binary", program_name));

    if loaded_program.id() != program.id() {
        panic!(
            "{} bytecode mismatch: expected program ID {:?}, got {:?}. \
             The binary at {} doesn't match the expected program.",
            program_name, program.id(), loaded_program.id(), bytecode_path
        );
    }

    // Deploy the program
    let deploy_msg = program_deployment_transaction::Message::new(bytecode);
    let deploy_tx = ProgramDeploymentTransaction::new(deploy_msg);

    match wallet_core.sequencer_client.send_transaction(NSSATransaction::ProgramDeployment(deploy_tx)).await {
        Ok(_) => {
            println!("  {} deployed (program ID: {:?})", program_name, program.id());
            true
        }
        Err(e) => {
            // Check if error indicates program already exists
            let err_str = format!("{:?}", e);
            if err_str.contains("already") || err_str.contains("exists") || err_str.contains("duplicate") {
                println!("  {} already deployed (program ID: {:?})", program_name, program.id());
                true
            } else {
                panic!("Failed to deploy {}: {:?}", program_name, e);
            }
        }
    }
}

/// Deploy a built-in program (bytecode already embedded in the binary).
async fn deploy_builtin_program(
    wallet_core: &WalletCore,
    program: &Program,
    program_name: &str,
) {
    let deploy_msg = program_deployment_transaction::Message::new(program.elf().to_vec());
    let deploy_tx = ProgramDeploymentTransaction::new(deploy_msg);

    match wallet_core.sequencer_client.send_transaction(NSSATransaction::ProgramDeployment(deploy_tx)).await {
        Ok(_) => {
            println!("  {} deployed (program ID: {:?})", program_name, program.id());
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("already") || err_str.contains("exists") || err_str.contains("duplicate") {
                println!("  {} already deployed (program ID: {:?})", program_name, program.id());
            } else {
                panic!("Failed to deploy {}: {:?}", program_name, e);
            }
        }
    }
}

/// Run setup: deploy programs, create token, initialize registration.
/// Returns the user payment holding account ID.
async fn run_setup(
    wallet_core: &mut WalletCore,
    registration_program: &Program,
    merkle_program: &Program,
    tree_id: &[u8; 24],
) -> AccountId {
    // Derive accounts we'll use to check deployment status
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    let tree_main_id = derive_tree_main_account(&registration_program.id(), tree_id);

    // Step 1: Deploy programs (if not already deployed)
    println!("Setup Step 1: Checking/deploying programs...");

    ensure_program_deployed(
        wallet_core,
        merkle_program,
        MERKLE_TREE_BINARY,
        "Merkle tree program",
        &tree_main_id,
    ).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    ensure_program_deployed(
        wallet_core,
        registration_program,
        REGISTRATION_BINARY,
        "Registration program",
        &config_id,
    ).await;

    deploy_builtin_program(wallet_core, &Program::token(), "Token program").await;

    // Step 2: Create accounts
    println!("Setup Step 2: Creating accounts...");
    let (token_definition_id, _) = wallet_core.create_new_account_public(None);
    let (supply_holding_id, _) = wallet_core.create_new_account_public(None);
    let (treasury_id, _) = wallet_core.create_new_account_public(None);
    wallet_core.store_persistent_data().await.expect("Failed to store wallet");

    // Step 3: Deploy payment token
    println!("Setup Step 3: Deploying payment token...");
    Token(wallet_core)
        .send_new_definition(token_definition_id.clone(), supply_holding_id.clone(), "RLNTOK".to_string(), TOKEN_SUPPLY)
        .await
        .expect("Failed to deploy token");
    wait_for_account_data(wallet_core, &supply_holding_id, 30).await;
    println!("  Token deployed: {}", token_definition_id);

    // Step 4: Initialize treasury
    println!("Setup Step 4: Initializing treasury...");
    Token(wallet_core)
        .send_transfer_transaction(supply_holding_id.clone(), treasury_id.clone(), 1)
        .await
        .expect("Failed to initialize treasury");
    wait_for_account_data(wallet_core, &treasury_id, 30).await;

    // Step 5: Initialize registration program
    // All accounts (config, credit_token_def, credit_supply, tree_main) are
    // derived as PDAs by the guest program — the message has 0 accounts.
    println!("Setup Step 5: Initializing registration program...");

    let instruction = Instruction::Initialize {
        registration_program_id: bytemuck::cast(registration_program.id()),
        merkle_program_id: bytemuck::cast(merkle_program.id()),
        tree_id: *tree_id,
        payment_token_id: *token_definition_id.value(),
        price_per_unit: PRICE_PER_UNIT,
        treasury_account_id: *treasury_id.value(),
        token_program_id: bytemuck::cast(Program::token().id()),
        max_total_rate_limit: MAX_TOTAL_RATE_LIMIT,
    };

    let message = Message::try_new(
        registration_program.id(),
        vec![], // All accounts derived as PDAs
        vec![],
        instruction,
    ).expect("Failed to create init message");

    let witness_set = WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    wallet_core.sequencer_client.send_transaction(NSSATransaction::Public(tx)).await.expect("Failed to initialize registration");
    wait_for_account_data(wallet_core, &config_id, 30).await;
    println!("  Registration initialized");

    // Step 6: Save supply holding for future runs
    save_supply_holding(tree_id, &supply_holding_id);
    println!("Setup Step 6: Saved supply holding for future runs");

    // Step 7: Create and fund user account
    println!("Setup Step 7: Creating and funding user account...");
    let (user_payment_holding_id, _) = wallet_core.create_new_account_public(None);
    wallet_core.store_persistent_data().await.expect("Failed to store wallet");

    Token(wallet_core)
        .send_transfer_transaction(supply_holding_id, user_payment_holding_id.clone(), USER_FUNDING)
        .await
        .expect("Failed to fund user");
    wait_for_account_data(wallet_core, &user_payment_holding_id, 30).await;
    println!("  User payment holding: {}", user_payment_holding_id);
    println!("  User funded with {} tokens", USER_FUNDING);

    println!("Setup complete!\n");
    user_payment_holding_id
}

/// Create a new user account and fund it from the saved supply holding.
/// Used for subsequent runs after initial setup.
async fn create_funded_user(
    wallet_core: &mut WalletCore,
    tree_id: &[u8; 24],
) -> AccountId {
    // Load the supply holding from previous setup
    let supply_holding_id = load_supply_holding(tree_id).unwrap_or_else(|| {
        eprintln!("Error: No saved supply holding found for this tree_id.");
        eprintln!("The supply holding file may have been deleted.");
        eprintln!("\nOptions:");
        eprintln!("  1. Use a different --tree-id to start fresh");
        eprintln!("  2. Provide --user-holding with an existing funded account");
        std::process::exit(1);
    });

    println!("  Using saved supply holding: {}", supply_holding_id);

    // Create new user account
    let (user_payment_holding_id, _) = wallet_core.create_new_account_public(None);
    wallet_core.store_persistent_data().await.expect("Failed to store wallet");

    // Fund the new user from supply holding
    println!("  Funding new user account...");
    Token(wallet_core)
        .send_transfer_transaction(supply_holding_id, user_payment_holding_id.clone(), USER_FUNDING)
        .await
        .expect("Failed to fund user. The supply holding may be out of funds.");

    wait_for_account_data(wallet_core, &user_payment_holding_id, 30).await;
    println!("  User payment holding: {}", user_payment_holding_id);
    println!("  User funded with {} tokens\n", USER_FUNDING);

    user_payment_holding_id
}

// ============================================================================
// RLN-Specific Functions
// ============================================================================

/// Create a new RLN identity and compute the rate commitment (leaf value).
///
/// The identity is derived from a wallet account's signing key using zerokit's
/// seeded key generation. The leaf value is `poseidon(id_commitment, user_message_limit)`.
///
/// Returns (identity_secret, id_commitment as Fr, id_commitment as bytes, leaf_bytes).
async fn create_identity(
    wallet_core: &mut WalletCore,
    user_message_limit: u64,
) -> (IdSecret, Fr, [u8; 32], [u8; 32]) {
    // Create a new account to derive identity from
    let (account_id, chain_index) = wallet_core.create_new_account_public(None);
    println!("  Created account: {} at path {}", account_id, chain_index);
    wallet_core
        .store_persistent_data()
        .await
        .expect("Failed to store wallet");

    // Get signing key for the account
    let signing_key = wallet_core
        .storage()
        .user_data
        .get_pub_account_signing_key(account_id.clone())
        .expect("Account should be self-owned public");

    // Derive identity from signing key using zerokit
    let seed = signing_key.value();
    let (mut identity_secret_fr, id_commitment) =
        seeded_keygen(seed).expect("seeded_keygen should succeed");

    // Wrap identity secret in IdSecret type
    let identity_secret = IdSecret::from(&mut identity_secret_fr);

    // Convert id_commitment to bytes (needed for registration)
    let id_commitment_bytes: [u8; 32] = fr_to_bytes_le(&id_commitment).try_into().unwrap();

    // Compute rate_commitment = poseidon(id_commitment, user_message_limit)
    // This is what the registration program will compute on-chain
    let user_message_limit_fr = Fr::from(user_message_limit);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit_fr])
        .expect("Failed to compute rate commitment");

    // Convert to bytes for verification
    let leaf_bytes: [u8; 32] = fr_to_bytes_le(&rate_commitment).try_into().unwrap();

    (identity_secret, id_commitment, id_commitment_bytes, leaf_bytes)
}

// ============================================================================
// Registration Program Functions
// ============================================================================

/// Register an identity via the registration program.
///
/// The registration program validates payment, rate limit, computes the leaf hash
/// (poseidon(id_commitment, rate_limit)), and inserts it into the merkle tree.
/// Payment is handled in the same transaction - user's token holding is debited
/// and treasury is credited.
async fn register_identity(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 24],
    id_commitment: &[u8; 32],
    user_holding_id: &AccountId,
    rate_limit: u64,
) -> u64 {
    let config_account = derive_config_account(&registration_program.id(), tree_id);
    let tree_main_account = derive_tree_main_account(&registration_program.id(), tree_id);

    // Fetch config to get treasury account and payment amount
    let config_data = wallet_core
        .get_account_public(config_account.clone())
        .await
        .expect("Failed to fetch config account. Is the registration initialized?");

    let config_bytes = config_data.data.as_ref();
    let treasury_bytes: [u8; 32] = config_bytes[CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32]
        .try_into()
        .expect("Invalid treasury account ID in config");
    let treasury_account_id = AccountId::new(treasury_bytes);

    let price_per_unit = u128::from_le_bytes(
        config_bytes[CONFIG_OFFSET_PRICE_PER_UNIT..CONFIG_OFFSET_PRICE_PER_UNIT + 16]
            .try_into()
            .unwrap()
    );
    let payment_amount = price_per_unit * (rate_limit as u128);

    // Fetch next_index from tree main account
    let main_account_data = wallet_core
        .get_account_public(tree_main_account.clone())
        .await
        .expect("Failed to fetch tree main account");

    let tree_data = main_account_data.data.as_ref();
    let next_index = u64::from_le_bytes(tree_data[1..9].try_into().unwrap());

    println!("  Payment amount: {} tokens", payment_amount);
    println!("  User holding: {}", user_holding_id);
    println!("  Treasury: {}", treasury_account_id);

    // Derive the single subtree account needed for this insertion
    let subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_account = derive_subtree_account(&registration_program.id(), tree_id, subtree_id);

    let accounts = vec![
        config_account,
        tree_main_account,
        user_holding_id.clone(),
        treasury_account_id,
        subtree_account,
    ];

    // Get user's signing key for authorization
    let signing_key = wallet_core
        .storage()
        .user_data
        .get_pub_account_signing_key(user_holding_id.clone())
        .expect("User holding account not found in wallet - must be owned by this wallet");

    // Get nonce for user's holding account
    let nonces = wallet_core
        .get_accounts_nonces(vec![*user_holding_id])
        .await
        .expect("Failed to fetch account nonces");

    let instruction = Instruction::Register {
        registration_program_id: bytemuck::cast(registration_program.id()),
        id_commitment: *id_commitment,
        rate_limit,
    };

    let message = Message::try_new(
        registration_program.id(),
        accounts,
        nonces,
        instruction,
    )
    .expect("Failed to create message");

    // Sign with user's key to authorize the payment
    let witness_set = WitnessSet::for_message(&message, &[signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .expect("Failed to register identity");

    next_index
}
