//! Shared client functions for interacting with the RLN registration program.
//!
//! Used by both `run_rln_proof` and `bulk_register` binaries.

use nssa::{
    AccountId, ProgramDeploymentTransaction, PublicTransaction,
    program::Program,
    program_deployment_transaction,
    public_transaction::{Message, WitnessSet},
};
use std::path::PathBuf;
use std::time::Duration;
use wallet::WalletCore;
use wallet::program_facades::token::Token;

use crate::merkle_tree::SUBTREE_LEAVES;
use crate::rln::{
    CONFIG_OFFSET_TREASURY_ACCOUNT_ID, derive_config_account, derive_subtree_account,
    derive_tree_main_account, layouts::Instruction,
};

// Setup constants
pub const PRICE_PER_UNIT: u128 = 10_000;
pub const TOKEN_SUPPLY: u128 = 1_000_000_000;
pub const MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

pub const REGISTRATION_BINARY: &str = "target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin";
pub const MERKLE_TREE_BINARY: &str =
    "target/riscv32im-risc0-zkvm-elf/docker/incremental_merkle_tree.bin";
pub const TREE_ID: [u8; 24] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
];
pub const DATA_DIR: &str = ".logos-lez-rln";

/// Initialize a WalletCore, creating storage if it doesn't exist.
///
/// When no storage exists (first run), any stale wallet config is removed so
/// that `WalletCore` generates a fresh default config matching the current
/// wallet crate version.
pub fn init_wallet() -> WalletCore {
    let config_path = wallet::helperfunctions::fetch_config_path().unwrap();
    let storage_path = wallet::helperfunctions::fetch_persistent_storage_path().unwrap();
    if storage_path.exists() {
        WalletCore::new_update_chain(config_path, storage_path, None).unwrap()
    } else {
        if config_path.exists() {
            println!("First run: removing stale wallet config at {config_path:?}");
            std::fs::remove_file(&config_path).ok();
        }
        println!("First run: initializing wallet storage at {storage_path:?}");
        WalletCore::new_init_storage(config_path, storage_path, None, String::new()).unwrap()
    }
}

/// Load registration and merkle programs from default binary paths.
pub fn load_programs() -> (Program, Program) {
    let registration_bytecode =
        std::fs::read(REGISTRATION_BINARY).expect("Failed to read registration program binary");
    let registration_program =
        Program::new(registration_bytecode).expect("Failed to parse registration program");

    let merkle_bytecode =
        std::fs::read(MERKLE_TREE_BINARY).expect("Failed to read merkle tree program binary");
    let merkle_program =
        Program::new(merkle_bytecode).expect("Failed to parse merkle tree program");

    (registration_program, merkle_program)
}

/// Check if the registration program is already initialized on-chain.
pub async fn is_initialized(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 24],
) -> bool {
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    wallet_core
        .get_account_public(config_id)
        .await
        .map(|acc| !acc.data.as_ref().is_empty())
        .unwrap_or(false)
}

/// Wait for an account to have non-empty data.
pub async fn wait_for_account_data(
    wallet_core: &WalletCore,
    account_id: &AccountId,
    max_attempts: u32,
) {
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
    panic!(
        "Timeout waiting for account {} to be initialized",
        account_id
    );
}

/// Get the path to the supply holding file for a given tree_id.
pub fn get_supply_holding_path(tree_id: &[u8; 24]) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(DATA_DIR)
        .join(format!("supply_holding_{}.txt", hex::encode(tree_id)))
}

/// Save the supply holding account ID for later reuse.
pub fn save_supply_holding(tree_id: &[u8; 24], supply_holding_id: &AccountId) {
    let path = get_supply_holding_path(tree_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, supply_holding_id.to_string()).expect("Failed to save supply holding ID");
}

/// Load a previously saved supply holding account ID.
pub fn load_supply_holding(tree_id: &[u8; 24]) -> Option<AccountId> {
    let path = get_supply_holding_path(tree_id);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Get the path to the payment account file for a given tree_id.
pub fn get_payment_account_path(tree_id: &[u8; 24]) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(DATA_DIR)
        .join(format!("payment_account_{}.txt", hex::encode(tree_id)))
}

/// Save the payment account ID for later reuse.
pub fn save_payment_account(tree_id: &[u8; 24], account_id: &AccountId) {
    let path = get_payment_account_path(tree_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, account_id.to_string()).expect("Failed to save payment account ID");
}

/// Load a previously saved payment account ID.
pub fn load_payment_account(tree_id: &[u8; 24]) -> Option<AccountId> {
    let path = get_payment_account_path(tree_id);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Check if a program is deployed by checking if an account owned by it exists.
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
pub async fn ensure_program_deployed(
    wallet_core: &WalletCore,
    program: &Program,
    bytecode_path: &str,
    program_name: &str,
    check_account: &AccountId,
) {
    if is_program_deployed(wallet_core, program, check_account).await {
        println!(
            "  {} already deployed (program ID: {:?})",
            program_name,
            program.id()
        );
        return;
    }

    let bytecode = std::fs::read(bytecode_path).unwrap_or_else(|_| {
        panic!(
            "Failed to read {} binary from {}",
            program_name, bytecode_path
        )
    });

    let loaded_program = Program::new(bytecode.clone())
        .unwrap_or_else(|_| panic!("Failed to parse {} binary", program_name));

    if loaded_program.id() != program.id() {
        panic!(
            "{} bytecode mismatch: expected program ID {:?}, got {:?}. \
             The binary at {} doesn't match the expected program.",
            program_name,
            program.id(),
            loaded_program.id(),
            bytecode_path
        );
    }

    let deploy_msg = program_deployment_transaction::Message::new(bytecode);
    let deploy_tx = ProgramDeploymentTransaction::new(deploy_msg);

    match wallet_core
        .sequencer_client
        .send_tx_program(deploy_tx)
        .await
    {
        Ok(_) => {
            println!(
                "  {} deployed (program ID: {:?})",
                program_name,
                program.id()
            );
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("already")
                || err_str.contains("exists")
                || err_str.contains("duplicate")
            {
                println!(
                    "  {} already deployed (program ID: {:?})",
                    program_name,
                    program.id()
                );
            } else {
                panic!("Failed to deploy {}: {:?}", program_name, e);
            }
        }
    }
}

/// Deploy a built-in program (bytecode already embedded in the binary).
pub async fn deploy_builtin_program(
    wallet_core: &WalletCore,
    program: &Program,
    program_name: &str,
) {
    let deploy_msg = program_deployment_transaction::Message::new(program.elf().to_vec());
    let deploy_tx = ProgramDeploymentTransaction::new(deploy_msg);

    match wallet_core
        .sequencer_client
        .send_tx_program(deploy_tx)
        .await
    {
        Ok(_) => println!(
            "  {} deployed (program ID: {:?})",
            program_name,
            program.id()
        ),
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("already")
                || err_str.contains("exists")
                || err_str.contains("duplicate")
            {
                println!(
                    "  {} already deployed (program ID: {:?})",
                    program_name,
                    program.id()
                );
            } else {
                panic!("Failed to deploy {}: {:?}", program_name, e);
            }
        }
    }
}

/// Run full setup: deploy programs, create token, initialize registration.
/// Returns the user payment holding account ID.
pub async fn run_setup(
    wallet_core: &mut WalletCore,
    registration_program: &Program,
    merkle_program: &Program,
    tree_id: &[u8; 24],
    user_funding: u128,
) -> AccountId {
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    let tree_main_id = derive_tree_main_account(&registration_program.id(), tree_id);

    println!("Setup Step 1: Checking/deploying programs...");

    ensure_program_deployed(
        wallet_core,
        merkle_program,
        MERKLE_TREE_BINARY,
        "Merkle tree program",
        &tree_main_id,
    )
    .await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    ensure_program_deployed(
        wallet_core,
        registration_program,
        REGISTRATION_BINARY,
        "Registration program",
        &config_id,
    )
    .await;

    deploy_builtin_program(wallet_core, &Program::token(), "Token program").await;

    println!("Setup Step 2: Creating accounts...");
    let (token_definition_id, _) = wallet_core.create_new_account_public(None);
    let (supply_holding_id, _) = wallet_core.create_new_account_public(None);
    let (treasury_id, _) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .await
        .expect("Failed to store wallet");

    println!("Setup Step 3: Deploying payment token...");
    Token(wallet_core)
        .send_new_definition(
            token_definition_id.clone(),
            supply_holding_id.clone(),
            "RLNTOK".to_string(),
            TOKEN_SUPPLY,
        )
        .await
        .expect("Failed to deploy token");
    wait_for_account_data(wallet_core, &supply_holding_id, 30).await;
    println!("  Token deployed: {}", token_definition_id);

    println!("Setup Step 4: Initializing treasury...");
    Token(wallet_core)
        .send_transfer_transaction(supply_holding_id.clone(), treasury_id.clone(), 1)
        .await
        .expect("Failed to initialize treasury");
    wait_for_account_data(wallet_core, &treasury_id, 30).await;

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

    let message = Message::try_new(registration_program.id(), vec![], vec![], instruction)
        .expect("Failed to create init message");

    let witness_set = WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    wallet_core
        .sequencer_client
        .send_tx_public(tx)
        .await
        .expect("Failed to initialize registration");
    wait_for_account_data(wallet_core, &config_id, 30).await;
    println!("  Registration initialized");

    save_supply_holding(tree_id, &supply_holding_id);
    println!("Setup Step 6: Saved supply holding for future runs");

    println!("Setup Step 7: Creating and funding user account...");
    let (user_payment_holding_id, _) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .await
        .expect("Failed to store wallet");

    Token(wallet_core)
        .send_transfer_transaction(
            supply_holding_id,
            user_payment_holding_id.clone(),
            user_funding,
        )
        .await
        .expect("Failed to fund user");
    wait_for_account_data(wallet_core, &user_payment_holding_id, 30).await;
    println!("  User payment holding: {}", user_payment_holding_id);
    println!("  User funded with {} tokens", user_funding);

    println!("Setup complete!\n");
    user_payment_holding_id
}

/// Create a new user account and fund it from the saved supply holding.
pub async fn create_funded_user(
    wallet_core: &mut WalletCore,
    tree_id: &[u8; 24],
    user_funding: u128,
) -> AccountId {
    let supply_holding_id = load_supply_holding(tree_id).unwrap_or_else(|| {
        eprintln!("Error: No saved supply holding found for this tree_id.");
        eprintln!("Run setup first or check that the supply holding file exists.");
        std::process::exit(1);
    });

    println!("  Using saved supply holding: {}", supply_holding_id);

    let (user_payment_holding_id, _) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .await
        .expect("Failed to store wallet");

    println!("  Funding new user account...");
    Token(wallet_core)
        .send_transfer_transaction(
            supply_holding_id,
            user_payment_holding_id.clone(),
            user_funding,
        )
        .await
        .expect("Failed to fund user. The supply holding may be out of funds.");

    wait_for_account_data(wallet_core, &user_payment_holding_id, 30).await;
    println!("  User payment holding: {}", user_payment_holding_id);
    println!("  User funded with {} tokens\n", user_funding);

    user_payment_holding_id
}

/// Register an identity via the registration program.
/// Returns the leaf index assigned to this registration.
///
/// If `nonce_override` is `Some`, uses that nonce instead of fetching from chain.
/// This is useful for bulk registration where transactions are sent faster than
/// the sequencer processes them.
pub async fn register_identity(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 24],
    id_commitment: &[u8; 32],
    user_holding_id: &AccountId,
    rate_limit: u64,
    nonce_override: Option<u128>,
) -> u64 {
    let config_account = derive_config_account(&registration_program.id(), tree_id);
    let tree_main_account = derive_tree_main_account(&registration_program.id(), tree_id);

    let config_data = wallet_core
        .get_account_public(config_account.clone())
        .await
        .expect("Failed to fetch config account. Is the registration initialized?");

    let config_bytes = config_data.data.as_ref();
    let treasury_bytes: [u8; 32] = config_bytes
        [CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32]
        .try_into()
        .expect("Invalid treasury account ID in config");
    let treasury_account_id = AccountId::new(treasury_bytes);

    let main_account_data = wallet_core
        .get_account_public(tree_main_account.clone())
        .await
        .expect("Failed to fetch tree main account");

    let tree_data = main_account_data.data.as_ref();
    let next_index = u64::from_le_bytes(tree_data[1..9].try_into().unwrap());

    let subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_account = derive_subtree_account(&registration_program.id(), tree_id, subtree_id);

    let accounts = vec![
        config_account,
        tree_main_account,
        user_holding_id.clone(),
        treasury_account_id,
        subtree_account,
    ];

    let signing_key = wallet_core
        .storage()
        .user_data
        .get_pub_account_signing_key(user_holding_id.clone())
        .expect("User holding account not found in wallet");

    let nonces = match nonce_override {
        Some(nonce) => vec![nonce],
        None => wallet_core
            .get_accounts_nonces(vec![*user_holding_id])
            .await
            .expect("Failed to fetch account nonces"),
    };

    let instruction = Instruction::Register {
        registration_program_id: bytemuck::cast(registration_program.id()),
        id_commitment: *id_commitment,
        rate_limit,
    };

    let message = Message::try_new(registration_program.id(), accounts, nonces, instruction)
        .expect("Failed to create message");

    let witness_set = WitnessSet::for_message(&message, &[signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    wallet_core
        .sequencer_client
        .send_tx_public(tx)
        .await
        .expect("Failed to register identity");

    next_index
}
