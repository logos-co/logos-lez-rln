//! Client helpers for the RLN registration program (shared by `run_rln_proof`,
//! `bulk_register`, and `run_setup`).

use std::{path::PathBuf, time::Duration};

use common::transaction::LeeTransaction as NSSATransaction;
use nssa::{
    AccountId, ProgramDeploymentTransaction, PublicTransaction,
    program::Program,
    program_deployment_transaction,
    public_transaction::{Message, WitnessSet},
};
use rln::{
    hashers::poseidon_hash,
    prelude::{Fr, seeded_keygen},
    utils::{IdSecret, fr_to_bytes_le},
};
use sequencer_service_rpc::RpcClient as _;
use wallet::{WalletCore, program_facades::token::Token};

use crate::{
    merkle_tree::SUBTREE_LEAVES,
    rln::{
        CONFIG_OFFSET_FAUCET_CLAIM_CAP, CONFIG_OFFSET_TREASURY_ACCOUNT_ID, Instruction,
        derive_config_account, derive_payment_supply_account, derive_payment_token_account,
        derive_subtree_account, derive_tree_main_account,
    },
};

pub const PRICE_PER_UNIT: u128 = 10_000;
/// 100 B RLNTOK minted per tree deploy. At PRICE_PER_UNIT=10_000 and the
/// demo's rateLimit=100, each registration burns 1 M tokens, so this supply
/// funds roughly 100K registrations across the tree's lifetime before
/// depletion forces a fresh deploy.
pub const TOKEN_SUPPLY: u128 = 100_000_000_000;
pub const MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

/// Default per-call faucet claim cap for faucet-funded deployments: 10 M
/// tokens = 10 registrations at the demo rate. Per-call only (repeat claims
/// are unbounded by design — test tokens).
pub const DEFAULT_FAUCET_CLAIM_CAP: u128 = 10_000_000;

/// How a deployment's payment token gets funded. The claim cap only exists
/// in faucet mode; on-chain, wallet-key deployments carry cap 0 (faucet
/// disabled) — derived at the `Initialize` build site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FundingPolicy {
    /// Payment token definition is a registration-program PDA; anyone claims
    /// up to `claim_cap` per `ClaimTokens` call — no human mint authority
    /// exists (default).
    Faucet { claim_cap: u128 },
    /// Legacy model: wallet-keypair definition, fixed pre-minted supply,
    /// funding via transfers (and the definition key can mint).
    WalletKey,
}

/// Deployment-time policy knobs (resolved once from env by `policy_from_env`).
pub struct DeployPolicy {
    pub funding: FundingPolicy,
    /// `None` = no free-quota registrar (zeros on the wire).
    pub authorized_registrar: Option<[u8; 32]>,
    pub free_quota: u64,
}

/// Env knobs: `LEZ_RLN_FUNDING` = `faucet` (default) | `wallet-key`,
/// `LEZ_RLN_FAUCET_CLAIM_CAP`, `LEZ_RLN_REGISTRAR` (64-hex account id),
/// `LEZ_RLN_FREE_QUOTA`.
pub fn policy_from_env() -> DeployPolicy {
    let funding = match std::env::var("LEZ_RLN_FUNDING").as_deref() {
        Err(_) | Ok("faucet") => {
            let claim_cap = match std::env::var("LEZ_RLN_FAUCET_CLAIM_CAP") {
                Err(_) => DEFAULT_FAUCET_CLAIM_CAP,
                Ok(s) => s.trim().parse().unwrap_or_else(|e| {
                    eprintln!("LEZ_RLN_FAUCET_CLAIM_CAP is not a valid u128: {e}");
                    std::process::exit(2);
                }),
            };
            FundingPolicy::Faucet { claim_cap }
        }
        Ok("wallet-key") => FundingPolicy::WalletKey,
        Ok(other) => {
            eprintln!("LEZ_RLN_FUNDING must be 'faucet' or 'wallet-key', got '{other}'");
            std::process::exit(2);
        }
    };
    let authorized_registrar = match std::env::var("LEZ_RLN_REGISTRAR") {
        Err(_) => None,
        Ok(s) => {
            let bytes = hex::decode(s.trim()).unwrap_or_else(|e| {
                eprintln!("LEZ_RLN_REGISTRAR is not valid hex: {e}");
                std::process::exit(2);
            });
            Some(bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
                eprintln!("LEZ_RLN_REGISTRAR must decode to 32 bytes, got {}", v.len());
                std::process::exit(2);
            }))
        }
    };
    let free_quota = match std::env::var("LEZ_RLN_FREE_QUOTA") {
        Err(_) => 0,
        Ok(s) => s.trim().parse().unwrap_or_else(|e| {
            eprintln!("LEZ_RLN_FREE_QUOTA is not a valid u64: {e}");
            std::process::exit(2);
        }),
    };
    DeployPolicy {
        funding,
        authorized_registrar,
        free_quota,
    }
}

/// 30 days, in seconds.
pub const DEFAULT_ACTIVE_DURATION_SECS: u32 = 30 * 24 * 60 * 60;

/// 7 days, in seconds.
pub const DEFAULT_GRACE_PERIOD_DURATION_SECS: u32 = 7 * 24 * 60 * 60;

/// CLOCK_50 system account id.
pub fn clock_account_id() -> AccountId {
    AccountId::new(crate::rln::CLOCK_50_ACCOUNT_ID_BYTES)
}

pub const REGISTRATION_BINARY: &str =
    "methods/guest/target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin";
pub const MERKLE_TREE_BINARY: &str =
    "methods/guest/target/riscv32im-risc0-zkvm-elf/docker/incremental_merkle_tree.bin";
pub const DATA_DIR: &str = ".logos-lez-rln";

/// Initialize a WalletCore, creating storage if missing.
///
/// An existing `wallet_config.json` is preserved (lets callers point the
/// wallet at a non-default sequencer, e.g. the public LEZ testnet); with
/// none present, a fresh local-dev default is written.
pub fn init_wallet() -> WalletCore {
    let config_path = wallet::helperfunctions::fetch_config_path().unwrap();
    let storage_path = wallet::helperfunctions::fetch_persistent_storage_path().unwrap();
    if storage_path.exists() {
        WalletCore::new_update_chain(config_path, storage_path, None).unwrap()
    } else {
        println!("First run: initializing wallet storage at {storage_path:?}");
        WalletCore::new_init_storage(config_path, storage_path, None, "")
            .unwrap()
            .0
    }
}

/// Load registration and merkle programs from default binary paths.
pub fn load_programs() -> (Program, Program) {
    let registration_bytecode =
        std::fs::read(REGISTRATION_BINARY).expect("Failed to read registration program binary");
    let registration_program =
        Program::new(registration_bytecode.into()).expect("Failed to parse registration program");

    let merkle_bytecode =
        std::fs::read(MERKLE_TREE_BINARY).expect("Failed to read merkle tree program binary");
    let merkle_program =
        Program::new(merkle_bytecode.into()).expect("Failed to parse merkle tree program");

    (registration_program, merkle_program)
}

/// Check if the registration program is already initialized on-chain.
pub async fn is_initialized(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
) -> bool {
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    let account = wallet_core
        .get_account_public(config_id)
        .await
        .expect("Failed to fetch config account from sequencer");
    !account.data.as_ref().is_empty()
}

/// Sleep long enough for the sequencer to seal a block, between back-to-back
/// program deployments. Two ~500 KiB ELFs in one block exceed the bedrock
/// inscription cap (~896 KiB = MAX_BLOCK_SIZE * 7/8) and panic the sequencer.
/// Default 90 s covers both local dev (~15 s blocks) and testnet (~60 s);
/// override via `LEZ_RLN_BLOCK_SEAL_SECS`.
pub async fn wait_for_block_seal() {
    let secs = std::env::var("LEZ_RLN_BLOCK_SEAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// Default `max_attempts` for `wait_for_account_data`. Each attempt sleeps
/// 500 ms, so 360 → 180 s — covers a testnet block cycle plus margin.
/// Override via `LEZ_RLN_ACCOUNT_WAIT_ATTEMPTS`.
pub fn wait_account_attempts() -> u32 {
    std::env::var("LEZ_RLN_ACCOUNT_WAIT_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(360)
}

/// RLN tree id, read from `LEZ_RLN_TREE_ID_HEX` (32 bytes, 64 hex chars).
/// Strict: aborts with an actionable error if unset or malformed. Kept out
/// of source to prevent the drift class where a deployment bump in this
/// file silently desyncs from shell scripts that key persistent caches
/// off the hex form (see project_tree_id_drift memory note).
pub fn tree_id_from_env() -> [u8; 32] {
    let hex = std::env::var("LEZ_RLN_TREE_ID_HEX").unwrap_or_else(|_| {
        eprintln!(
            "LEZ_RLN_TREE_ID_HEX not set (expected 64 hex chars).\n\
             Example: LEZ_RLN_TREE_ID_HEX=000102030405060708090a0b0c0d0e0f\
             1011121314151617a0cba6e85ca1e26e cargo run --bin run_setup"
        );
        std::process::exit(2);
    });
    let bytes = hex::decode(&hex).unwrap_or_else(|e| {
        eprintln!("LEZ_RLN_TREE_ID_HEX is not valid hex: {e}");
        std::process::exit(2);
    });
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!(
            "LEZ_RLN_TREE_ID_HEX must decode to exactly 32 bytes, got {}",
            v.len()
        );
        std::process::exit(2);
    })
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

/// Path to a per-tree account file, named `<prefix>_<tree_id>.txt`.
fn account_file_path(tree_id: &[u8; 32], prefix: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(DATA_DIR)
        .join(format!("{}_{}.txt", prefix, hex::encode(tree_id)))
}

/// Persist an account ID to its per-tree file for later reuse.
fn save_account_file(tree_id: &[u8; 32], prefix: &str, account_id: &AccountId) {
    let path = account_file_path(tree_id, prefix);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, account_id.to_string())
        .unwrap_or_else(|_| panic!("Failed to save {} ID", prefix));
}

/// Load a previously saved account ID from its per-tree file.
fn load_account_file(tree_id: &[u8; 32], prefix: &str) -> Option<AccountId> {
    std::fs::read_to_string(account_file_path(tree_id, prefix))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Get the path to the supply holding file for a given tree_id.
pub fn get_supply_holding_path(tree_id: &[u8; 32]) -> PathBuf {
    account_file_path(tree_id, "supply_holding")
}

/// Save the supply holding account ID for later reuse.
pub fn save_supply_holding(tree_id: &[u8; 32], supply_holding_id: &AccountId) {
    save_account_file(tree_id, "supply_holding", supply_holding_id);
}

/// Load a previously saved supply holding account ID.
pub fn load_supply_holding(tree_id: &[u8; 32]) -> Option<AccountId> {
    load_account_file(tree_id, "supply_holding")
}

/// Get the path to the payment account file for a given tree_id.
pub fn get_payment_account_path(tree_id: &[u8; 32]) -> PathBuf {
    account_file_path(tree_id, "payment_account")
}

/// Save the payment account ID for later reuse.
pub fn save_payment_account(tree_id: &[u8; 32], account_id: &AccountId) {
    save_account_file(tree_id, "payment_account", account_id);
}

/// Load a previously saved payment account ID.
pub fn load_payment_account(tree_id: &[u8; 32]) -> Option<AccountId> {
    load_account_file(tree_id, "payment_account")
}

/// Compute the membership leaf: rate_commitment = poseidon(id_commitment, rate_limit).
/// Single source of truth for the leaf value shared by identity creation and
/// CSV-driven bulk registration.
pub fn rate_commitment_from_fr(id_commitment_fr: &Fr, rate_limit: u64) -> [u8; 32] {
    let rate_commitment = poseidon_hash(&[*id_commitment_fr, Fr::from(rate_limit)]);
    fr_to_bytes_le(&rate_commitment).try_into().unwrap()
}

/// Outputs of `create_identity`: the RLN identity plus the on-chain leaf (rate commitment).
pub struct RlnIdentity {
    pub identity_secret: IdSecret,
    pub id_commitment_fr: Fr,
    pub id_commitment_bytes: [u8; 32],
    pub leaf_bytes: [u8; 32],
    pub id_secret_hash_hex: String,
}

/// Create a new wallet account, derive an RLN identity from its signing key, and
/// compute the rate commitment (leaf value = poseidon(id_commitment, rate_limit)).
pub async fn create_identity(wallet_core: &mut WalletCore, user_message_limit: u64) -> RlnIdentity {
    let (account_id, _chain_index) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .expect("Failed to store wallet");

    let signing_key = wallet_core
        .get_account_public_signing_key(account_id)
        .expect("Account should be self-owned public");

    let seed = signing_key.value();
    let (mut identity_secret_fr, id_commitment_fr) = seeded_keygen(seed);

    let id_secret_hash_bytes = fr_to_bytes_le(&identity_secret_fr);
    let id_secret_hash_hex: String = id_secret_hash_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let identity_secret = IdSecret::from(&mut identity_secret_fr);
    let id_commitment_bytes: [u8; 32] = fr_to_bytes_le(&id_commitment_fr).try_into().unwrap();

    let leaf_bytes = rate_commitment_from_fr(&id_commitment_fr, user_message_limit);

    RlnIdentity {
        identity_secret,
        id_commitment_fr,
        id_commitment_bytes,
        leaf_bytes,
        id_secret_hash_hex,
    }
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

/// Send a program-deployment transaction, treating "already deployed" sequencer
/// errors as success (idempotent deploy).
async fn send_deploy_tx(
    wallet_core: &WalletCore,
    program: &Program,
    program_name: &str,
    bytecode: Vec<u8>,
) {
    let deploy_msg = program_deployment_transaction::Message::new(bytecode);
    let deploy_tx = ProgramDeploymentTransaction::new(deploy_msg);

    match wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::ProgramDeployment(deploy_tx))
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

    let loaded_program = Program::new(bytecode.clone().into())
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

    send_deploy_tx(wallet_core, program, program_name, bytecode).await;
}

/// Deploy a built-in program (bytecode already embedded in the binary).
pub async fn deploy_builtin_program(
    wallet_core: &WalletCore,
    program: &Program,
    program_name: &str,
) {
    send_deploy_tx(wallet_core, program, program_name, program.elf().to_vec()).await;
}

/// Build, submit, and await one registration-program init transaction.
/// All init txs share this shape: PDA-only accounts, empty nonces, no
/// signing keys. Blocks until `wait_on` has on-chain data.
async fn send_init_tx(
    wallet_core: &WalletCore,
    registration_program: &Program,
    accounts: Vec<AccountId>,
    instruction: Instruction,
    label: &str,
    wait_on: &AccountId,
) {
    let msg = Message::try_new(registration_program.id(), accounts, vec![], instruction)
        .unwrap_or_else(|e| panic!("Failed to create {label} message: {e:?}"));
    let witness = WitnessSet::for_message(&msg, &[]);
    let tx = PublicTransaction::new(msg, witness);
    let hash = wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"));
    println!("  {label} tx hash: {hash}");
    wait_for_account_data(wallet_core, wait_on, wait_account_attempts()).await;
}

/// Run full setup: deploy programs, create token, initialize registration.
/// Returns the user payment holding account ID.
pub async fn run_setup(
    wallet_core: &mut WalletCore,
    registration_program: &Program,
    merkle_program: &Program,
    tree_id: &[u8; 32],
    user_funding: u128,
    policy: &DeployPolicy,
) -> AccountId {
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    let tree_main_id = derive_tree_main_account(&registration_program.id(), tree_id);
    let credit_token_id =
        crate::rln::derive_credit_token_account(&registration_program.id(), tree_id);
    let credit_supply_id =
        crate::rln::derive_credit_supply_account(&registration_program.id(), tree_id);

    println!("Setup Step 1: Checking/deploying programs...");

    ensure_program_deployed(
        wallet_core,
        merkle_program,
        MERKLE_TREE_BINARY,
        "Merkle tree program",
        &tree_main_id,
    )
    .await;

    wait_for_block_seal().await;

    ensure_program_deployed(
        wallet_core,
        registration_program,
        REGISTRATION_BINARY,
        "Registration program",
        &config_id,
    )
    .await;

    wait_for_block_seal().await;

    deploy_builtin_program(wallet_core, &programs::token(), "Token program").await;

    wait_for_block_seal().await;

    println!("Setup Step 2: Creating accounts...");
    let (treasury_id, _) = wallet_core.create_new_account_public(None);

    // Funding-mode split: wallet-key mints a fixed supply into a
    // wallet-owned definition (the legacy model); faucet defers token
    // creation to the program's own `payment` PDA (Step 5b) so no human
    // ever holds the mint key.
    let payment_token_id: [u8; 32] = match policy.funding {
        FundingPolicy::WalletKey => {
            let (token_definition_id, _) = wallet_core.create_new_account_public(None);
            let (supply_holding_id, _) = wallet_core.create_new_account_public(None);
            wallet_core
                .store_persistent_data()
                .expect("Failed to store wallet");

            println!("Setup Step 3: Deploying payment token (wallet-key funding)...");
            Token(wallet_core)
                .send_new_definition(
                    wallet::AccountIdentity::Public(token_definition_id.clone()),
                    wallet::AccountIdentity::Public(supply_holding_id.clone()),
                    "RLNTOK".to_string(),
                    TOKEN_SUPPLY,
                )
                .await
                .expect("Failed to deploy token");
            wait_for_account_data(wallet_core, &supply_holding_id, wait_account_attempts()).await;
            println!("  Token deployed: {}", token_definition_id);

            println!("Setup Step 4: Initializing treasury...");
            Token(wallet_core)
                .send_transfer_transaction(
                    wallet::AccountIdentity::Public(supply_holding_id.clone()),
                    wallet::AccountIdentity::Public(treasury_id.clone()),
                    1,
                )
                .await
                .expect("Failed to initialize treasury");
            wait_for_account_data(wallet_core, &treasury_id, wait_account_attempts()).await;

            // Saved before Step 7: `create_funded_user`'s wallet-key path
            // funds the user from this sidecar file (`load_supply_holding`).
            save_supply_holding(tree_id, &supply_holding_id);
            *token_definition_id.value()
        }
        FundingPolicy::Faucet { .. } => {
            wallet_core
                .store_persistent_data()
                .expect("Failed to store wallet");
            let payment_def = derive_payment_token_account(&registration_program.id(), tree_id);
            println!(
                "Setup Step 3-4: Faucet funding — payment token will be the program PDA {payment_def} (created in Step 5b; treasury seeded by claim)"
            );
            *payment_def.value()
        }
    };

    println!("Setup Step 5: Initializing registration program...");
    // Split across 3 txs: a fused Initialize+token+merkle blows the 32M
    // per-session cycle cap when all chained calls execute inline.
    send_init_tx(
        wallet_core,
        registration_program,
        vec![config_id.clone(), credit_token_id.clone()],
        Instruction::Initialize {
            merkle_program_id: bytemuck::cast(merkle_program.id()),
            tree_id: *tree_id,
            payment_token_id,
            price_per_unit: PRICE_PER_UNIT,
            treasury_account_id: *treasury_id.value(),
            token_program_id: bytemuck::cast(programs::token().id()),
            max_total_rate_limit: MAX_TOTAL_RATE_LIMIT,
            active_duration_for_new_memberships: DEFAULT_ACTIVE_DURATION_SECS,
            grace_period_duration_for_new_memberships: DEFAULT_GRACE_PERIOD_DURATION_SECS,
            authorized_registrar: policy.authorized_registrar.unwrap_or([0u8; 32]),
            free_quota: policy.free_quota,
            faucet_claim_cap: match policy.funding {
                FundingPolicy::Faucet { claim_cap } => claim_cap,
                FundingPolicy::WalletKey => 0,
            },
        },
        "InitializeConfig",
        &config_id,
    )
    .await;

    send_init_tx(
        wallet_core,
        registration_program,
        vec![credit_token_id.clone(), credit_supply_id.clone()],
        Instruction::InitializeCreditToken {
            token_program_id: bytemuck::cast(programs::token().id()),
            tree_id: *tree_id,
        },
        "InitializeCreditToken",
        &credit_supply_id,
    )
    .await;

    send_init_tx(
        wallet_core,
        registration_program,
        vec![tree_main_id.clone()],
        Instruction::InitializeMerkleTree {
            merkle_program_id: bytemuck::cast(merkle_program.id()),
            tree_id: *tree_id,
        },
        "InitializeMerkleTree",
        &tree_main_id,
    )
    .await;
    println!("  Registration initialized");

    if matches!(policy.funding, FundingPolicy::Faucet { .. }) {
        // 4th init tx (32M-cycle split discipline): create RLNTOK as the
        // program's own PDA definition — mirror of InitializeCreditToken.
        println!("Setup Step 5b: Creating payment token (program-owned PDA)...");
        let payment_def_id = derive_payment_token_account(&registration_program.id(), tree_id);
        let payment_supply_id = derive_payment_supply_account(&registration_program.id(), tree_id);
        send_init_tx(
            wallet_core,
            registration_program,
            vec![payment_def_id.clone(), payment_supply_id.clone()],
            Instruction::InitializePaymentToken {
                token_program_id: bytemuck::cast(programs::token().id()),
                tree_id: *tree_id,
            },
            "InitializePaymentToken",
            &payment_def_id,
        )
        .await;

        // Treasury must be an initialized holding of the payment token so
        // the paid register path's chained Transfer can credit it.
        println!("Setup Step 5c: Seeding treasury via faucet claim...");
        claim_payment_tokens(wallet_core, registration_program, tree_id, &treasury_id, 1).await;
        wait_for_account_data(wallet_core, &treasury_id, wait_account_attempts()).await;

        // The faucet token's supply holder is the (empty) program PDA; saved
        // so downstream tooling records a supply pointer for this tree.
        save_supply_holding(tree_id, &payment_supply_id);
    }
    println!("Setup Step 6: Saved supply holding for future runs");

    // Single funding path: the config just initialized above is what
    // `create_funded_user` reads its mode from (on-chain faucet_claim_cap ==
    // the policy's claim cap here), and both arms saved the supply pointer
    // its wallet-key fallback loads.
    println!("Setup Step 7: Creating and funding user account...");
    let user_payment_holding_id =
        create_funded_user(wallet_core, registration_program, tree_id, user_funding).await;

    println!("Setup complete!\n");
    user_payment_holding_id
}

/// Submit a faucet `ClaimTokens` minting `amount` payment tokens into `dest`.
/// `dest` signs (its key must be in the wallet — fresh holdings are claimed
/// `Claim::Authorized` by the token program). Faucet deployments only: the
/// guest rejects claims when `faucet_claim_cap` is 0 or `amount` exceeds it.
pub async fn claim_payment_tokens(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
    dest: &AccountId,
    amount: u128,
) {
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    let payment_def_id = derive_payment_token_account(&registration_program.id(), tree_id);
    let instruction_data = Program::serialize_instruction(Instruction::ClaimTokens {
        tree_id: *tree_id,
        amount,
    })
    .expect("serialize ClaimTokens");
    let hash = wallet_core
        .send_pub_tx(
            vec![
                wallet::AccountIdentity::PublicNoSign(config_id),
                wallet::AccountIdentity::PublicNoSign(payment_def_id),
                wallet::AccountIdentity::Public(dest.clone()),
            ],
            instruction_data,
            registration_program.id(),
        )
        .await
        .expect("Failed to send ClaimTokens");
    println!("  ClaimTokens tx hash: {hash}");
}

/// Create a new user account and fund it, mode-aware: on faucet deployments
/// (config `faucet_claim_cap > 0`) the funding is claimed from the faucet
/// (clamped to the cap); otherwise it is transferred from the saved supply
/// holding (wallet-key deployments).
pub async fn create_funded_user(
    wallet_core: &mut WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
    user_funding: u128,
) -> AccountId {
    let (user_payment_holding_id, _) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .expect("Failed to store wallet");

    let faucet_cap = fetch_faucet_claim_cap(wallet_core, registration_program, tree_id).await;
    if faucet_cap > 0 {
        let amount = user_funding.min(faucet_cap);
        println!("  Claiming {} tokens from the faucet...", amount);
        claim_payment_tokens(
            wallet_core,
            registration_program,
            tree_id,
            &user_payment_holding_id,
            amount,
        )
        .await;
        wait_for_account_data(
            wallet_core,
            &user_payment_holding_id,
            wait_account_attempts(),
        )
        .await;
        println!("  User payment holding: {}", user_payment_holding_id);
        println!("  User funded with {} tokens\n", amount);
        return user_payment_holding_id;
    }

    let supply_holding_id = load_supply_holding(tree_id).unwrap_or_else(|| {
        eprintln!("Error: No saved supply holding found for this tree_id.");
        eprintln!("Run setup first or check that the supply holding file exists.");
        std::process::exit(1);
    });

    println!("  Using saved supply holding: {}", supply_holding_id);

    println!("  Funding new user account...");
    Token(wallet_core)
        .send_transfer_transaction(
            wallet::AccountIdentity::Public(supply_holding_id),
            wallet::AccountIdentity::Public(user_payment_holding_id.clone()),
            user_funding,
        )
        .await
        .expect("Failed to fund user. The supply holding may be out of funds.");

    wait_for_account_data(
        wallet_core,
        &user_payment_holding_id,
        wait_account_attempts(),
    )
    .await;
    println!("  User payment holding: {}", user_payment_holding_id);
    println!("  User funded with {} tokens\n", user_funding);

    user_payment_holding_id
}

/// Read the deployment's `faucet_claim_cap` from the on-chain config
/// (offset-based; 0 for wallet-key deployments and for pre-policy configs
/// whose ConfigState predates the field).
async fn fetch_faucet_claim_cap(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
) -> u128 {
    let config_id = derive_config_account(&registration_program.id(), tree_id);
    // The sequencer returns absent accounts as Ok with empty data, so Err
    // here is a transport failure — defaulting to 0 would misroute a faucet
    // deployment onto the wallet-key supply-transfer path.
    let account = wallet_core
        .get_account_public(config_id)
        .await
        .expect("Failed to fetch config account (sequencer unreachable?)");
    let data = account.data.as_ref();
    if data.len() < CONFIG_OFFSET_FAUCET_CLAIM_CAP + 16 {
        return 0;
    }
    u128::from_le_bytes(
        data[CONFIG_OFFSET_FAUCET_CLAIM_CAP..CONFIG_OFFSET_FAUCET_CLAIM_CAP + 16]
            .try_into()
            .expect("16-byte slice"),
    )
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
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    user_holding_id: &AccountId,
    rate_limit: u64,
    nonce_override: Option<nssa_core::account::Nonce>,
) -> u64 {
    rln::utils::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

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

    let membership_account =
        crate::rln::derive_membership_account(&registration_program.id(), tree_id, id_commitment);
    let accounts = vec![
        config_account,
        tree_main_account,
        user_holding_id.clone(),
        treasury_account_id,
        subtree_account,
        clock_account_id(),
        membership_account,
    ];

    let signing_key = wallet_core
        .get_account_public_signing_key(user_holding_id.clone())
        .expect("User holding account not found in wallet");

    let nonces = match nonce_override {
        Some(nonce) => vec![nonce],
        None => wallet_core
            .get_accounts_nonces(vec![*user_holding_id])
            .await
            .expect("Failed to fetch account nonces"),
    };

    let instruction = Instruction::Register {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        subtree_id,
    };

    let message = Message::try_new(registration_program.id(), accounts, nonces, instruction)
        .expect("Failed to create message");

    let witness_set = WitnessSet::for_message(&message, &[signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .expect("Failed to register identity");

    next_index
}

/// Renew a membership that is currently inside its grace period. The
/// `fee_payer_id` pays the tx fee; any funded account may call this.
pub async fn extend_membership(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    fee_payer_id: &AccountId,
) {
    rln::utils::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let config_account = derive_config_account(&registration_program.id(), tree_id);
    let membership_account =
        crate::rln::derive_membership_account(&registration_program.id(), tree_id, id_commitment);

    let accounts = vec![config_account, membership_account, clock_account_id()];

    let signing_key = wallet_core
        .get_account_public_signing_key(fee_payer_id.clone())
        .expect("Fee payer account not found in wallet");

    let nonces = wallet_core
        .get_accounts_nonces(vec![*fee_payer_id])
        .await
        .expect("Failed to fetch account nonces");

    let instruction = Instruction::Extend {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
    };

    let message = Message::try_new(registration_program.id(), accounts, nonces, instruction)
        .expect("Failed to create extend message");

    let witness_set = WitnessSet::for_message(&message, &[signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .expect("Failed to extend membership");
}

/// Erase an expired membership. Any funded account can call this; callers
/// pre-grace-period or mid-grace-period are rejected by the guest.
pub async fn erase_membership(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    leaf_index: u64,
    fee_payer_id: &AccountId,
) {
    rln::utils::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let config_account = derive_config_account(&registration_program.id(), tree_id);
    let tree_main_account = derive_tree_main_account(&registration_program.id(), tree_id);
    let membership_account =
        crate::rln::derive_membership_account(&registration_program.id(), tree_id, id_commitment);
    let subtree_id = (leaf_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_account = derive_subtree_account(&registration_program.id(), tree_id, subtree_id);

    let accounts = vec![
        config_account,
        tree_main_account,
        membership_account,
        subtree_account,
        clock_account_id(),
    ];

    let signing_key = wallet_core
        .get_account_public_signing_key(fee_payer_id.clone())
        .expect("Fee payer account not found in wallet");

    let nonces = wallet_core
        .get_accounts_nonces(vec![*fee_payer_id])
        .await
        .expect("Failed to fetch account nonces");

    let instruction = Instruction::Erase {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        subtree_id,
    };

    let message = Message::try_new(registration_program.id(), accounts, nonces, instruction)
        .expect("Failed to create erase message");

    let witness_set = WitnessSet::for_message(&message, &[signing_key]);
    let tx = PublicTransaction::new(message, witness_set);

    wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .expect("Failed to erase membership");
}
