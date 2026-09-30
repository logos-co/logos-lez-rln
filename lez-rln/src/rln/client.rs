//! Client helpers for the RLN registration program (shared by `run_rln_proof`,
//! `bulk_register`, and `run_setup`).

use std::{path::PathBuf, time::Duration};

use nssa::{AccountId, program::Program};
use nssa_core::{
    account::Account,
    program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramId},
};
use program_loader_core::{MAX_SEGMENT_DATA_LEN, ProgramHeader, ProgramSegment};
use rand_chacha::ChaCha20Rng;
use rln::prelude::{Fr, Hasher, IdentityKeys, PoseidonHash, SecretFr};
use sequencer_service_protocol::FeeStateQuote;
use wallet::{AccountIdentity, WalletCore};

use crate::{
    fr_bytes::fr_to_bytes_le,
    merkle_tree::SUBTREE_LEAVES,
    rln::{
        CONFIG_OFFSET_TREASURY_ACCOUNT_ID, Instruction, derive_config_account,
        derive_subtree_account, derive_tree_main_account,
    },
};

/// Native atomic units charged per unit of rate limit. Kept from the token
/// era as a pure re-denomination: at rate_limit 100 a membership costs
/// 1,000,000, which is the anti-grief price `Extend` needs to stay non-zero.
pub const PRICE_PER_UNIT: u128 = 10_000;
pub const MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

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
pub async fn init_wallet() -> WalletCore {
    let config_path = wallet::helperfunctions::fetch_config_path().unwrap();
    let storage_path = wallet::helperfunctions::fetch_persistent_storage_path().unwrap();
    let statistics_path = wallet::helperfunctions::fetch_statistics_path().unwrap();
    if storage_path.exists() {
        WalletCore::new_update_chain(config_path, storage_path, statistics_path, None)
            .await
            .unwrap()
    } else {
        println!("First run: initializing wallet storage at {storage_path:?}");
        WalletCore::new_init_storage(config_path, storage_path, statistics_path, None, "")
            .await
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
    let config_id = derive_config_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
    );
    let account = wallet_core
        .get_account_public(config_id)
        .await
        .expect("Failed to fetch config account from sequencer");
    !account.data.as_ref().is_empty()
}

/// Sleep long enough for the sequencer to seal a block, between back-to-back
/// program deployments: a block is capped at `max_block_size`, and a deploy
/// that does not fit the remainder is deferred with no client feedback.
/// Default 90 s covers local dev (~15 s blocks) and testnet (~60 s); override
/// via `LEZ_RLN_BLOCK_SEAL_SECS`.
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
/// Strict: aborts with an actionable error if unset or malformed. Kept out of
/// source because shell scripts key persistent caches off the hex form, and a
/// bump here would silently desync them.
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
            .get_account_public(*account_id)
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

/// Path to the file recording which account this tree's registrations pay from.
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
    let rate_commitment =
        Hasher::<PoseidonHash>::hash_pair(*id_commitment_fr, Fr::from(rate_limit));
    fr_to_bytes_le(&rate_commitment)
}

/// Outputs of `create_identity`: the RLN identity plus the on-chain leaf (rate commitment).
pub struct RlnIdentity {
    pub identity_secret: SecretFr,
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
    let identity_keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed);
    let identity_secret = identity_keys.identity_secret();
    let id_commitment_fr = identity_keys.id_commitment();

    // Deliberate secret leak: this hex is the IDENTITY_SECRET_HASH recovery path.
    let id_secret_hash_bytes = fr_to_bytes_le(&identity_secret);
    let id_secret_hash_hex: String = id_secret_hash_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let id_commitment_bytes = fr_to_bytes_le(&id_commitment_fr);

    let leaf_bytes = rate_commitment_from_fr(&id_commitment_fr, user_message_limit);

    RlnIdentity {
        identity_secret,
        id_commitment_fr,
        id_commitment_bytes,
        leaf_bytes,
        id_secret_hash_hex,
    }
}

/// The account a deployed program lives at.
///
/// v0.2.5 lets whoever deploys a program choose its address, and the stock
/// wallet facade takes a freshly generated one. We deliberately keep the
/// address v0.2.2 derived from the image id instead, because everything
/// downstream assumes a program is content-addressed: PDA derivation,
/// `derive_accounts`, the `deployment.json` cross-check in `provision.sh` and
/// the module's own reads all recompute it from the bytecode rather than
/// carrying it as state. Letting it float would mean threading a new address
/// through every one of them for no gain.
///
/// `program_loader` permits this. `CreateHeader` and `WriteSegment` require
/// only that their target still be an unclaimed account, never that it be
/// signed for, so a keyless `PublicNoSign` identity can land the header at an
/// address nobody holds a key to. The conversion between the two id types is
/// the byte-preserving reinterpretation LEZ documents, so this is exactly the
/// address v0.2.2 used.
///
/// The cost of that same permissiveness: the address is a pure function of our
/// bytecode and anyone may claim it first, with bytecode of their own, since
/// `CreateHeader` checks only that the target is unclaimed. A squatted address
/// cannot be vacated and cannot be moved without changing the bytecode, so on a
/// fresh chain deploy before publishing the image id.
fn header_account(program: &Program) -> AccountId {
    AccountId::from(program.id())
}

/// Where segment `index` of `program`'s bytecode chain lives.
///
/// Derived rather than generated, so a re-run lands on the same accounts and
/// an interrupted deploy can be told apart from a fresh one. The "segment"
/// label keeps these clear of the program's own PDAs, which derive from their
/// own labels.
fn segment_account(program: &Program, index: u32) -> AccountId {
    let seed = crate::spel_seeds::combine_seeds(&[
        &crate::spel_seeds::label_seed("segment"),
        &crate::spel_seeds::u32_seed(index),
    ]);
    AccountId::for_public_pda(&header_account(program), &PdaSeed::new(seed))
}

/// The funded account that pays for deployment and initialization.
///
/// Every account a deploy touches is freshly claimed and holds nothing, so
/// self-pay has nothing to draw on. v0.2.5 charges real fees and no program
/// can mint native, so this has to name an account funded at genesis, over
/// the bridge, or by a transfer from something already funded.
fn fee_payer() -> Option<AccountId> {
    std::env::var("LEZ_RLN_PAYER").ok().map(|raw| {
        raw.parse::<AccountId>()
            .unwrap_or_else(|e| panic!("LEZ_RLN_PAYER is not an account id: {e}"))
    })
}

/// The execution gas a transaction declares.
///
/// The wallet's own send path bakes in 2,000,000, which is under half what a
/// registration costs: a merkle insert is one Poseidon compression — about
/// 902,000 cycles — per level of tree depth, and gas is cycles. Anything that
/// registers has to declare its own limit, so it builds the transaction itself
/// rather than going through `send_pub_tx_paid_by`. Program deploys and the
/// two init transactions still go through it, so they declare 2,000,000
/// whatever `LEZ_RLN_GAS_LIMIT` says.
///
/// Defaults to the protocol's own ceiling. Declaring more than
/// `fee_core::market::MAX_GAS_EXEC` is not merely wasteful — the sequencer
/// refuses such a transaction outright, and it can never be included in any
/// block, so this is a ceiling rather than a preference.
fn declared_gas_limit() -> u64 {
    const MAX_GAS_EXEC: u64 = 10_000_000;
    let limit = std::env::var("LEZ_RLN_GAS_LIMIT")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(MAX_GAS_EXEC);
    assert!(
        limit <= MAX_GAS_EXEC,
        "LEZ_RLN_GAS_LIMIT {limit} exceeds MAX_GAS_EXEC {MAX_GAS_EXEC}; \
         a transaction declaring more can never be included in a block"
    );
    limit
}

/// Send a public transaction that declares its own gas limit, signed by
/// `signer` and paid for by the configured payer.
///
/// This is `send_pub_tx_paid_by` with the one thing it does not expose: the
/// gas limit. Everything it was doing for us comes back by hand — the signer's
/// nonce, the payer's nonce appended after it, and both signatures over the
/// message hash.
///
/// Only accounts that sign carry a nonce. The rest of an instruction's account
/// list is program-derived, and PDAs have no nonce to advance.
///
/// `max_fee` is the declared cap, normally the `fee_reserve` the caller
/// checked the payer against: the chain refuses a cap below its reserve, so
/// the two must come from the same quote.
async fn send_metered_tx(
    wallet_core: &WalletCore,
    program_account: AccountId,
    accounts: Vec<AccountId>,
    signer: &AccountId,
    instruction_data: nssa_core::program::InstructionData,
    max_fee: u128,
    label: &str,
) -> common::HashType {
    let payer =
        fee_payer().unwrap_or_else(|| panic!("{label} needs a funded payer — set LEZ_RLN_PAYER"));

    let signer_key = wallet_core
        .get_account_public_signing_key(*signer)
        .unwrap_or_else(|| panic!("{label}: signer {signer:?} not in wallet"));

    // Since registration pays its price and its fee from ONE native balance,
    // signer == payer is the normal case, not an oddity. Listing that account
    // twice would take two nonces and two signatures for it, and
    // apply_state_diff advances a nonce once per entry — so the account's
    // nonce jumps by two and the NEXT transaction fails its nonce check, with
    // an error that reads like a sequencer fault. The stock wallet dedupes the
    // same way (`Some(payer) if acc_manager.signs_for(payer)`).
    let payer_is_signer = payer == *signer;
    let payer_key = (!payer_is_signer).then(|| {
        wallet_core
            .get_account_public_signing_key(payer)
            .unwrap_or_else(|| panic!("{label}: payer {payer:?} not in wallet"))
    });

    let nonce_accounts: Vec<AccountId> = if payer_is_signer {
        vec![*signer]
    } else {
        vec![*signer, payer]
    };
    let nonces = wallet_core
        .get_accounts_nonces(&nonce_accounts)
        .await
        .unwrap_or_else(|e| panic!("{label}: failed to read nonces: {e:?}"));

    let fee = nssa::FeeDeclaration::new(payer, declared_gas_limit(), 0, max_fee);
    let message = nssa::public_transaction::Message::new_preserialized(
        program_account,
        accounts,
        nonces,
        instruction_data,
        Some(fee),
    );

    let hash = message.hash();
    let mut witnesses = vec![(
        nssa::Signature::new(signer_key, &hash),
        nssa::PublicKey::new_from_private_key(signer_key),
    )];
    if let Some(payer_key) = payer_key.as_ref() {
        witnesses.push((
            nssa::Signature::new(payer_key, &hash),
            nssa::PublicKey::new_from_private_key(payer_key),
        ));
    }
    let witness = nssa::public_transaction::WitnessSet::from_raw_parts(witnesses);

    use sequencer_service_rpc::RpcClient as _;
    wallet_core
        .helm_owned()
        .send_transaction(common::transaction::LeeTransaction::Public(
            nssa::PublicTransaction::new(message, witness),
        ))
        .await
        .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"))
}

/// The serialized-size allowance the wallet sizes its `max_fee` against
/// (`ASSUMED_DATA_BYTES` in the LEZ wallet). A Register tx is a few hundred
/// bytes, so this over-reserves storage gas — by ~1% of the whole reserve.
const ASSUMED_DATA_BYTES: u128 = 100_000;

/// Headroom over the quoted ceiling for the base fee rising between the
/// balance check and the block the transaction lands in.
///
/// The quote's `next_*_ceiling` already bounds the NEXT block (a full one
/// raises the base fee by at most one step, 8 -> 9 on devnet). x2 is six more
/// full-block steps of +12.5% (1.125^6 ~ 2.03), the same margin
/// logos-rln-module's `ensure.rs` reserves. Over-reserving costs nothing but a
/// larger funding target — the reserve is refunded down to the actual fee —
/// while under-reserving gets the transaction refused at admission.
const BASE_FEE_HEADROOM: u128 = 2;

/// The fee cap declared, and the reserve required, when no fee quote can be
/// had: the wallet's own sizing, `(gas_limit + ASSUMED_DATA_BYTES) x
/// ASSUMED_BASE_FEE (64)`, at the protocol's gas ceiling — ~646M. It is what
/// every register and extend declared before the quote.
const DECLARED_MAX_FEE: u128 = (10_000_000 + ASSUMED_DATA_BYTES) * 64;

/// Where a reserve came from, so a refusal can say what it was sized against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReserveBasis {
    /// Computed from the sequencer's quote at this height.
    Quote(u64),
    Fallback,
}

impl std::fmt::Display for ReserveBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveBasis::Quote(height) => write!(f, "getFeeState at height {height}"),
            ReserveBasis::Fallback => write!(f, "fixed fallback, no fee quote"),
        }
    }
}

/// The fee a metered tx reserves, over and above anything it pays a program.
///
/// A tx's `max_fee` is only a cap: the chain checks `max_fee >= reserve` and
/// `balance >= reserve`, then debits `gas_limit x base_fee_exec + data_bytes x
/// base_fee_stor + tip` at the including block's fee state, refunded down to
/// the actual fee. So the payer has to hold that reserve, not the cap — ~182M
/// at devnet's base fee 8 (ceiling 9) against the old cap's 646M — and the
/// same figure serves as the cap, since it clears the reserve by construction.
fn fee_reserve_from(quote: &FeeStateQuote, gas_limit: u64) -> u128 {
    u128::from(gas_limit)
        .saturating_mul(u128::from(quote.next_base_fee_exec_ceiling))
        .saturating_add(
            ASSUMED_DATA_BYTES.saturating_mul(u128::from(quote.next_base_fee_stor_ceiling)),
        )
        .saturating_mul(BASE_FEE_HEADROOM)
}

/// The reserve from the sequencer's live quote, or `DECLARED_MAX_FEE`.
fn fee_reserve<E>(quote: Result<FeeStateQuote, E>, gas_limit: u64) -> (u128, ReserveBasis) {
    match quote {
        Ok(quote) => (
            fee_reserve_from(&quote, gas_limit),
            ReserveBasis::Quote(quote.height),
        ),
        Err(_) => (DECLARED_MAX_FEE, ReserveBasis::Fallback),
    }
}

/// Quote the reserve for one transaction. The caller uses the one figure for
/// both the affordability check and the declared `max_fee`, so the two cannot
/// disagree about the fee state they were sized against.
async fn quoted_fee_reserve(wallet_core: &WalletCore, label: &str) -> (u128, ReserveBasis) {
    use sequencer_service_rpc::RpcClient as _;
    let quote = wallet_core.helm_owned().get_fee_state().await;
    if let Err(e) = &quote {
        eprintln!("{label}: getFeeState failed ({e}); reserving the fixed {DECLARED_MAX_FEE}");
    }
    fee_reserve(quote, declared_gas_limit())
}

/// Whether `program`'s header is on-chain, judged from the header account.
///
/// The header is written after every segment, so a loader-owned header naming
/// this image id means the whole deploy landed. Anything else non-default at
/// that address is a claim `CreateHeader` can never overwrite.
fn header_deployed(header: &Account, program_id: &ProgramId) -> Result<bool, String> {
    if *header == Account::default() {
        return Ok(false);
    }
    let decoded = (header.program_owner == PROGRAM_LOADER_ACCOUNT_ID)
        .then(|| ProgramHeader::from_bytes(header.data.as_ref()))
        .flatten();
    match decoded {
        Some(decoded) if decoded.image_id == *program_id => Ok(true),
        Some(decoded) => Err(format!("holds a header for image {:?}", decoded.image_id)),
        None => Err("holds something other than a program header".to_string()),
    }
}

/// Which segments of a deploy still have to be written, by index.
///
/// A segment already holding exactly what this deploy would write is left
/// alone: `WriteSegment` requires a default target, so rewriting it fails
/// on-chain and is still charged its full gas limit. A segment holding
/// anything else cannot be rewritten, and a header over it would hash a
/// different image.
fn segments_to_write(
    on_chain: &[Account],
    expected: &[ProgramSegment],
) -> Result<Vec<usize>, String> {
    assert_eq!(on_chain.len(), expected.len(), "one account per segment");
    let mut missing = Vec::new();
    for (index, (account, segment)) in on_chain.iter().zip(expected).enumerate() {
        if *account == Account::default() {
            missing.push(index);
        } else if !segment_matches(account, segment) {
            return Err(format!(
                "segment {index} holds something other than this bytecode"
            ));
        }
    }
    Ok(missing)
}

/// Whether `account` is a loader-owned segment holding exactly `segment`.
fn segment_matches(account: &Account, segment: &ProgramSegment) -> bool {
    account.program_owner == PROGRAM_LOADER_ACCOUNT_ID
        && ProgramSegment::from_bytes(account.data.as_ref()).as_ref() == Some(segment)
}

/// Read a public account, panicking with `label` on a transport error.
async fn read_account(wallet_core: &WalletCore, account_id: &AccountId, label: &str) -> Account {
    wallet_core
        .get_account_public(*account_id)
        .await
        .unwrap_or_else(|e| panic!("{label}: cannot read {account_id}: {e:?}"))
}

/// Wait for tx `hash` to take effect on `account_id`, and fail loudly if it
/// never does.
///
/// `send_pub_tx_paid_by` returning `Ok` means only that the sequencer admitted
/// the transaction. One that then fails on-chain is still included — charged
/// and reverted — so there is no error to catch; the only sign is that its
/// target never changes. The sequencer has no receipt or status RPC, so this
/// watches both the account and `getTransaction`: once the transaction is in a
/// block and `landed` still does not hold, it has failed.
async fn confirm_effect(
    wallet_core: &WalletCore,
    hash: common::HashType,
    account_id: &AccountId,
    landed: impl Fn(&Account) -> bool,
    label: &str,
) {
    let attempts = wait_account_attempts();
    for _ in 0..attempts {
        if landed(&read_account(wallet_core, account_id, label).await) {
            return;
        }
        if let Ok(Some((_, block))) = wallet_core.get_transaction(hash).await {
            // Re-read: the account may have been read before the block landed.
            if landed(&read_account(wallet_core, account_id, label).await) {
                return;
            }
            panic!(
                "{label}: tx {hash} was accepted and included in block {block} but had no \
                 effect on {account_id} — it failed on-chain, and its fee (up to the full \
                 {} gas it declared) was charged to the payer",
                wallet::DEFAULT_GAS_LIMIT
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "{label}: tx {hash} was accepted but after {} s is neither in a block nor has any \
         effect on {account_id}; if it lands and fails, its fee (up to the full {} gas it \
         declared) is still charged to the payer",
        attempts / 2,
        wallet::DEFAULT_GAS_LIMIT
    );
}

/// Upload the `missing` segments of a chain, then point a header at it.
///
/// Segments link tail-to-head, so they upload in reverse: a segment's
/// `next_segment` has to be on-chain before the segment naming it is written.
async fn send_deploy_tx(
    wallet_core: &WalletCore,
    program: &Program,
    program_name: &str,
    segments: &[AccountId],
    expected: &[ProgramSegment],
    missing: &[usize],
) {
    let header = header_account(program);
    let payer = fee_payer();

    for &index in missing.iter().rev() {
        let segment = &expected[index];
        let instruction = program_loader_core::Instruction::WriteSegment {
            bytecode: segment.bytecode.clone(),
            next_segment: segment.next_segment,
        };
        let data = Program::serialize_instruction(instruction).expect("instruction serializes");
        let mut accounts = vec![AccountIdentity::PublicNoSign(segments[index])];
        accounts.extend(segment.next_segment.map(AccountIdentity::PublicNoSign));
        let label = format!("{program_name} segment {index}");
        let hash = wallet_core
            .send_pub_tx_paid_by(accounts, data, PROGRAM_LOADER_ACCOUNT_ID, payer)
            .await
            .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"));
        // Each write has to land before the next is built, for two reasons: a
        // segment naming this one as `next_segment` requires it to already be
        // on-chain, and the payer's nonce only advances once a transaction
        // settles — building the next one against a stale nonce fails the fee
        // check rather than the instruction, which reads as a fee problem
        // when it is really a pacing one.
        confirm_effect(
            wallet_core,
            hash,
            &segments[index],
            |account| segment_matches(account, segment),
            &label,
        )
        .await;
        println!("  {label} written");
    }

    let instruction = program_loader_core::Instruction::CreateHeader {
        first_segment: segments[0],
        immutable: true,
    };
    let data = Program::serialize_instruction(instruction).expect("instruction serializes");
    let mut accounts = vec![AccountIdentity::PublicNoSign(header)];
    accounts.extend(segments.iter().copied().map(AccountIdentity::PublicNoSign));
    let label = format!("{program_name} header");
    let hash = wallet_core
        .send_pub_tx_paid_by(accounts, data, PROGRAM_LOADER_ACCOUNT_ID, payer)
        .await
        .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"));
    let program_id = program.id();
    confirm_effect(
        wallet_core,
        hash,
        &header,
        |account| header_deployed(account, &program_id) == Ok(true),
        &label,
    )
    .await;
    println!("  {program_name} deployed at {header:?}");
}

/// Deploy a program unless its header is already on-chain, resuming an
/// interrupted deploy from the segments that already landed. Returns whether
/// any deploy transaction was sent.
pub async fn ensure_program_deployed(
    wallet_core: &WalletCore,
    program: &Program,
    bytecode_path: &str,
    program_name: &str,
) -> bool {
    // An override for when the caller vouches that the image id is already
    // on-chain; the header read below detects that on its own. If the program
    // is NOT actually deployed, the init chained calls fail loudly instead.
    if std::env::var_os("LEZ_RLN_SKIP_PROGRAM_DEPLOY").is_some() {
        println!(
            "  {} deploy skipped (LEZ_RLN_SKIP_PROGRAM_DEPLOY; assumed on-chain, ID: {:?})",
            program_name,
            program.id()
        );
        return false;
    }

    // Keyed on the program's own content-addressed header, not on a tree's
    // accounts: those are empty for every fresh tree_id, and re-deploying over
    // a live program fails on-chain while still being charged in full.
    let header = header_account(program);
    let header_state = read_account(wallet_core, &header, program_name).await;
    match header_deployed(&header_state, &program.id()) {
        Ok(true) => {
            println!(
                "  {} already deployed (program ID: {:?})",
                program_name,
                program.id()
            );
            return false;
        }
        Ok(false) => {}
        Err(what) => panic!("{program_name}: header account {header} {what}"),
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

    let chunks: Vec<&[u8]> = bytecode.chunks(MAX_SEGMENT_DATA_LEN).collect();
    let segments: Vec<AccountId> = (0..chunks.len())
        .map(|i| segment_account(program, u32::try_from(i).expect("segment count fits u32")))
        .collect();
    let expected: Vec<ProgramSegment> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| ProgramSegment {
            bytecode: chunk.to_vec(),
            next_segment: segments.get(index + 1).copied(),
        })
        .collect();
    let mut on_chain = Vec::with_capacity(segments.len());
    for segment in &segments {
        on_chain.push(read_account(wallet_core, segment, program_name).await);
    }
    let missing = segments_to_write(&on_chain, &expected)
        .unwrap_or_else(|what| panic!("{program_name}: {what}"));
    if missing.len() < segments.len() {
        println!(
            "  {program_name}: resuming, {} of {} segments already on-chain",
            segments.len() - missing.len(),
            segments.len()
        );
    }

    send_deploy_tx(
        wallet_core,
        program,
        program_name,
        &segments,
        &expected,
        &missing,
    )
    .await;
    true
}

/// Confirm a built-in program is on-chain.
///
/// v0.2.5 seeds the builtins at genesis, each at the address its image id maps
/// to, so there is nothing to deploy. Trying anyway uploads a whole segment
/// chain to accounts nobody will read and then trips `program_loader`'s
/// "header target already deployed" assertion, which looks like a failure and
/// is really just wasted work.
pub async fn require_builtin_program(
    wallet_core: &WalletCore,
    program: &Program,
    program_name: &str,
) {
    let header = header_account(program);
    match wallet_core.get_account_public(header).await {
        Ok(account) if !account.data.as_ref().is_empty() => {
            println!("  {program_name} present at {header:?}");
        }
        _ => panic!(
            "{program_name} is not on-chain at {header:?} — builtins are seeded at genesis, \
             so this chain's genesis does not match the binaries this host was built against"
        ),
    }
}

/// Build, submit, and confirm one registration-program init transaction.
/// All init txs share this shape: PDA-only accounts, empty nonces, no
/// signing keys. Blocks until `wait_on` holds data owned by `owner`, and
/// fails loudly if the tx lands without that effect.
async fn send_init_tx(
    wallet_core: &WalletCore,
    registration_program: &Program,
    accounts: Vec<AccountId>,
    instruction: Instruction,
    label: &str,
    wait_on: &AccountId,
    owner: AccountId,
) {
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    let hash = wallet_core
        .send_pub_tx_paid_by(
            accounts
                .into_iter()
                .map(AccountIdentity::PublicNoSign)
                .collect(),
            instruction_data,
            crate::spel_seeds::program_account(&registration_program.id()),
            fee_payer(),
        )
        .await
        .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"));
    println!("  {label} tx hash: {hash}");
    confirm_effect(
        wallet_core,
        hash,
        wait_on,
        |account| account.program_owner == owner && !account.data.as_ref().is_empty(),
        label,
    )
    .await;
}

/// Deploy both programs, create the treasury, and initialize the registry.
/// Returns the account registrations pay from.
pub async fn run_setup(
    wallet_core: &mut WalletCore,
    registration_program: &Program,
    merkle_program: &Program,
    tree_id: &[u8; 32],
) -> AccountId {
    let program_account = crate::spel_seeds::program_account(&registration_program.id());
    let config_id = derive_config_account(&program_account, tree_id);
    let tree_main_id = derive_tree_main_account(&program_account, tree_id);

    println!("Setup Step 1: Checking/deploying programs...");

    if ensure_program_deployed(
        wallet_core,
        merkle_program,
        MERKLE_TREE_BINARY,
        "Merkle tree program",
    )
    .await
    {
        wait_for_block_seal().await;
    }

    if ensure_program_deployed(
        wallet_core,
        registration_program,
        REGISTRATION_BINARY,
        "Registration program",
    )
    .await
    {
        wait_for_block_seal().await;
    }

    // The treasury is a plain public account, deliberately not a PDA: a PDA is
    // spendable only through a chained call carrying its seeds, issued by its
    // owning program, and this program has no instruction that would issue
    // one. It needs no initialization either — a native credit lands on an
    // account that has never been written to, and leaves it unowned. That is
    // also why nothing can squat the funds: ownership gates DATA writes, while
    // a balance decrease is gated separately on the account's own
    // authorization.
    println!("Setup Step 2: Creating the treasury account...");
    let (treasury_id, _) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .expect("Failed to store wallet");
    println!("  Treasury: {treasury_id}");

    println!("Setup Step 3: Initializing registration program...");
    // Two transactions rather than one: a fused Initialize+merkle exceeds the
    // execution-gas cap once the chained call runs inline.
    send_init_tx(
        wallet_core,
        registration_program,
        vec![config_id],
        Instruction::Initialize {
            merkle_program_id: bytemuck::cast(merkle_program.id()),
            tree_id: *tree_id,
            price_per_unit: PRICE_PER_UNIT,
            treasury_account_id: *treasury_id.value(),
            max_total_rate_limit: MAX_TOTAL_RATE_LIMIT,
            active_duration_for_new_memberships_sec: DEFAULT_ACTIVE_DURATION_SECS,
            grace_period_duration_for_new_memberships_sec: DEFAULT_GRACE_PERIOD_DURATION_SECS,
        },
        "InitializeConfig",
        &config_id,
        program_account,
    )
    .await;

    send_init_tx(
        wallet_core,
        registration_program,
        vec![config_id, tree_main_id],
        Instruction::InitializeMerkleTree { tree_id: *tree_id },
        "InitializeMerkleTree",
        &tree_main_id,
        // The chained call hands `main`'s seed to the merkle program, which
        // claims it — so the tree's main account is the merkle program's.
        header_account(merkle_program),
    )
    .await;
    println!("  Registration initialized");

    let payer = resolve_payer();
    save_payment_account(tree_id, &payer);
    println!("Setup complete! Registrations pay from {payer}\n");
    payer
}

/// An account id as either 64 hex chars or base58.
///
/// `AccountId`'s own FromStr is base58 only, but the registry module publishes
/// its payer as hex — `wallet_status` answers `{"payer":"<64 hex>"}` because
/// that is what every other id on its wire is. Accepting one spelling would
/// mean the caller that most needs these binaries cannot use them, and the
/// error for the wrong one ("invalid base58: InvalidBase58Character") does not
/// suggest the fix. Hex is tried only at exactly 64 characters, so a base58 id
/// is never silently reinterpreted as bytes.
pub fn parse_account_id(raw: &str) -> Result<AccountId, String> {
    let raw = raw.trim();
    if raw.len() == 64
        && let Ok(bytes) = hex::decode(raw)
        && let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(AccountId::new(id));
    }
    raw.parse()
        .map_err(|e| format!("neither 64-hex nor base58: {e}"))
}

/// The account that signs a registration and pays for it.
///
/// One account now does three jobs that used to take two: it signs the
/// `Register` transaction, pays the registry price out of its native balance,
/// and pays the transaction fee. There is nothing to create and nothing to
/// mint here — no program can mint native balance, so this account must
/// already have been funded at genesis (`dev.sh`'s `LEZ_RLN_GENESIS_FUND`),
/// over the bridge, or by a transfer from something already funded.
pub fn resolve_payer() -> AccountId {
    fee_payer().unwrap_or_else(|| {
        eprintln!(
            "LEZ_RLN_PAYER must name a funded account: a registration pays its \
             price and its fee from one native balance, and no program can mint native."
        );
        std::process::exit(2);
    })
}

/// Refuse a payer that cannot cover the registry price AND the fee reserve,
/// and return that reserve for the transaction to declare as its `max_fee`.
///
/// The fee dwarfs the price by two orders of magnitude — ~182M at devnet's
/// base fee against a price of ~1e6 — so "can afford the price" is not the
/// question. The reserve is moved out of the payer before the guest runs, so
/// an account that clears the price but not the reserve never reaches the
/// program at all: the sequencer refuses it with a bare "Incorrect fee" that
/// names neither number.
async fn assert_can_afford(
    wallet_core: &WalletCore,
    payer: &AccountId,
    price: u128,
    label: &str,
) -> u128 {
    let account = read_account(wallet_core, payer, label).await;
    let (reserve, basis) = quoted_fee_reserve(wallet_core, label).await;
    let required = price.saturating_add(reserve);
    assert!(
        account.balance >= required,
        "{label}: payer {payer} holds {} native, needs {required} \
         ({price} price + {reserve} fee reserve, sized from {basis})",
        account.balance,
    );
    reserve
}

pub async fn register_identity(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    payer_id: &AccountId,
    rate_limit: u64,
) -> u64 {
    crate::fr_bytes::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let config_account = derive_config_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
    );
    let tree_main_account = derive_tree_main_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
    );

    let config_data = wallet_core
        .get_account_public(config_account)
        .await
        .expect("Failed to fetch config account. Is the registration initialized?");

    let config_bytes = config_data.data.as_ref();
    let treasury_bytes: [u8; 32] = config_bytes
        [CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32]
        .try_into()
        .expect("Invalid treasury account ID in config");
    let treasury_account_id = AccountId::new(treasury_bytes);

    let main_account_data = wallet_core
        .get_account_public(tree_main_account)
        .await
        .expect("Failed to fetch tree main account");

    let tree_data = main_account_data.data.as_ref();
    let next_index = u64::from_le_bytes(tree_data[1..9].try_into().unwrap());

    let subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_account = derive_subtree_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
        subtree_id,
    );

    let membership_account = crate::rln::derive_membership_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
        id_commitment,
    );
    let accounts = vec![
        config_account,
        tree_main_account,
        *payer_id,
        treasury_account_id,
        subtree_account,
        clock_account_id(),
        membership_account,
    ];

    let max_fee = assert_can_afford(
        wallet_core,
        payer_id,
        PRICE_PER_UNIT.saturating_mul(u128::from(rate_limit)),
        "register",
    )
    .await;

    let instruction = Instruction::Register {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        subtree_id,
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    send_metered_tx(
        wallet_core,
        crate::spel_seeds::program_account(&registration_program.id()),
        accounts,
        payer_id,
        instruction_data,
        max_fee,
        "Failed to register identity",
    )
    .await;

    next_index
}

/// Renew a membership that is currently inside its grace period.
///
/// Renewal costs the same as registering the membership's rate limit, so
/// `payer_id` must hold that much NATIVE balance on top of the fee reserve; it
/// signs and is debited. Anyone may pay for anyone's renewal — the charge, not
/// the caller's identity, is what stops a third party from pinning an
/// abandoned membership's rate limit forever.
pub async fn extend_membership(
    wallet_core: &WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    payer_id: &AccountId,
    treasury_id: &AccountId,
) {
    crate::fr_bytes::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let config_account = derive_config_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
    );
    let membership_account = crate::rln::derive_membership_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
        id_commitment,
    );

    let accounts = vec![
        config_account,
        membership_account,
        *payer_id,
        *treasury_id,
        clock_account_id(),
    ];

    // Priced off the membership's own rate limit, which the guest reads and
    // the host would have to fetch; MAX_RATE_LIMIT is the ceiling, so checking
    // against it refuses an account that could not afford any renewal without
    // a second round trip. A payer that clears this can still be refused by
    // the guest for its actual price, which is the authority.
    let max_fee = assert_can_afford(
        wallet_core,
        payer_id,
        PRICE_PER_UNIT.saturating_mul(u128::from(crate::rln::MAX_RATE_LIMIT)),
        "extend",
    )
    .await;

    let instruction = Instruction::Extend {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    send_metered_tx(
        wallet_core,
        crate::spel_seeds::program_account(&registration_program.id()),
        accounts,
        payer_id,
        instruction_data,
        max_fee,
        "Failed to extend membership",
    )
    .await;
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
    crate::fr_bytes::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let config_account = derive_config_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
    );
    let tree_main_account = derive_tree_main_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
    );
    let membership_account = crate::rln::derive_membership_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
        id_commitment,
    );
    let subtree_id = (leaf_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_account = derive_subtree_account(
        &crate::spel_seeds::program_account(&registration_program.id()),
        tree_id,
        subtree_id,
    );

    let accounts = vec![
        config_account,
        tree_main_account,
        membership_account,
        subtree_account,
        clock_account_id(),
    ];

    // Erase pays no price, only the fee, so there is nothing to check the
    // payer against beyond what admission itself checks.
    let (max_fee, _) = quoted_fee_reserve(wallet_core, "erase").await;
    let instruction = Instruction::Erase {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        subtree_id,
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    send_metered_tx(
        wallet_core,
        crate::spel_seeds::program_account(&registration_program.id()),
        accounts,
        fee_payer_id,
        instruction_data,
        max_fee,
        "Failed to erase membership",
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAS: u64 = 10_000_000;

    /// devnet's quote on 2026-09-30: base fee 8, next-block ceiling 9.
    fn devnet_quote() -> FeeStateQuote {
        FeeStateQuote {
            height: 15_448,
            base_fee_exec: 8,
            base_fee_stor: 8,
            next_base_fee_exec_floor: 8,
            next_base_fee_exec_ceiling: 9,
            next_base_fee_stor_floor: 8,
            next_base_fee_stor_ceiling: 9,
            max_gas_exec: 10_000_000,
            max_gas_stor: 1_000_000,
        }
    }

    #[test]
    fn the_reserve_is_sized_from_the_quoted_ceiling() {
        // (10M x 9 + 100k x 9) x 2
        assert_eq!(fee_reserve_from(&devnet_quote(), GAS), 181_800_000);
    }

    #[test]
    fn the_headroom_multiplies_the_quoted_reserve() {
        let quote = devnet_quote();
        let unscaled = u128::from(GAS) * u128::from(quote.next_base_fee_exec_ceiling)
            + ASSUMED_DATA_BYTES * u128::from(quote.next_base_fee_stor_ceiling);
        assert_eq!(fee_reserve_from(&quote, GAS), unscaled * BASE_FEE_HEADROOM);
    }

    #[test]
    fn the_reserve_follows_the_declared_gas_limit() {
        assert_eq!(
            fee_reserve_from(&devnet_quote(), 2_000_000),
            (2_000_000 * 9 + 100_000 * 9) * 2
        );
    }

    #[test]
    fn a_quote_reports_its_height() {
        assert_eq!(
            fee_reserve(Ok::<_, ()>(devnet_quote()), GAS),
            (181_800_000, ReserveBasis::Quote(15_448))
        );
    }

    #[test]
    fn no_quote_falls_back_to_the_fixed_reserve() {
        // A transport error and an unparsable reply both surface as the RPC
        // call's error.
        assert_eq!(
            fee_reserve(Err::<FeeStateQuote, _>("connection refused"), GAS),
            (DECLARED_MAX_FEE, ReserveBasis::Fallback)
        );
        assert_eq!(DECLARED_MAX_FEE, 646_400_000);
    }

    #[test]
    fn the_declared_cap_clears_the_chains_reserve() {
        // Admission refuses max_fee below gas_limit x base_fee_exec +
        // bytes x base_fee_stor; the quoted cap has to clear it even if the
        // next block moves the base fee all the way to its ceiling.
        let quote = devnet_quote();
        let at_ceiling = u128::from(GAS) * u128::from(quote.next_base_fee_exec_ceiling)
            + ASSUMED_DATA_BYTES * u128::from(quote.next_base_fee_stor_ceiling);
        assert!(fee_reserve_from(&quote, GAS) >= at_ceiling);
        assert!(fee_reserve_from(&quote, GAS) < DECLARED_MAX_FEE);
    }

    #[test]
    fn the_reserve_saturates_instead_of_overflowing() {
        let quote = FeeStateQuote {
            next_base_fee_exec_ceiling: u64::MAX,
            next_base_fee_stor_ceiling: u64::MAX,
            ..devnet_quote()
        };
        assert_eq!(fee_reserve_from(&quote, u64::MAX), u128::MAX);
    }

    fn program_id() -> ProgramId {
        [7; 8]
    }

    fn loader_account(data: Vec<u8>) -> Account {
        Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: data.try_into().expect("fits"),
            ..Account::default()
        }
    }

    fn header_for(image_id: ProgramId) -> Account {
        loader_account(
            ProgramHeader {
                image_id,
                program_first_segment: AccountId::new([1; 32]),
                immutable: true,
            }
            .to_bytes(),
        )
    }

    fn segments() -> Vec<ProgramSegment> {
        vec![
            ProgramSegment {
                bytecode: vec![1, 2, 3],
                next_segment: Some(AccountId::new([2; 32])),
            },
            ProgramSegment {
                bytecode: vec![4, 5],
                next_segment: None,
            },
        ]
    }

    #[test]
    fn an_empty_header_account_is_not_deployed() {
        assert_eq!(
            header_deployed(&Account::default(), &program_id()),
            Ok(false)
        );
    }

    #[test]
    fn a_header_for_this_image_is_deployed() {
        assert_eq!(
            header_deployed(&header_for(program_id()), &program_id()),
            Ok(true)
        );
    }

    #[test]
    fn a_header_for_another_image_is_refused() {
        assert!(header_deployed(&header_for([9; 8]), &program_id()).is_err());
    }

    #[test]
    fn header_bytes_not_owned_by_the_loader_are_refused() {
        let mut squatted = header_for(program_id());
        squatted.program_owner = AccountId::new([3; 32]);
        assert!(header_deployed(&squatted, &program_id()).is_err());
    }

    #[test]
    fn a_funded_but_empty_header_account_is_refused() {
        // CreateHeader asserts a default target, so a balance alone blocks it.
        let funded = Account {
            balance: 1,
            ..Account::default()
        };
        assert!(header_deployed(&funded, &program_id()).is_err());
    }

    #[test]
    fn a_fresh_deploy_writes_every_segment() {
        let on_chain = vec![Account::default(), Account::default()];
        assert_eq!(segments_to_write(&on_chain, &segments()), Ok(vec![0, 1]));
    }

    #[test]
    fn a_resumed_deploy_skips_segments_already_on_chain() {
        let expected = segments();
        let on_chain = vec![Account::default(), loader_account(expected[1].to_bytes())];
        assert_eq!(segments_to_write(&on_chain, &expected), Ok(vec![0]));
    }

    #[test]
    fn a_complete_chain_writes_nothing() {
        let expected = segments();
        let on_chain = expected
            .iter()
            .map(|segment| loader_account(segment.to_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(segments_to_write(&on_chain, &expected), Ok(vec![]));
    }

    #[test]
    fn a_segment_holding_other_bytes_is_refused() {
        let expected = segments();
        let other = ProgramSegment {
            bytecode: vec![9],
            next_segment: None,
        };
        let on_chain = vec![Account::default(), loader_account(other.to_bytes())];
        assert!(segments_to_write(&on_chain, &expected).is_err());
    }
}
