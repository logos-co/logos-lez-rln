//! The registry's whole lifecycle against a LIVE sequencer: deploy, init,
//! register, prove, a refused duplicate, slash, extend, erase.
//!
//! Skipped unless `LEZ_RLN_LOCAL_SEQUENCER` is set. `tools/e2e-local.sh`
//! boots a sequencer with `dev.sh`, funds a payer at genesis and runs this
//! with the environment it needs:
//!
//! - `LEE_WALLET_HOME_DIR`: a wallet whose config names the local sequencer;
//! - `LEZ_RLN_PAYER`: the genesis-funded account (deploys, pays, signs);
//! - `LEZ_RLN_ACTIVE_DURATION_SECS` / `LEZ_RLN_GRACE_PERIOD_DURATION_SECS`: seconds, so extend and
//!   erase become legal within a few clock ticks.
//!
//! `CLOCK_50` moves every 50 blocks, so the two time-gated steps each wait
//! for the clock to pass a threshold rather than sleeping a fixed time.

use std::time::Duration;

use logos_lez_rln::{
    fr_bytes::fr_to_bytes_le,
    merkle_tree::{
        fetch_tree_shard, find_leaf_index, get_merkle_proof, node_hash, proof_to_circuit,
    },
    rln::{
        ProgramIds,
        client::{
            RlnIdentity, create_identity, erase_membership, extend_membership, init_wallet,
            load_programs, membership_durations, read_clock_ms, read_config, read_membership,
            register_identity, resolve_payer, run_setup, slash_membership,
        },
    },
};
use nssa::AccountId;
use rln::prelude::{Fr, Hasher, PoseidonHash, RLNWitnessInput, hash_to_field_le};
use rln_layouts::secs_to_millis;
use wallet::WalletCore;

const RATE_LIMIT: u64 = 100;
const ZERO_LEAF: [u8; 32] = [0u8; 32];

/// Poll the clock until it reads at least `threshold_ms`.
async fn wait_for_clock(wallet: &WalletCore, threshold_ms: u64, what: &str) -> u64 {
    for _ in 0..600 {
        let now = read_clock_ms(wallet).await;
        if now >= threshold_ms {
            return now;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("{what}: CLOCK_50 never reached {threshold_ms}");
}

/// Poll until the membership for `id_commitment` is absent.
async fn wait_for_membership_gone(
    wallet: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    what: &str,
) {
    for _ in 0..120 {
        if read_membership(wallet, programs, tree_id, id_commitment)
            .await
            .is_none()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{what}: membership was never cleared");
}

async fn register(
    wallet: &mut WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    payer: &AccountId,
) -> (RlnIdentity, u64) {
    let identity = create_identity(wallet, RATE_LIMIT).await;
    let leaf_index = register_identity(
        wallet,
        programs,
        tree_id,
        &identity.id_commitment_bytes,
        payer,
        RATE_LIMIT,
    )
    .await
    .expect("the leaf never appeared on-chain");
    (identity, leaf_index)
}

async fn native_balance(wallet: &WalletCore, id: &AccountId) -> u128 {
    wallet.get_account_balance(*id).await.expect("balance read")
}

#[tokio::test]
async fn registry_lifecycle_on_a_live_sequencer() {
    if std::env::var_os("LEZ_RLN_LOCAL_SEQUENCER").is_none() {
        eprintln!("LEZ_RLN_LOCAL_SEQUENCER not set; skipping (run tools/e2e-local.sh)");
        return;
    }
    let (active_sec, grace_sec) = membership_durations();
    assert!(
        active_sec <= 60 && grace_sec <= 300,
        "set LEZ_RLN_ACTIVE_DURATION_SECS / LEZ_RLN_GRACE_PERIOD_DURATION_SECS to seconds, \
         or extend and erase cannot be exercised in one run"
    );

    let mut tree_id = [0u8; 32];
    tree_id.copy_from_slice(&rand_bytes());
    let mut wallet = init_wallet().await;
    let (registration_program, merkle_program) = load_programs();
    let payer = resolve_payer();

    // ── deploy + init ─────────────────────────────────────────────────
    let programs = run_setup(
        &mut wallet,
        &registration_program,
        &merkle_program,
        &tree_id,
    )
    .await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.tree_id, tree_id);
    assert_eq!(config.merkle_program_id, *programs.merkle.value());
    assert_eq!(config.active_duration_for_new_memberships_sec, active_sec);
    assert_eq!(config.total_registrations, 0);
    let treasury = AccountId::new(config.treasury_account_id);
    let price = config.price_per_unit * u128::from(RATE_LIMIT);

    // ── register three members ────────────────────────────────────────
    let treasury_before = native_balance(&wallet, &treasury).await;
    let (member_a, leaf_a) = register(&mut wallet, &programs, &tree_id, &payer).await;
    let (member_b, leaf_b) = register(&mut wallet, &programs, &tree_id, &payer).await;
    let (member_c, leaf_c) = register(&mut wallet, &programs, &tree_id, &payer).await;
    assert_eq!((leaf_a, leaf_b, leaf_c), (0, 1, 2));
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 3);
    assert_eq!(config.current_total_rate_limit, 3 * RATE_LIMIT);
    assert_eq!(
        native_balance(&wallet, &treasury).await,
        treasury_before + 3 * price,
        "the treasury is credited the price of every registration"
    );
    let membership_a = read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
        .await
        .expect("member A is registered");
    assert_eq!(membership_a.rate_limit, RATE_LIMIT);
    assert_eq!(
        find_leaf_index(
            &fetch_tree_shard(&wallet, &programs, &tree_id).await,
            &member_a.leaf_bytes
        ),
        Some(leaf_a)
    );

    // ── an RLN proof against the on-chain root verifies ───────────────
    let proof = get_merkle_proof(&wallet, &programs, &tree_id, leaf_a).await;
    assert_eq!(proof.leaf, member_a.leaf_bytes);
    let (merkle_proof, root) = proof_to_circuit(&proof);
    let epoch = hash_to_field_le(b"local-sequencer-epoch");
    let rln_identifier = hash_to_field_le(b"local-sequencer");
    let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch, rln_identifier);
    let x = hash_to_field_le(b"hello");
    let witness = RLNWitnessInput::new_single()
        .identity_secret(member_a.identity_secret)
        .user_message_limit(Fr::from(RATE_LIMIT))
        .merkle_proof(merkle_proof)
        .x(x)
        .external_nullifier(external_nullifier)
        .message_id(Fr::from(0u64))
        .build()
        .expect("witness");
    let engine = logos_lez_rln::proof_circuit::engine();
    let (rln_proof, values) = engine.generate_proof(&witness).expect("proof generation");
    assert!(
        engine
            .verify_with_roots(&rln_proof, &values, &x, &[root])
            .expect("verification runs"),
        "proof must verify against the folded on-chain root"
    );

    // ── a duplicate registration is refused ───────────────────────────
    let next_index = leaf_c + 1;
    assert_eq!(
        register_identity(
            &wallet,
            &programs,
            &tree_id,
            &member_a.id_commitment_bytes,
            &payer,
            RATE_LIMIT,
        )
        .await,
        None,
        "re-registering an existing commitment must not insert a leaf"
    );
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 3);
    assert!(
        read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
            .await
            .is_some(),
        "still registered"
    );
    assert_eq!(
        find_leaf_index(
            &fetch_tree_shard(&wallet, &programs, &tree_id).await,
            &member_a.leaf_bytes
        ),
        Some(leaf_a)
    );

    // ── slash C by revealing its secret; C may then register again ────
    let secret_c = fr_to_bytes_le(&member_c.identity_secret);
    slash_membership(
        &wallet,
        &programs,
        &tree_id,
        &secret_c,
        &member_c.id_commitment_bytes,
        &payer,
    )
    .await;
    wait_for_membership_gone(
        &wallet,
        &programs,
        &tree_id,
        &member_c.id_commitment_bytes,
        "slash",
    )
    .await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 2);
    assert_eq!(config.current_total_rate_limit, 2 * RATE_LIMIT);
    let shard = fetch_tree_shard(&wallet, &programs, &tree_id).await;
    assert_eq!(
        node_hash(&shard, rln_layouts::TREE_DEPTH, leaf_c),
        ZERO_LEAF,
        "a slashed leaf is zeroed"
    );
    let leaf_c_again = register_identity(
        &wallet,
        &programs,
        &tree_id,
        &member_c.id_commitment_bytes,
        &payer,
        RATE_LIMIT,
    )
    .await
    .expect("C's second leaf never appeared on-chain");
    assert_eq!(
        leaf_c_again, next_index,
        "a slashed commitment registers at a new leaf"
    );

    // ── extend A once its grace period opens ──────────────────────────
    let start_a = membership_a.grace_period_start_timestamp_ms;
    wait_for_clock(&wallet, start_a, "extend").await;
    let treasury_before = native_balance(&wallet, &treasury).await;
    extend_membership(
        &wallet,
        &programs,
        &tree_id,
        &member_a.id_commitment_bytes,
        &payer,
    )
    .await;
    let renewed_start = start_a + secs_to_millis(grace_sec) + secs_to_millis(active_sec);
    for _ in 0..120 {
        let membership =
            read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
                .await
                .expect("A stays registered");
        if membership.grace_period_start_timestamp_ms == renewed_start {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
            .await
            .expect("A stays registered")
            .grace_period_start_timestamp_ms,
        renewed_start,
        "extend pushes the grace window out by one grace + one active period"
    );
    assert_eq!(
        native_balance(&wallet, &treasury).await,
        treasury_before + price,
        "renewal is priced like a registration"
    );

    // ── erase B once it has expired ───────────────────────────────────
    let membership_b = read_membership(&wallet, &programs, &tree_id, &member_b.id_commitment_bytes)
        .await
        .expect("B is registered");
    let expiry_b = membership_b.grace_period_start_timestamp_ms + secs_to_millis(grace_sec);
    wait_for_clock(&wallet, expiry_b, "erase").await;
    erase_membership(
        &wallet,
        &programs,
        &tree_id,
        &member_b.id_commitment_bytes,
        &payer,
    )
    .await;
    wait_for_membership_gone(
        &wallet,
        &programs,
        &tree_id,
        &member_b.id_commitment_bytes,
        "erase",
    )
    .await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 2);
    assert_eq!(config.current_total_rate_limit, 2 * RATE_LIMIT);
    let shard = fetch_tree_shard(&wallet, &programs, &tree_id).await;
    assert_eq!(
        node_hash(&shard, rln_layouts::TREE_DEPTH, leaf_b),
        ZERO_LEAF
    );
    assert_eq!(
        node_hash(&shard, rln_layouts::TREE_DEPTH, leaf_a),
        member_a.leaf_bytes,
        "erasing B leaves A's leaf alone"
    );
}

fn rand_bytes() -> [u8; 32] {
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    let mut seed = [0u8; 32];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&nanos);
    seed[16..24].copy_from_slice(&std::process::id().to_le_bytes()[..4].repeat(2));
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    out
}
