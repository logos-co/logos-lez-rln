//! End-to-end RLN proof demonstration.
//!
//! Run repeatedly with `cargo run --bin run_rln_proof` to register new memberships.
//! First run deploys programs and initializes the tree; subsequent runs add members.
//!
//! Build the guest programs first:
//! ```bash
//! cargo risczero build --manifest-path methods/guest/Cargo.toml
//! ```
use logos_lez_rln::merkle_tree::{
    TREE_DEPTH, get_merkle_proof, proof_to_fr, wait_for_leaf,
};
use logos_lez_rln::rln::client::{
    TREE_ID, init_wallet, load_programs, is_initialized,
    run_setup, create_funded_user, register_identity,
};
use rln::hashers::poseidon_hash;
use rln::prelude::{hash_to_field_le, seeded_keygen, Fr, RLNWitnessInput, RLN};
use rln::utils::{fr_to_bytes_le, IdSecret};
use std::time::Duration;
use wallet::WalletCore;

const USER_FUNDING: u128 = 100_000_000;

// RLN proof constants
const USER_MESSAGE_LIMIT: u64 = 100;
const MESSAGE_ID: u64 = 0;
const MESSAGE: &str = "Hello, RLN!";
const EPOCH: &str = "1231028105";
const RLN_IDENTIFIER: &str = "rln/logos-rln-relay/v2.0.0";

#[tokio::main]
async fn main() {
    let mut wallet_core = init_wallet();
    let tree_id = TREE_ID;
    let (registration_program, merkle_program) = load_programs();

    println!("=== RLN Proof Demo ===\n");

    let user_holding_id = if is_initialized(&wallet_core, &registration_program, &tree_id).await {
        println!("Registration already initialized, creating new user...\n");
        create_funded_user(&mut wallet_core, &tree_id, USER_FUNDING).await
    } else {
        println!("First run, setting up...\n");
        run_setup(&mut wallet_core, &registration_program, &merkle_program, &tree_id, USER_FUNDING).await
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
        &tree_id,
        &id_commitment_bytes,
        &user_holding_id,
        USER_MESSAGE_LIMIT,
        None,
    ).await;
    println!("  Registered at index: {}", leaf_index);

    // Wait for transaction to be finalized
    let finalized = wait_for_leaf(
        &wallet_core,
        &registration_program,
        &tree_id,
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
    let proof = get_merkle_proof(&wallet_core, &registration_program, &tree_id, leaf_index).await;
    let (path_elements, path_indices, root) = proof_to_fr(&proof);

    assert_eq!(leaf_bytes, proof.leaf, "Leaf mismatch - transaction may not be finalized");

    // Step 4: Generate RLN proof
    println!("\nStep 4: Generating RLN proof...");
    let user_message_limit_fr = Fr::from(USER_MESSAGE_LIMIT);
    let message_id_fr = Fr::from(MESSAGE_ID);

    let epoch_fr = hash_to_field_le(EPOCH.as_bytes()).expect("Failed to hash epoch");
    let rln_identifier_fr = hash_to_field_le(RLN_IDENTIFIER.as_bytes())
        .expect("Failed to hash rln_identifier");
    let external_nullifier = poseidon_hash(&[epoch_fr, rln_identifier_fr])
        .expect("Failed to compute external nullifier");

    let x = hash_to_field_le(MESSAGE.as_bytes()).expect("Failed to hash message");

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

    let rln = RLN::new(TREE_DEPTH, "").expect("Failed to initialize RLN");

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

    println!("\n=== Summary ===");
    println!("Identity inserted at index: {}", leaf_index);
    println!("On-chain root: {}", hex::encode(fr_to_bytes_le(&root)));
    println!("Proof valid: {}", is_valid);

    if !is_valid {
        panic!("RLN proof verification failed!");
    }
}

/// Create a new RLN identity and compute the rate commitment (leaf value).
async fn create_identity(
    wallet_core: &mut WalletCore,
    user_message_limit: u64,
) -> (IdSecret, Fr, [u8; 32], [u8; 32]) {
    let (account_id, chain_index) = wallet_core.create_new_account_public(None);
    println!("  Created account: {} at path {}", account_id, chain_index);
    wallet_core
        .store_persistent_data()
        .await
        .expect("Failed to store wallet");

    let signing_key = wallet_core
        .storage()
        .user_data
        .get_pub_account_signing_key(account_id.clone())
        .expect("Account should be self-owned public");

    let seed = signing_key.value();
    let (mut identity_secret_fr, id_commitment) =
        seeded_keygen(seed).expect("seeded_keygen should succeed");

    let identity_secret = IdSecret::from(&mut identity_secret_fr);
    let id_commitment_bytes: [u8; 32] = fr_to_bytes_le(&id_commitment).try_into().unwrap();

    let user_message_limit_fr = Fr::from(user_message_limit);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit_fr])
        .expect("Failed to compute rate commitment");
    let leaf_bytes: [u8; 32] = fr_to_bytes_le(&rate_commitment).try_into().unwrap();

    (identity_secret, id_commitment, id_commitment_bytes, leaf_bytes)
}
