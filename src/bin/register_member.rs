//! Register a single RLN membership and print the config account ID and leaf index.
//!
//! Used by the E2E test script to register members and parse results.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin register_member
//! ```

use logos_lez_rln::merkle_tree::wait_for_leaf;
use logos_lez_rln::rln::client::{
    TREE_ID, init_wallet, load_programs, create_funded_user, register_identity,
};
use logos_lez_rln::rln::derive_config_account;
use rln::hashers::poseidon_hash;
use rln::prelude::{seeded_keygen, Fr};
use rln::utils::{fr_to_bytes_le, IdSecret};
use std::time::Duration;

const USER_FUNDING: u128 = 100_000_000;
const USER_MESSAGE_LIMIT: u64 = 100;

#[tokio::main]
async fn main() {
    let mut wallet_core = init_wallet();
    let tree_id = TREE_ID;
    let (registration_program, _merkle_program) = load_programs();

    let config_account_id = derive_config_account(&registration_program.id(), &tree_id);

    let user_holding_id = create_funded_user(&mut wallet_core, &tree_id, USER_FUNDING).await;

    let (_, id_commitment_bytes, leaf_bytes) =
        create_identity(&mut wallet_core, USER_MESSAGE_LIMIT).await;

    let leaf_index = register_identity(
        &wallet_core,
        &registration_program,
        &tree_id,
        &id_commitment_bytes,
        &user_holding_id,
        USER_MESSAGE_LIMIT,
        None,
    )
    .await;

    let finalized = wait_for_leaf(
        &wallet_core,
        &registration_program,
        &tree_id,
        leaf_index,
        &leaf_bytes,
        30,
        Duration::from_millis(500),
    )
    .await;
    if !finalized {
        panic!("Timeout waiting for leaf to appear on-chain");
    }

    // Print parseable output for the test script
    println!("CONFIG_ACCOUNT={}", config_account_id);
    println!("LEAF_INDEX={}", leaf_index);
}

/// Create a new RLN identity and compute the rate commitment (leaf value).
async fn create_identity(
    wallet_core: &mut wallet::WalletCore,
    user_message_limit: u64,
) -> (IdSecret, [u8; 32], [u8; 32]) {
    let (account_id, _chain_index) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .await
        .expect("Failed to store wallet");

    let signing_key = wallet_core
        .storage()
        .user_data
        .get_pub_account_signing_key(account_id)
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

    (identity_secret, id_commitment_bytes, leaf_bytes)
}
