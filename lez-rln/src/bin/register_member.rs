//! Register one or more RLN memberships and print config account IDs and leaf indices.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin register_member          # single
//! source dev/env.sh && cargo run --bin register_member -- --count 5  # batch
//! ```

use logos_lez_rln::merkle_tree::wait_for_leaf;
use logos_lez_rln::rln::client::{
    RlnIdentity, create_funded_user, create_identity, init_wallet, load_programs,
    register_identity, tree_id_from_env,
};
use logos_lez_rln::rln::derive_config_account;
use std::time::Duration;

const USER_FUNDING: u128 = 100_000_000;
const USER_MESSAGE_LIMIT: u64 = 100;

#[tokio::main]
async fn main() {
    let count = parse_count();

    let mut wallet_core = init_wallet();
    let tree_id = tree_id_from_env();
    let (registration_program, _merkle_program) = load_programs();
    let config_account_id = derive_config_account(&registration_program.id(), &tree_id);

    for i in 0..count {
        let user_holding_id = create_funded_user(&mut wallet_core, &tree_id, USER_FUNDING).await;

        let RlnIdentity { id_commitment_bytes, leaf_bytes, id_secret_hash_hex, .. } =
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
            panic!("Timeout waiting for leaf {} to appear on-chain", leaf_index);
        }

        println!("CONFIG_ACCOUNT={}", config_account_id);
        println!("LEAF_INDEX={}", leaf_index);
        println!("IDENTITY_SECRET_HASH={}", id_secret_hash_hex);

        if count > 1 {
            eprintln!("  Registered member {}/{}: leaf={}", i + 1, count, leaf_index);
        }
    }
}

fn parse_count() -> usize {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--count" {
            if let Some(n) = args.get(i + 1) {
                return n.parse().expect("--count must be a positive integer");
            }
        }
    }
    1
}
