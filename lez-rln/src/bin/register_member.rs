//! Register one or more RLN memberships and print config account IDs and leaf indices.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin register_member          # single
//! source dev/env.sh && cargo run --bin register_member -- --count 5  # batch
//! ```

use logos_lez_rln::rln::{
    client::{
        RlnIdentity, create_identity, init_wallet, register_identity, resolve_payer,
        tree_id_from_env,
    },
    derive_config_account, program_ids_or_exit,
};

const USER_MESSAGE_LIMIT: u64 = 100;

#[tokio::main]
async fn main() {
    let count = parse_count();

    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    let mut wallet_core = init_wallet().await;
    let config_account_id = derive_config_account(&programs.registration, &tree_id);

    for i in 0..count {
        let user_holding_id = resolve_payer();

        let RlnIdentity {
            id_commitment_bytes,
            leaf_bytes,
            id_secret_hash_hex,
            ..
        } = create_identity(&mut wallet_core, USER_MESSAGE_LIMIT).await;

        let leaf_index = register_identity(
            &wallet_core,
            &programs,
            &tree_id,
            &id_commitment_bytes,
            &user_holding_id,
            USER_MESSAGE_LIMIT,
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "Timeout waiting for leaf 0x{} to appear on-chain",
                hex::encode(leaf_bytes)
            )
        });

        println!("CONFIG_ACCOUNT={}", config_account_id);
        println!("LEAF_INDEX={}", leaf_index);
        println!("IDENTITY_SECRET_HASH={}", id_secret_hash_hex);

        if count > 1 {
            eprintln!(
                "  Registered member {}/{}: leaf={}",
                i + 1,
                count,
                leaf_index
            );
        }
    }
}

fn parse_count() -> usize {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--count"
            && let Some(n) = args.get(i + 1)
        {
            return n.parse().expect("--count must be a positive integer");
        }
    }
    1
}
