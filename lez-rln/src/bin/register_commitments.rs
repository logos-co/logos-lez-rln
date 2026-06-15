//! Register pre-generated identity commitments on-chain from a CSV file.
//! FEATURE: Bridge between off-chain credential generation and on-chain LEZ registration
//!
//! Each line: hex_id_commitment,rate_limit
//!
//! ```bash
//! source dev/env.sh && cargo run --bin register_commitments -- commitments.csv
//! ```

use logos_lez_rln::merkle_tree::wait_for_leaf;
use logos_lez_rln::rln::client::{
    init_wallet, load_programs, create_funded_user, register_identity, tree_id_from_env,
};
use logos_lez_rln::rln::derive_config_account;
use rln::hashers::poseidon_hash;
use rln::prelude::Fr;
use rln::utils::{bytes_le_to_fr, fr_to_bytes_le};
use std::fs;
use std::time::Duration;

const USER_FUNDING: u128 = 100_000_000;

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let hex = hex.trim();
    assert_eq!(hex.len(), 64, "Expected 64 hex chars, got {}", hex.len());
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("Invalid hex at position {}", i));
    }
    bytes
}

fn compute_rate_commitment(id_commitment_bytes: &[u8; 32], rate_limit: u64) -> [u8; 32] {
    let (id_commitment_fr, _) = bytes_le_to_fr(id_commitment_bytes)
        .expect("Invalid id_commitment bytes");
    let rate_limit_fr = Fr::from(rate_limit);
    let rate_commitment = poseidon_hash(&[id_commitment_fr, rate_limit_fr]);
    fr_to_bytes_le(&rate_commitment).try_into().unwrap()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let csv_path = args.get(1).expect("Usage: register_commitments <commitments.csv>");

    let content = fs::read_to_string(csv_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", csv_path, e));

    let entries: Vec<([u8; 32], u64)> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            assert!(parts.len() >= 2, "Expected: hex_commitment,rate_limit[,idSecretHash]");
            let commitment = hex_to_bytes32(parts[0]);
            let rate_limit: u64 = parts[1].trim().parse().expect("Invalid rate_limit");
            (commitment, rate_limit)
        })
        .collect();

    eprintln!("Registering {} identity commitments on-chain...", entries.len());

    let mut wallet_core = init_wallet();
    let tree_id = tree_id_from_env();
    let (registration_program, _merkle_program) = load_programs();
    let config_account_id = derive_config_account(&registration_program.id(), &tree_id);

    for (i, (id_commitment, rate_limit)) in entries.iter().enumerate() {
        let user_holding_id = create_funded_user(&mut wallet_core, &tree_id, USER_FUNDING).await;

        let leaf_bytes = compute_rate_commitment(id_commitment, *rate_limit);

        let leaf_index = register_identity(
            &wallet_core,
            &registration_program,
            &tree_id,
            id_commitment,
            &user_holding_id,
            *rate_limit,
            None,
        )
        .await;

        eprintln!(
            "    leaf_index={} id_commitment=0x{} rate_commitment=0x{}",
            leaf_index,
            hex::encode(&id_commitment[..8]),
            hex::encode(&leaf_bytes[..8])
        );

        let finalized = wait_for_leaf(
            &wallet_core,
            &registration_program,
            &tree_id,
            leaf_index,
            &leaf_bytes,
            60,
            Duration::from_millis(500),
        )
        .await;
        if !finalized {
            eprintln!("WARNING: Leaf {} not confirmed, continuing...", leaf_index);
        }

        eprintln!(
            "  Registered {}/{}: leaf_index={} commitment={}...",
            i + 1,
            entries.len(),
            leaf_index,
            &hex::encode(&id_commitment[..8])
        );
    }

    println!("CONFIG_ACCOUNT={}", config_account_id);
    eprintln!("All {} commitments registered successfully.", entries.len());
}
