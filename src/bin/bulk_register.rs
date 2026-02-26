//! Bulk-register RLN identities from an `rln_tree.db` file.
//!
//! Reads the binary format produced by the logos-delivery mixnet simulation
//! and registers each member on-chain via the LSSA sequencer.
//!
//! Usage:
//! ```bash
//! cargo run --bin bulk_register -- <path_to_rln_tree.db>
//! ```
//!
//! The .db format:
//! - Header (16 bytes): member_count(u64 LE) + next_index(u64 LE)
//! - Per member (48 bytes): id_commitment(32) + index(u64 LE) + userMessageLimit(u64 LE)

use logos_lez_rln::rln::client::{
    TREE_ID, init_wallet, load_programs, is_initialized,
    run_setup, create_funded_user, register_identity, PRICE_PER_UNIT,
};
use rln_layouts::{MIN_RATE_LIMIT, MAX_RATE_LIMIT};
use std::path::Path;

struct DbMember {
    id_commitment: [u8; 32],
    index: u64,
    user_message_limit: u64,
}

fn parse_rln_tree_db(path: &Path) -> Vec<DbMember> {
    let data = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path.display(), e);
        std::process::exit(1);
    });

    if data.len() < 16 {
        eprintln!("File too small for header (got {} bytes)", data.len());
        std::process::exit(1);
    }

    let member_count = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let next_index = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let expected_size = 16 + member_count * 48;
    if data.len() != expected_size {
        eprintln!(
            "File size mismatch: expected {} bytes ({} members), got {} bytes",
            expected_size, member_count, data.len()
        );
        std::process::exit(1);
    }

    println!("Parsed header: {} members, next_index={}", member_count, next_index);

    let mut members = Vec::with_capacity(member_count);
    for i in 0..member_count {
        let offset = 16 + i * 48;
        let id_commitment: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
        let index = u64::from_le_bytes(data[offset + 32..offset + 40].try_into().unwrap());
        let user_message_limit =
            u64::from_le_bytes(data[offset + 40..offset + 48].try_into().unwrap());

        members.push(DbMember {
            id_commitment,
            index,
            user_message_limit,
        });
    }

    // Sort by index to register in order
    members.sort_by_key(|m| m.index);
    members
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_rln_tree.db>", args[0]);
        std::process::exit(1);
    }

    let db_path = Path::new(&args[1]);
    let members = parse_rln_tree_db(db_path);

    if members.is_empty() {
        println!("No members to register.");
        return;
    }

    // Validate rate limits upfront
    let mut invalid = Vec::new();
    for (i, m) in members.iter().enumerate() {
        if m.user_message_limit < MIN_RATE_LIMIT || m.user_message_limit > MAX_RATE_LIMIT {
            invalid.push((i, m.index, m.user_message_limit));
        }
    }
    if !invalid.is_empty() {
        eprintln!("Error: {} members have invalid rate limits (must be {}-{}):", invalid.len(), MIN_RATE_LIMIT, MAX_RATE_LIMIT);
        for (i, idx, limit) in &invalid {
            eprintln!("  member[{}] index={} userMessageLimit={}", i, idx, limit);
        }
        std::process::exit(1);
    }

    // Calculate total cost
    let total_cost: u128 = members
        .iter()
        .map(|m| PRICE_PER_UNIT * m.user_message_limit as u128)
        .sum();

    println!(
        "\n=== Bulk Registration ===\n\
         Members: {}\n\
         Total cost: {} tokens (price_per_unit={}, sum of rate_limits={})\n",
        members.len(),
        total_cost,
        PRICE_PER_UNIT,
        members.iter().map(|m| m.user_message_limit).sum::<u64>(),
    );

    // Init wallet and load programs
    let mut wallet_core = init_wallet();
    let tree_id = TREE_ID;
    let (registration_program, merkle_program) = load_programs();

    // Fund with enough for all registrations plus margin
    let user_funding = total_cost + total_cost / 10; // 10% margin

    let user_holding_id = if is_initialized(&wallet_core, &registration_program, &tree_id).await {
        println!("Registration already initialized.\n");
        create_funded_user(&mut wallet_core, &tree_id, user_funding).await
    } else {
        println!("First run, setting up...\n");
        run_setup(
            &mut wallet_core,
            &registration_program,
            &merkle_program,
            &tree_id,
            user_funding,
        )
        .await
    };

    // Fetch initial nonce for the user account, then track it client-side
    // to avoid nonce mismatch errors when sending transactions faster than
    // the sequencer processes them.
    let initial_nonces = wallet_core
        .get_accounts_nonces(vec![user_holding_id.clone()])
        .await
        .expect("Failed to fetch initial nonce");
    let mut current_nonce = initial_nonces[0];

    // Bulk register
    println!("Registering {} members...\n", members.len());

    for (i, member) in members.iter().enumerate() {
        let leaf_index = register_identity(
            &wallet_core,
            &registration_program,
            &tree_id,
            &member.id_commitment,
            &user_holding_id,
            member.user_message_limit,
            Some(current_nonce),
        )
        .await;

        current_nonce += 1;

        println!(
            "[{}/{}] leaf_index={} id_commitment=0x{:.16}... rate_limit={}",
            i + 1,
            members.len(),
            leaf_index,
            hex::encode(&member.id_commitment),
            member.user_message_limit,
        );
    }

    println!(
        "\n=== Done ===\nRegistered {} members successfully.",
        members.len()
    );
}
