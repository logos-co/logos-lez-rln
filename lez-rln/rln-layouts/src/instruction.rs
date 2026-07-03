//! Shared `Instruction` enum for the RLN registration program.
//!
//! Defined once and consumed by both the guest (via the SPEL macro arg
//! `#[lez_program(instruction = "rln_layouts::Instruction")]`) and the host
//! when building transactions. Variants and field order must match the
//! `#[instruction]` fn parameter lists in `methods/guest/src/program.rs`
//! (account params stripped, remaining args preserved in order).

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Instruction {
    Initialize {
        merkle_program_id: [u8; 32],
        token_program_id: [u8; 32],
        tree_id: [u8; 32],
        payment_token_id: [u8; 32],
        price_per_unit: u128,
        treasury_account_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships: u32,
        grace_period_duration_for_new_memberships: u32,
    },
    InitializeCreditToken {
        token_program_id: [u8; 32],
        tree_id: [u8; 32],
    },
    InitializeMerkleTree {
        merkle_program_id: [u8; 32],
        tree_id: [u8; 32],
    },
    Register {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        subtree_id: u32,
    },
    BuyCredits {
        tree_id: [u8; 32],
        amount: u128,
    },
    RegisterWithCredits {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        amount_to_burn: u64,
        subtree_id: u32,
    },
    Slash {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        identity_secret: [u8; 32],
        subtree_id: u32,
    },
    Extend {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
    },
    Erase {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        subtree_id: u32,
    },
}
