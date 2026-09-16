//! Shared `Instruction` enum for the RLN registration program.
//!
//! Defined once and consumed by both the guest (via the SPEL macro arg
//! `#[lez_program(instruction = "rln_layouts::Instruction")]`) and the host
//! when building transactions. Variants and field order must match the
//! `#[instruction]` fn parameter lists in `methods/guest/src/program.rs`
//! (account params stripped, remaining args preserved in order).
//!
//! Borsh encodes a variant as its DECLARATION INDEX, so removing or reordering
//! a variant re-numbers every variant after it. A host built against one
//! revision of this enum and a guest built against another agree on the bytes
//! and disagree on their meaning, silently. Move the two together.
//!
//! A membership is paid for in the NATIVE asset by the account that signs the
//! transaction, which is also its fee payer. There is no payment token, no
//! credit token and no faucet: no program can mint native balance, so it
//! enters an account only at genesis, over the bridge, or by transfer.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Instruction {
    Initialize {
        merkle_program_id: [u8; 32],
        tree_id: [u8; 32],
        /// Native atomic units charged per unit of rate limit.
        price_per_unit: u128,
        /// Plain public account the price is credited to. Deliberately not a
        /// PDA: a PDA is spendable only through a chained call carrying its
        /// seeds, issued by its owning program, and this program has no
        /// instruction that would issue one.
        treasury_account_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships: u32,
        grace_period_duration_for_new_memberships: u32,
    },
    /// The callee program id is deliberately absent: it comes from the config
    /// PDA this instruction declares. A caller-supplied program id would be
    /// handed `pda_seeds` authorizing it to claim this program's own PDAs.
    InitializeMerkleTree { tree_id: [u8; 32] },
    Register {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
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
