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
        authorized_registrar: [u8; 32],
        free_quota: u64,
        faucet_claim_cap: u128,
    },
    /// Callee program ids are deliberately absent here and on
    /// `InitializePaymentToken`: they come from the config PDA these
    /// instructions declare. A caller-supplied program id would be handed
    /// `pda_seeds` authorizing it to claim the registration program's own PDAs.
    InitializeMerkleTree { tree_id: [u8; 32] },
    Register {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        subtree_id: u32,
    },
    /// Register while displacing an expired membership, taking over its leaf
    /// index and refunding its holder.
    RegisterReplacing {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        subtree_id: u32,
        id_commitment_to_replace: [u8; 32],
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
    /// Create the payment token ("RLNTOK") as a program-owned PDA definition
    /// — faucet deployments only; the mint authority is the program itself,
    /// no human key.
    InitializePaymentToken { tree_id: [u8; 32] },
    /// Faucet: mint up to `faucet_claim_cap` payment tokens to the (signing)
    /// destination holding. Rejected when the deployment's cap is 0.
    ClaimTokens { tree_id: [u8; 32], amount: u128 },
    /// Bring a membership's grace period forward to now. Holder only.
    ForceExpire {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
    },
    /// Create a membership without payment — only the deployment's
    /// `authorized_registrar` may call it, and only while
    /// `free_quota_remaining > 0`.
    RegisterFree {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        subtree_id: u32,
    },
}
