//! Shared `Message` enums for the RLN registration and merkle programs.
//!
//! Defined once and consumed by both guests (decoded when a message is
//! delivered) and the host when building the root message of a transaction.
//!
//! Borsh encodes a variant as its DECLARATION INDEX, so removing or reordering
//! a variant re-numbers every variant after it. A host built against one
//! revision of this enum and a guest built against another agree on the bytes
//! and disagree on their meaning, silently. Move the two together.
//!
//! # Actors and messages
//!
//! A program runs as actors: one `(account, program)` pair per message
//! delivery, seeing only that actor's own state. The registration program has
//! two kinds of actor, the config PDA (`config_seed(tree_id)`) and one
//! membership PDA per member (`membership_seed(tree_id, id_commitment)`); the
//! merkle program has one, the tree's main PDA (`main_seed(tree_id)`, owned
//! by the registration program).
//!
//! Every value a handler needs it reads from its own state or receives from
//! another actor of its own program. There are no claims: the config knows
//! its price, treasury, durations, bounds and the merkle program; a
//! membership knows its rate limit and dates. What a transaction submits is
//! the ENTRY variant for the actor it targets (the config for `Initialize`,
//! `InitializeMerkleTree` and `Register`; the membership for `Slash`,
//! `Extend` and `Erase`); the INTERNAL variants are sent between the
//! program's own actors and are refused from anyone else.
//!
//! The leaf index is NOT carried for a registration. The tree assigns it on
//! insert (its own `next_index`), so registrations built from the same chain
//! state do not contend for one index. Slash and erase carry the index as a
//! HINT that the merkle program checks by content: the leaf there must be
//! `H(id_commitment, rate_limit)`, with `rate_limit` read from the
//! membership's own state.
//!
//! `now_ms` is the submitter's reading of chain time. It dates the
//! membership and bounds the transaction's validity window: the including
//! block's timestamp must lie in `[now_ms, now_ms + CLOCK_CLAIM_TOLERANCE_MS)`,
//! so a claim may be at most the tolerance behind chain time and never ahead.
//!
//! A membership is paid for in the NATIVE asset by `payer`, who signs the
//! transaction and is also its fee payer. There is no payment token, no
//! credit token and no faucet: no program can mint native balance, so it
//! enters an account only at genesis, over the bridge, or by transfer.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::state::MembershipState;

/// Messages of the registration program.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message {
    // ── entry: sent to the config actor ──────────────────────────────────
    /// Write the registry's config. One-shot: refused on a non-empty state.
    Initialize {
        /// Account id of the deployed merkle program: the header account the
        /// deployer created and signed, not a hash of its bytecode.
        merkle_program_id: [u8; 32],
        tree_id: [u8; 32],
        /// Native atomic units charged per unit of rate limit.
        price_per_unit: u128,
        /// Plain public account the price is credited to. Deliberately not a
        /// PDA: a PDA is spendable only by its owning program, and this
        /// program has no message that would spend it.
        treasury_account_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships_sec: u32,
        grace_period_duration_for_new_memberships_sec: u32,
        /// Inclusive bounds every registration's `rate_limit` must satisfy;
        /// `0 < min <= max`.
        min_rate_limit: u64,
        max_rate_limit: u64,
    },
    /// Initialize the tree: the config grants the merkle program its `main`
    /// PDA. One-shot on the tree's side.
    InitializeMerkleTree { tree_id: [u8; 32] },
    /// Register `id_commitment` at `rate_limit`, paid by `payer`.
    Register {
        tree_id: [u8; 32],
        /// A BN254 field element, non-zero.
        id_commitment: [u8; 32],
        rate_limit: u64,
        /// Signs the transaction; its native balance pays the price.
        payer: [u8; 32],
        /// The submitter's reading of chain time, in milliseconds; dates
        /// the membership and bounds the validity window.
        now_ms: u64,
    },

    // ── entry: sent to the membership actor ──────────────────────────────
    /// Remove a member whose identity secret is known.
    Slash {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        identity_secret: [u8; 32],
        /// Hint: the index of the membership's leaf, found by scanning the
        /// tree. The merkle `Remove` refuses it unless it holds this member's
        /// leaf.
        leaf_index: u64,
    },
    /// Renew a membership inside its grace period, paid by `payer`.
    Extend {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        payer: [u8; 32],
        now_ms: u64,
    },
    /// Remove an expired membership, returning its rate limit to the pool.
    Erase {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        /// Hint, as for `Slash`.
        leaf_index: u64,
        now_ms: u64,
    },

    // ── internal: between the program's own actors ───────────────────────
    /// Config → membership: write a new membership. One-shot: this is the
    /// only duplicate-registration guard.
    InitMembership {
        tree_id: [u8; 32],
        state: MembershipState,
    },
    /// Membership → config: uncount a removed member and remove its leaf.
    Release {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        leaf_index: u64,
        leaf: [u8; 32],
    },
    /// Membership → config: charge `payer` the renewal of `rate_limit`.
    ChargeRenewal {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        payer: [u8; 32],
    },
}

/// Messages of the incremental merkle tree program, sent by the registration
/// program's config actor to the tree's main PDA (and, in tests, directly).
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum MerkleMessage {
    /// Empty tree. Refused on a non-empty state.
    Initialize,
    /// Append `leaf` at the tree's own `next_index`.
    Insert { leaf: [u8; 32] },
    /// Zero the leaf at `index`, which must hold `leaf`.
    Remove { index: u64, leaf: [u8; 32] },
    /// Write `leaf` into an emptied slot below `next_index`. No caller today;
    /// the only index-reuse path if capacity ever has to grow.
    Set { index: u64, leaf: [u8; 32] },
}
