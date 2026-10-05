//! Incremental Merkle Tree with On-Chain Storage
//!
//! Client-side reads of the on-chain incremental Merkle tree and Merkle proof
//! generation.
//!
//! # Note on Tree Operations
//!
//! The merkle tree program is only called via chained calls from the RLN
//! registration program. Clients do not directly build merkle tree transactions.
//! Instead, use the RLN client (`rln::client::register_identity`, etc.).
//!
//! # Provided Functionality
//!
//! - **PDA derivation**: `derive_main_account`
//! - **State reading**: `fetch_tree_shard`, `fetch_root`, `fetch_next_index`, `fetch_node_hash`
//! - **Merkle proofs**: `get_merkle_proof`, `merkle_proof`, `proof_to_fr`
//!
//! # Storage Model
//!
//! The whole tree — header, per-level defaults and a sparse node map — is the
//! merkle program's shard of the registration program's `tree_main` PDA.
//!
//! # Compatibility
//!
//! The on-chain program uses `rust-poseidon-bn254-pure` for hashing, which is
//! compatible with zerokit/RLN's Poseidon implementation.

mod client;
mod constants;
mod pda;

pub use client::*;
pub use constants::*;
pub use pda::*;
