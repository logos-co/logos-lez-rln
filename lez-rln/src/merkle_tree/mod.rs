//! Incremental Merkle Tree with On-Chain Storage
//!
//! This module provides client-side utilities for reading state from the on-chain
//! incremental Merkle tree and generating Merkle proofs.
//!
//! # Note on Tree Operations
//!
//! The merkle tree program is only called via chained calls from the RLN
//! registration program. Clients do not directly build merkle tree transactions.
//! Instead, use the RLN client (`rln::register`, etc.) which handles merkle tree
//! operations internally.
//!
//! # Provided Functionality
//!
//! - **PDA derivation**: `derive_main_account`, `derive_subtree_account`
//! - **State reading**: `fetch_root`, `fetch_next_index`, `fetch_node_hash`
//! - **Merkle proofs**: `get_merkle_proof`, `proof_to_fr`
//!
//! # Storage Model
//!
//! - **Main Account**: Stores tree metadata (depth, next_index, root, cached defaults) and top tree
//!   nodes (levels 0-10) in sparse format
//! - **Subtree Accounts**: Each stores a depth-10 bottom subtree in sparse format
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
