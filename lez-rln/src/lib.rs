//! RLN zkVM Programs
//!
//! This crate contains RLN (Rate Limiting Nullifier) programs and client code for LSSA.
//!
//! # Architecture Overview
//!
//! The code is organized into three categories:
//!
//! ## On-Chain (Guest Programs)
//! Located in `methods/guest/src/bin/`. These are zkVM programs that run inside RISC Zero.
//! They define the state transition logic and are compiled to RISC-V.
//! - `incremental_merkle_tree.rs` - Merkle tree implementation
//! - `rln_registration.rs` - RLN registration with payment/credit flows
//!
//! ## Client-Side
//! Located in `src/bin/`. These are regular Rust binaries for building transactions to interact with the programs.
//! - `run_rln_proof.rs` - End-to-end RLN proof demo
//!
//! ## Shared (This Library)
//! Constants and utilities used by client-side code. Note that guest programs
//! maintain their own copies of constants due to different compilation targets.

pub mod merkle_tree;
pub mod rln;

// TODO: state_tests need updating for new LSSA API (V03State, Nonce newtype, etc.)
// #[cfg(test)]
// mod state_tests;
