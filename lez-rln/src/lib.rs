//! Host-side library for the RLN (Rate Limiting Nullifier) zkVM programs.
//!
//! Companion code lives in two other places:
//! - `methods/guest/src/bin/` — zkVM guest programs compiled to RISC-V: `incremental_merkle_tree`
//!   (storage) and `rln_registration` (control).
//! - `src/bin/` — host CLIs (`run_setup`, `register_member`, `run_rln_proof`) that drive a live
//!   sequencer using the helpers in this library.

pub mod merkle_tree;
pub mod rln;
pub mod spel_seeds;

#[cfg(all(test, feature = "rc5-state-tests"))]
mod state_tests;
