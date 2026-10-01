//! Guest crate for the RLN registration and incremental merkle tree zkVM
//! programs.
//!
//! [`program`] holds the registration program's plan and apply;
//! [`merkle_tree`] the merkle program's; the binaries in `src/bin/` wire each
//! into `run_program`.

pub mod hash;
pub mod layouts;
pub mod merkle_tree;
pub mod program;
pub mod registration;
