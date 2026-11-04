//! Guest crate for the RLN registration and incremental merkle tree zkVM
//! programs.
//!
//! [`program`] holds the registration program's message handler;
//! [`merkle_tree`] the merkle program's; the binaries in `src/bin/` wire each
//! into `lee_core::actor_entrypoint!`.

pub mod fail;
pub mod hash;
pub mod layouts;
pub mod merkle_tree;
pub mod program;
pub mod registration;
