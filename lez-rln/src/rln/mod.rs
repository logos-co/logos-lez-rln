//! Host-side client for the RLN registration program: PDAs, layout offsets,
//! and transaction-building helpers. The `Instruction` enum is re-exported
//! straight from the guest crate (macro-emitted) so host and guest can't drift.

pub mod client;
pub mod constants;
pub mod layouts;
pub mod pda;

pub use constants::*;
pub use logos_lez_rln_guest::program::Instruction;
pub use pda::*;
