//! RLN Registration client code.
//!
//! This module provides constants, PDA derivation, and helpers
//! for building RLN registration transactions.
//!
//! # Module Structure
//!
//! - [`constants`] - Layout-derived constants (offsets, sizes) and re-exports from `rln-layouts`
//! - [`layouts`] - Re-exports types from `rln-layouts` crate (account layouts + `Instruction` enum)
//! - [`pda`] - PDA (Program Derived Account) derivation functions
//!
//! # Shared Code
//!
//! Constants and layouts are shared between host and guest via the `rln-layouts` crate,
//! which is `no_std` compatible for use in zkVM guest programs.

pub mod client;
pub mod constants;
pub mod layouts;
pub mod pda;

// Re-export commonly used items at module root for convenience
pub use constants::*;
pub use pda::*;
