//! Guest crate for the RLN registration zkVM programs.
//!
//! Pure handler logic lives in [`handlers`]; [`program`] holds the SPEL macro
//! wiring plus the `#[account_type]` struct definitions the framework scans.

pub mod handlers;
pub mod hash;
pub mod layouts;
pub mod merkle_tree;
pub mod program;
pub mod registration;
