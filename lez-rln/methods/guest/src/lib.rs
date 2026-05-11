//! Guest crate for the RLN registration zkVM programs.
//!
//! [`program`] hosts the SPEL program; the macro emits `main()` and the
//! `Instruction` enum at the module level (alongside the user-defined
//! `rln_registration` submodule that holds the handler fns).

pub mod hash;
pub mod layouts;
pub mod merkle_tree;
pub mod program;
pub mod registration;
