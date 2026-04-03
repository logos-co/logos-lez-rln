//! Zero-copy binary layouts for instruction data.
//!
//! This module re-exports layouts from the shared `rln-layouts` crate.
//! All types are no_std compatible for use in zkVM guest programs.

// Re-export everything from the shared crate
pub use rln_layouts::*;
