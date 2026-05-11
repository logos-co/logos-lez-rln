//! SPEL-style PDA seed primitives shared across modules.
//!
//! Leaf module with no internal dependencies. Both `rln::pda` and
//! `merkle_tree::pda` build their derivations on these helpers. The seed
//! primitives themselves are now defined in `rln-layouts` so the same code
//! can be shared with the guest binary; this module re-exports them and adds
//! the host-only `derive_pda` (which depends on `nssa` types not available
//! in the no_std layouts crate).

use nssa::AccountId;
use nssa_core::program::{PdaSeed, ProgramId};

pub use rln_layouts::{combine_seeds, label_seed, u32_seed};

/// Derive a PDA account ID from program_id and a list of 32-byte seeds.
pub fn derive_pda(program_id: &ProgramId, seeds: &[&[u8; 32]]) -> AccountId {
    AccountId::for_public_pda(program_id, &PdaSeed::new(combine_seeds(seeds)))
}
