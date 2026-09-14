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

/// Derive a PDA account ID from a program's account id and a list of 32-byte
/// seeds.
///
/// v0.2.5 addresses a program by the account its header was deployed to rather
/// than by its image id. The derivation itself is unchanged: the preimage is
/// the same 32 bytes followed by the same combined seed.
pub fn derive_pda(program_id: &AccountId, seeds: &[&[u8; 32]]) -> AccountId {
    AccountId::for_public_pda(program_id, &PdaSeed::new(combine_seeds(seeds)))
}

/// The account a program's header is deployed to.
///
/// v0.2.5 lets a deployer put a program at any unclaimed address. We keep
/// using the one v0.2.2 derived from the image id so a program stays
/// content-addressed and nothing downstream has to carry its address as
/// state. `send_deploy_tx` is what actually lands the header there; this is
/// the shared answer everything else derives from.
pub fn program_account(program_id: &ProgramId) -> AccountId {
    AccountId::from(*program_id)
}
