//! PDA derivation for the merkle tree's main account.
//!
//! `tree_main` is a PDA of the **registration program's** id; the tree itself
//! lives in the merkle program's shard of it, which the registration program
//! grants through `pda_seeds` on its chained calls.
//!
//! Seed scheme: `compute_pda(SHA-256(label("main") || tree_id))`.

use nssa::AccountId;
use nssa_core::program::PdaSeed;

use crate::spel_seeds::{combine_seeds, label_seed};

/// Tree main account: `seeds = [literal("main"), arg("tree_id")]`.
pub fn derive_main_account(registration_program_id: &AccountId, tree_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(
        registration_program_id,
        &PdaSeed::new(main_pda_seed(tree_id)),
    )
}

/// Raw seed bytes for the tree main PDA.
pub fn main_pda_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_pdas_vary_by_tree() {
        let p = AccountId::new([1u8; 32]);
        assert_ne!(
            derive_main_account(&p, &[1u8; 32]),
            derive_main_account(&p, &[2u8; 32])
        );
    }

    #[test]
    fn raw_seed_matches_derived_account() {
        let p = AccountId::new([1u8; 32]);
        let t = [2u8; 32];
        assert_eq!(
            AccountId::for_public_pda(&p, &PdaSeed::new(main_pda_seed(&t))),
            derive_main_account(&p, &t),
        );
    }
}
