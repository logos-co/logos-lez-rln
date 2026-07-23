//! PDA derivation for the merkle tree's main and subtree accounts.
//!
//! These PDAs live under the **registration program's** ID — the merkle tree
//! program never owns its own data accounts; it operates on accounts that the
//! registration program claims via `pda_seeds` chained-call authorization.
//!
//! Seed scheme matches what the SPEL `rln_registration` declares for its
//! `init` constraints: `compute_pda(SHA-256(label || tree_id [|| subtree_id]))`.

use nssa::AccountId;
use nssa_core::program::{PdaSeed, ProgramId};

use crate::spel_seeds::{combine_seeds, label_seed, u32_seed};

/// Tree main account: `seeds = [literal("main"), arg("tree_id")]`.
pub fn derive_main_account(program_id: &ProgramId, tree_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(
        program_id,
        &PdaSeed::new(combine_seeds(&[&label_seed("main"), tree_id])),
    )
}

/// Bottom subtree: `seeds = [literal("subtree"), arg("tree_id"), arg("subtree_id")]`.
pub fn derive_subtree_account(
    program_id: &ProgramId,
    tree_id: &[u8; 32],
    subtree_id: u32,
) -> AccountId {
    AccountId::for_public_pda(
        program_id,
        &PdaSeed::new(combine_seeds(&[
            &label_seed("subtree"),
            tree_id,
            &u32_seed(subtree_id),
        ])),
    )
}

/// Raw seed bytes for a subtree PDA (used in `pda_seeds` of chained calls).
pub fn subtree_pda_seed(tree_id: &[u8; 32], subtree_id: u32) -> [u8; 32] {
    combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)])
}

/// Raw seed bytes for the tree main PDA.
pub fn main_pda_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_program_id() -> ProgramId {
        bytemuck::cast([1u8; 32])
    }

    #[test]
    fn subtree_pdas_vary_by_id() {
        let p = mock_program_id();
        let t = [1u8; 32];
        assert_ne!(
            derive_subtree_account(&p, &t, 0),
            derive_subtree_account(&p, &t, 1)
        );
    }

    #[test]
    fn main_and_subtree_are_distinct() {
        let p = mock_program_id();
        let t = [1u8; 32];
        assert_ne!(
            derive_main_account(&p, &t),
            derive_subtree_account(&p, &t, 0)
        );
    }

    #[test]
    fn raw_seeds_match_derived_accounts() {
        let p = mock_program_id();
        let t = [2u8; 32];
        assert_eq!(
            AccountId::for_public_pda(&p, &PdaSeed::new(main_pda_seed(&t))),
            derive_main_account(&p, &t),
        );
        assert_eq!(
            AccountId::for_public_pda(&p, &PdaSeed::new(subtree_pda_seed(&t, 7))),
            derive_subtree_account(&p, &t, 7),
        );
    }
}
