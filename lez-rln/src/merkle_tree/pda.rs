//! PDA (Program Derived Account) derivation for the Merkle tree.
//!
//! Seed construction is defined in `rln-layouts` (shared with guest).

use nssa::AccountId;
use nssa_core::program::{PdaSeed, ProgramId};

/// Derives the main tree account ID.
pub fn derive_main_account(program_id: &ProgramId, tree_id: &[u8; 24]) -> AccountId {
    AccountId::from((program_id, &PdaSeed::new(rln_layouts::main_seed(tree_id))))
}

/// Derives a bottom subtree account ID.
pub fn derive_subtree_account(
    program_id: &ProgramId,
    tree_id: &[u8; 24],
    subtree_id: u32,
) -> AccountId {
    AccountId::from((program_id, &PdaSeed::new(rln_layouts::subtree_seed(tree_id, subtree_id))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_program_id() -> ProgramId {
        let bytes: [u8; 32] = [1u8; 32];
        bytemuck::cast(bytes)
    }

    #[test]
    fn test_seed_layout() {
        let tree_id = [0u8; 24];
        let main = rln_layouts::main_seed(&tree_id);
        assert_eq!(&main[24..32], b"__main__");

        let subtree = rln_layouts::subtree_seed(&tree_id, 10);
        assert_eq!(subtree[24], 0xFF);
        assert_eq!(&subtree[25..29], &10u32.to_le_bytes());
    }

    #[test]
    fn test_subtree_pdas_vary_by_id() {
        let program_id = mock_program_id();
        let tree_id = [1u8; 24];

        let subtree_0 = derive_subtree_account(&program_id, &tree_id, 0);
        let subtree_1 = derive_subtree_account(&program_id, &tree_id, 1);

        assert_ne!(subtree_0, subtree_1, "Different subtree IDs should have different PDAs");
    }

    #[test]
    fn test_main_and_subtree_are_distinct() {
        let program_id = mock_program_id();
        let tree_id = [1u8; 24];

        let main = derive_main_account(&program_id, &tree_id);
        let subtree = derive_subtree_account(&program_id, &tree_id, 0);

        assert_ne!(main, subtree, "Main and subtree should have different PDAs");
    }
}
