//! PDA (Program Derived Account) derivation for RLN registration.
//!
//! Seed construction is defined in `rln-layouts` (shared with guest).

use nssa::AccountId;
use nssa_core::program::{PdaSeed, ProgramId};

// Re-export tree PDAs from the merkle_tree module (canonical definitions)
pub use crate::merkle_tree::{
    derive_main_account as derive_tree_main_account,
    derive_subtree_account,
};

/// Derive config account for a registration program.
pub fn derive_config_account(program_id: &ProgramId, tree_id: &[u8; 24]) -> AccountId {
    AccountId::from((program_id, &PdaSeed::new(rln_layouts::config_seed(tree_id))))
}

/// Derive credit token definition account.
pub fn derive_credit_token_account(program_id: &ProgramId, tree_id: &[u8; 24]) -> AccountId {
    AccountId::from((program_id, &PdaSeed::new(rln_layouts::credit_token_seed(tree_id))))
}

/// Derive credit supply holder account.
pub fn derive_credit_supply_account(program_id: &ProgramId, tree_id: &[u8; 24]) -> AccountId {
    AccountId::from((program_id, &PdaSeed::new(rln_layouts::credit_supply_seed(tree_id))))
}

/// Derive membership account for a registered identity.
///
/// The seed is derived by hashing (tree_id || id_commitment) to create a unique
/// 32-byte seed for each (tree_id, id_commitment) pair.
pub fn derive_membership_account(
    program_id: &ProgramId,
    tree_id: &[u8; 24],
    id_commitment: &[u8; 32],
) -> AccountId {
    let seed = membership_pda_seed(tree_id, id_commitment);
    AccountId::from((program_id, &PdaSeed::new(seed)))
}

/// Build the PDA seed for a membership account.
///
/// This returns the 32-byte seed that can be used as a PdaSeed for
/// authorization when tail-calling to modify the membership account.
pub fn membership_pda_seed(tree_id: &[u8; 24], id_commitment: &[u8; 32]) -> [u8; 32] {
    use rln::hashers::poseidon_hash;
    use rln::utils::{bytes_le_to_fr, fr_to_bytes_le};

    let mut tree_id_padded = [0u8; 32];
    tree_id_padded[0..24].copy_from_slice(tree_id);

    let (tree_fr, _) = bytes_le_to_fr(&tree_id_padded).expect("Invalid tree_id bytes");
    let (commit_fr, _) = bytes_le_to_fr(id_commitment).expect("Invalid id_commitment bytes");

    let seed_fr = poseidon_hash(&[tree_fr, commit_fr]).expect("Poseidon hash failed");
    fr_to_bytes_le(&seed_fr).try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_program_id() -> ProgramId {
        let bytes: [u8; 32] = [1u8; 32];
        bytemuck::cast(bytes)
    }

    #[test]
    fn test_pda_derivation_is_deterministic() {
        let program_id = mock_program_id();
        let tree_id: [u8; 24] = [2u8; 24];

        let pda1 = derive_config_account(&program_id, &tree_id);
        let pda2 = derive_config_account(&program_id, &tree_id);

        assert_eq!(pda1, pda2, "PDA derivation should be deterministic");
    }

    #[test]
    fn test_different_tree_ids_produce_different_pdas() {
        let program_id = mock_program_id();
        let tree_id1: [u8; 24] = [1u8; 24];
        let tree_id2: [u8; 24] = [2u8; 24];

        let pda1 = derive_config_account(&program_id, &tree_id1);
        let pda2 = derive_config_account(&program_id, &tree_id2);

        assert_ne!(pda1, pda2, "Different tree IDs should produce different PDAs");
    }

    #[test]
    fn test_all_pda_types_are_distinct() {
        let program_id = mock_program_id();
        let tree_id: [u8; 24] = [1u8; 24];

        let config = derive_config_account(&program_id, &tree_id);
        let main = derive_tree_main_account(&program_id, &tree_id);
        let credit = derive_credit_token_account(&program_id, &tree_id);
        let supply = derive_credit_supply_account(&program_id, &tree_id);
        let subtree = derive_subtree_account(&program_id, &tree_id, 0);

        assert_ne!(config, main, "config and main should differ");
        assert_ne!(config, credit, "config and credit should differ");
        assert_ne!(config, supply, "config and supply should differ");
        assert_ne!(config, subtree, "config and subtree should differ");
        assert_ne!(main, credit, "main and credit should differ");
        assert_ne!(main, supply, "main and supply should differ");
        assert_ne!(main, subtree, "main and subtree should differ");
        assert_ne!(credit, supply, "credit and supply should differ");
        assert_ne!(credit, subtree, "credit and subtree should differ");
        assert_ne!(supply, subtree, "supply and subtree should differ");
    }

    #[test]
    fn test_subtree_pdas_vary_by_id() {
        let program_id = mock_program_id();
        let tree_id: [u8; 24] = [1u8; 24];

        let subtree_0 = derive_subtree_account(&program_id, &tree_id, 0);
        let subtree_1 = derive_subtree_account(&program_id, &tree_id, 1);

        assert_ne!(subtree_0, subtree_1, "Different subtree IDs should differ");
    }

    #[test]
    fn test_membership_pda_derivation_is_deterministic() {
        let program_id = mock_program_id();
        let tree_id: [u8; 24] = [1u8; 24];
        let id_commitment: [u8; 32] = [2u8; 32];

        let pda1 = derive_membership_account(&program_id, &tree_id, &id_commitment);
        let pda2 = derive_membership_account(&program_id, &tree_id, &id_commitment);

        assert_eq!(pda1, pda2, "PDA derivation should be deterministic");
    }

    #[test]
    fn test_membership_pdas_differ_by_commitment() {
        let program_id = mock_program_id();
        let tree_id: [u8; 24] = [1u8; 24];
        let commit1: [u8; 32] = [1u8; 32];
        let commit2: [u8; 32] = [2u8; 32];

        let pda1 = derive_membership_account(&program_id, &tree_id, &commit1);
        let pda2 = derive_membership_account(&program_id, &tree_id, &commit2);

        assert_ne!(pda1, pda2, "Different commitments should produce different PDAs");
    }

    #[test]
    fn test_membership_pdas_differ_by_tree() {
        let program_id = mock_program_id();
        let tree_id1: [u8; 24] = [1u8; 24];
        let tree_id2: [u8; 24] = [2u8; 24];
        let id_commitment: [u8; 32] = [3u8; 32];

        let pda1 = derive_membership_account(&program_id, &tree_id1, &id_commitment);
        let pda2 = derive_membership_account(&program_id, &tree_id2, &id_commitment);

        assert_ne!(pda1, pda2, "Different trees should produce different PDAs");
    }

    #[test]
    fn test_membership_pda_distinct_from_other_pdas() {
        let program_id = mock_program_id();
        let tree_id: [u8; 24] = [1u8; 24];
        let id_commitment: [u8; 32] = [2u8; 32];

        let membership = derive_membership_account(&program_id, &tree_id, &id_commitment);
        let config = derive_config_account(&program_id, &tree_id);
        let main = derive_tree_main_account(&program_id, &tree_id);
        let credit = derive_credit_token_account(&program_id, &tree_id);

        assert_ne!(membership, config, "membership and config should differ");
        assert_ne!(membership, main, "membership and main should differ");
        assert_ne!(membership, credit, "membership and credit should differ");
    }
}
