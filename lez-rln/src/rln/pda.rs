//! Program-Derived Account derivations for the RLN registration program.
//!
//! Every PDA address is `compute_pda(SHA-256(seed_1 || seed_2 || ...))` where
//! each seed is a 32-byte value: string labels are zero-padded, `u32` args are
//! little-endian in the first 4 bytes, 32-byte args pass through.

use nssa::AccountId;
use nssa_core::program::ProgramId;

// The tree main and subtree PDAs sit under the registration program's id (the
// merkle program never owns its own data accounts), but their canonical
// derivation lives next to the merkle program's other client code.
pub use crate::merkle_tree::{
    derive_main_account as derive_tree_main_account, derive_subtree_account,
};
// `spel_seeds` is a leaf module so both this and `merkle_tree::pda` can depend
// on it without a cross-module cycle.
pub use crate::spel_seeds::{combine_seeds, derive_pda, label_seed, u32_seed};

/// Config account: `seeds = [literal("config"), arg("tree_id")]`.
pub fn derive_config_account(program_id: &ProgramId, tree_id: &[u8; 32]) -> AccountId {
    derive_pda(program_id, &[&label_seed("config"), tree_id])
}

/// Credit (receipt) token definition: `seeds = [literal("receipt"), arg("tree_id")]`.
pub fn derive_credit_token_account(program_id: &ProgramId, tree_id: &[u8; 32]) -> AccountId {
    derive_pda(program_id, &[&label_seed("receipt"), tree_id])
}

/// Credit supply holder: `seeds = [literal("supply"), arg("tree_id")]`.
pub fn derive_credit_supply_account(program_id: &ProgramId, tree_id: &[u8; 32]) -> AccountId {
    derive_pda(program_id, &[&label_seed("supply"), tree_id])
}

/// Payment token definition (faucet deployments): `seeds = [literal("payment"), arg("tree_id")]`.
pub fn derive_payment_token_account(program_id: &ProgramId, tree_id: &[u8; 32]) -> AccountId {
    derive_pda(program_id, &[&label_seed("payment"), tree_id])
}

/// Payment token supply holder (faucet deployments): `seeds = [literal("payment_supply"),
/// arg("tree_id")]`.
pub fn derive_payment_supply_account(program_id: &ProgramId, tree_id: &[u8; 32]) -> AccountId {
    derive_pda(program_id, &[&label_seed("payment_supply"), tree_id])
}

/// Membership account: `seeds = [literal("membership"), arg("tree_id"), arg("id_commitment")]`.
pub fn derive_membership_account(
    program_id: &ProgramId,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
) -> AccountId {
    derive_pda(
        program_id,
        &[&label_seed("membership"), tree_id, id_commitment],
    )
}

/// Raw seed bytes for the membership PDA (used as `pda_seeds` in chained calls).
pub fn membership_pda_seed(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("membership"), tree_id, id_commitment])
}

#[cfg(test)]
mod tests {
    use nssa_core::program::PdaSeed;

    use super::*;

    fn mock_program_id() -> ProgramId {
        bytemuck::cast([1u8; 32])
    }

    fn tree_id_a() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = 7;
        t
    }

    #[test]
    fn pda_derivation_is_deterministic() {
        let p = mock_program_id();
        let t = tree_id_a();
        assert_eq!(derive_config_account(&p, &t), derive_config_account(&p, &t));
        assert_eq!(
            derive_membership_account(&p, &t, &[2u8; 32]),
            derive_membership_account(&p, &t, &[2u8; 32]),
        );
    }

    #[test]
    fn different_tree_ids_produce_different_pdas() {
        let p = mock_program_id();
        let mut t2 = tree_id_a();
        t2[1] = 9;
        assert_ne!(
            derive_config_account(&p, &tree_id_a()),
            derive_config_account(&p, &t2)
        );
    }

    #[test]
    fn all_pda_types_are_distinct() {
        let p = mock_program_id();
        let t = tree_id_a();
        let config = derive_config_account(&p, &t);
        let main = derive_tree_main_account(&p, &t);
        let credit = derive_credit_token_account(&p, &t);
        let supply = derive_credit_supply_account(&p, &t);
        let payment = derive_payment_token_account(&p, &t);
        let payment_supply = derive_payment_supply_account(&p, &t);
        let subtree = derive_subtree_account(&p, &t, 0);
        let mem = derive_membership_account(&p, &t, &[3u8; 32]);
        let all = [
            &config,
            &main,
            &credit,
            &supply,
            &payment,
            &payment_supply,
            &subtree,
            &mem,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "PDA types must be distinct");
            }
        }
    }

    #[test]
    fn membership_pdas_differ_by_commitment() {
        let p = mock_program_id();
        let t = tree_id_a();
        assert_ne!(
            derive_membership_account(&p, &t, &[1u8; 32]),
            derive_membership_account(&p, &t, &[2u8; 32]),
        );
    }

    #[test]
    fn membership_pdas_differ_by_tree() {
        let p = mock_program_id();
        let mut t2 = tree_id_a();
        t2[1] = 9;
        assert_ne!(
            derive_membership_account(&p, &tree_id_a(), &[5u8; 32]),
            derive_membership_account(&p, &t2, &[5u8; 32]),
        );
    }

    #[test]
    fn membership_seed_matches_derive() {
        let p = mock_program_id();
        let t = tree_id_a();
        let id = [4u8; 32];
        let seed = membership_pda_seed(&t, &id);
        let from_seed = AccountId::for_public_pda(&p, &PdaSeed::new(seed));
        assert_eq!(from_seed, derive_membership_account(&p, &t, &id));
    }
}
