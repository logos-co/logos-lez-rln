//! SPEL macro wiring for the RLN registration program.
//!
//! `ConfigState` / `MembershipState` live here because the `#[account_type]`
//! marker must be at the same scope as `#[lez_program]` for the IDL scanner
//! to find them. All business logic is in `crate::handlers`; each
//! `#[instruction]` body below is a thin delegate.

use borsh::{BorshDeserialize, BorshSerialize};
use rln_layouts::{ConfigState as SharedConfigState, MembershipState as SharedMembershipState};
use spel_framework::prelude::*;

use crate::handlers;

#[account_type]
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct ConfigState {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub price_per_unit: u128,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships_sec: u32,
    pub grace_period_duration_for_new_memberships_sec: u32,
}

impl ConfigState {
    pub(crate) fn can_register(&self, rate_limit: u64) -> bool {
        self.current_total_rate_limit.saturating_add(rate_limit) <= self.max_total_rate_limit
    }
}

// These structs are duplicated (not a re-export of `rln_layouts`) on purpose:
// the SPEL IDL scanner only picks up literal `#[account_type]` struct items with
// named fields declared in this scope — a `pub use`/type alias is invisible to
// it — and `impl ConfigState` (below) is an inherent impl that must live in the
// crate that owns the type. The compile-time `size_of` assert catches gross
// drift; the `#[cfg(test)] layout_equivalence` tests below catch *field-level*
// drift (order / type changes) by proving the Borsh byte layout is identical to
// `rln_layouts`, which is the consensus-critical property the host depends on.
const _: () = {
    assert!(core::mem::size_of::<ConfigState>() == core::mem::size_of::<SharedConfigState>());
};

#[account_type]
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct MembershipState {
    pub leaf_index: u64,
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    pub grace_period_start_timestamp_ms: u64,
    pub active_duration_sec: u32,
    pub grace_period_duration_sec: u32,
    pub holder: [u8; 32],
    pub deposit_amount: u128,
    pub exiting: u8,
}

const _: () = {
    assert!(
        core::mem::size_of::<MembershipState>() == core::mem::size_of::<SharedMembershipState>()
    );
};

// Field-level drift guard: prove that the local `#[account_type]` structs and the
// shared `rln_layouts` structs serialize to byte-identical Borsh, using distinct
// per-field values so any reorder or type change is observable. Borsh encodes in
// field declaration order, so equal bytes for distinct values implies identical
// field order + widths — the exact layout the host reads via offset constants.
#[cfg(test)]
mod layout_equivalence {
    use super::*;

    #[test]
    fn config_state_borsh_layout_matches_shared() {
        let local = ConfigState {
            merkle_program_id: [1u8; 32],
            tree_id: [2u8; 32],
            price_per_unit: 5,
            treasury_account_id: [6u8; 32],
            total_registrations: 7,
            max_total_rate_limit: 8,
            current_total_rate_limit: 9,
            active_duration_for_new_memberships_sec: 10,
            grace_period_duration_for_new_memberships_sec: 11,
        };
        let shared = SharedConfigState {
            merkle_program_id: [1u8; 32],
            tree_id: [2u8; 32],
            price_per_unit: 5,
            treasury_account_id: [6u8; 32],
            total_registrations: 7,
            max_total_rate_limit: 8,
            current_total_rate_limit: 9,
            active_duration_for_new_memberships_sec: 10,
            grace_period_duration_for_new_memberships_sec: 11,
        };
        assert_eq!(
            borsh::to_vec(&local).unwrap(),
            borsh::to_vec(&shared).unwrap(),
            "ConfigState Borsh layout drifted from rln_layouts::ConfigState"
        );
    }

    #[test]
    fn membership_state_borsh_layout_matches_shared() {
        let local = MembershipState {
            leaf_index: 1,
            rate_limit: 2,
            id_commitment: [3u8; 32],
            grace_period_start_timestamp_ms: 4,
            active_duration_sec: 5,
            grace_period_duration_sec: 6,
            holder: [7u8; 32],
            deposit_amount: 8,
            exiting: 9,
        };
        let shared = SharedMembershipState {
            leaf_index: 1,
            rate_limit: 2,
            id_commitment: [3u8; 32],
            grace_period_start_timestamp_ms: 4,
            active_duration_sec: 5,
            grace_period_duration_sec: 6,
            holder: [7u8; 32],
            deposit_amount: 8,
            exiting: 9,
        };
        assert_eq!(
            borsh::to_vec(&local).unwrap(),
            borsh::to_vec(&shared).unwrap(),
            "MembershipState Borsh layout drifted from rln_layouts::MembershipState"
        );
    }
}

#[lez_program(instruction = "rln_layouts::Instruction")]
pub mod rln_registration {
    #[allow(unused_imports)]
    use super::*;

    #[instruction]
    pub fn initialize(
        #[account(init, pda = [literal("config"), arg("tree_id")])] config: AccountWithMetadata,
        merkle_program_id: [u8; 32],
        tree_id: [u8; 32],
        price_per_unit: u128,
        treasury_account_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships_sec: u32,
        grace_period_duration_for_new_memberships_sec: u32,
    ) -> SpelResult {
        Ok(handlers::initialize(
            config,
            merkle_program_id,
            tree_id,
            price_per_unit,
            treasury_account_id,
            max_total_rate_limit,
            active_duration_for_new_memberships_sec,
            grace_period_duration_for_new_memberships_sec,
        ))
    }

    #[instruction]
    pub fn initialize_merkle_tree(
        #[account(pda = [literal("config"), arg("tree_id")])] config: AccountWithMetadata,
        #[account(init, pda = [literal("main"), arg("tree_id")])] tree_main: AccountWithMetadata,
        tree_id: [u8; 32],
    ) -> SpelResult {
        Ok(handlers::initialize_merkle_tree(config, tree_main, tree_id))
    }

    #[instruction]
    pub fn register(
        #[account(pda = [literal("config"), arg("tree_id")])] config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])] tree_main: AccountWithMetadata,
        #[account(signer)] payer: AccountWithMetadata,
        #[account(pda = [literal("escrow"), arg("tree_id")])] escrow: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        #[account(init, pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        subtree_id: u32,
    ) -> SpelResult {
        Ok(handlers::register(
            config,
            tree_main,
            payer,
            escrow,
            bottom_subtree,
            clock_account,
            membership,
            tree_id,
            id_commitment,
            rate_limit,
            subtree_id,
        ))
    }

    #[instruction]
    pub fn slash(
        #[account(pda = [literal("config"), arg("tree_id")])] config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])] tree_main: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        #[account(pda = [literal("escrow"), arg("tree_id")])] escrow: AccountWithMetadata,
        treasury: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        identity_secret: [u8; 32],
        subtree_id: u32,
    ) -> SpelResult {
        Ok(handlers::slash(
            config,
            tree_main,
            membership,
            bottom_subtree,
            escrow,
            treasury,
            tree_id,
            id_commitment,
            identity_secret,
            subtree_id,
        ))
    }

    #[instruction]
    pub fn extend(
        #[account(pda = [literal("config"), arg("tree_id")])] config: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        #[account(signer)] payer: AccountWithMetadata,
        treasury: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
    ) -> SpelResult {
        let _ = id_commitment; // PDA seed only; consumed by the #[account] macro
        Ok(handlers::extend(
            config,
            membership,
            payer,
            treasury,
            clock_account,
            tree_id,
        ))
    }

    #[instruction]
    pub fn erase(
        #[account(pda = [literal("config"), arg("tree_id")])] config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])] tree_main: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        #[account(pda = [literal("escrow"), arg("tree_id")])] escrow: AccountWithMetadata,
        holder: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        subtree_id: u32,
    ) -> SpelResult {
        let _ = id_commitment;
        Ok(handlers::erase(
            config,
            tree_main,
            membership,
            bottom_subtree,
            clock_account,
            escrow,
            holder,
            tree_id,
            subtree_id,
        ))
    }

    #[instruction]
    pub fn force_expire(
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        #[account(signer)] holder: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
    ) -> SpelResult {
        // Both are PDA seeds only; the membership account they derive is what
        // binds this call to a tree.
        let _ = (tree_id, id_commitment);
        Ok(handlers::force_expire(membership, holder, clock_account))
    }
}
