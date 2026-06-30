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
    pub payment_token_id: [u8; 32],
    pub receipt_token_id: [u8; 32],
    pub price_per_unit: u128,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships: u32,
    pub grace_period_duration_for_new_memberships: u32,
    pub token_program_id: [u8; 32],
}

impl ConfigState {
    pub(crate) fn can_register(&self, rate_limit: u64) -> bool {
        self.current_total_rate_limit
            .saturating_add(rate_limit)
            <= self.max_total_rate_limit
    }
}

// Guard against silent drift between this `#[account_type]` and the shared
// `rln_layouts::ConfigState` that the host uses to compute byte offsets.
const _: () = {
    assert!(core::mem::size_of::<ConfigState>() == core::mem::size_of::<SharedConfigState>());
};

#[account_type]
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct MembershipState {
    pub leaf_index: u64,
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    pub grace_period_start_timestamp: u64,
    pub active_duration: u32,
    pub grace_period_duration: u32,
}

const _: () = {
    assert!(
        core::mem::size_of::<MembershipState>() == core::mem::size_of::<SharedMembershipState>()
    );
};

#[lez_program(instruction = "rln_layouts::Instruction")]
pub mod rln_registration {
    #[allow(unused_imports)]
    use super::*;

    #[instruction]
    pub fn initialize(
        #[account(init, pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("receipt"), arg("tree_id")])]
        credit_token: AccountWithMetadata,
        merkle_program_id: [u8; 32],
        token_program_id: [u8; 32],
        tree_id: [u8; 32],
        payment_token_id: [u8; 32],
        price_per_unit: u128,
        treasury_account_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships: u32,
        grace_period_duration_for_new_memberships: u32,
    ) -> SpelResult {
        Ok(handlers::initialize(
            config,
            credit_token,
            merkle_program_id,
            token_program_id,
            tree_id,
            payment_token_id,
            price_per_unit,
            treasury_account_id,
            max_total_rate_limit,
            active_duration_for_new_memberships,
            grace_period_duration_for_new_memberships,
        ))
    }

    #[instruction]
    pub fn initialize_credit_token(
        #[account(pda = [literal("receipt"), arg("tree_id")])]
        credit_token: AccountWithMetadata,
        #[account(pda = [literal("supply"), arg("tree_id")])]
        credit_supply: AccountWithMetadata,
        token_program_id: [u8; 32],
        tree_id: [u8; 32],
    ) -> SpelResult {
        Ok(handlers::initialize_credit_token(
            credit_token,
            credit_supply,
            token_program_id,
            tree_id,
        ))
    }

    #[instruction]
    pub fn initialize_merkle_tree(
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        merkle_program_id: [u8; 32],
        tree_id: [u8; 32],
    ) -> SpelResult {
        Ok(handlers::initialize_merkle_tree(
            tree_main,
            merkle_program_id,
            tree_id,
        ))
    }

    #[instruction]
    pub fn register(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(signer)]
        user_holding: AccountWithMetadata,
        treasury_holding: AccountWithMetadata,
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
            user_holding,
            treasury_holding,
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
    pub fn buy_credits(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("receipt"), arg("tree_id")])]
        credit_token_def: AccountWithMetadata,
        #[account(signer)]
        user_payment_holding: AccountWithMetadata,
        treasury_holding: AccountWithMetadata,
        user_credit_holding: AccountWithMetadata,
        tree_id: [u8; 32],
        amount: u128,
    ) -> SpelResult {
        Ok(handlers::buy_credits(
            config,
            credit_token_def,
            user_payment_holding,
            treasury_holding,
            user_credit_holding,
            tree_id,
            amount,
        ))
    }

    #[instruction]
    pub fn register_with_credits(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("receipt"), arg("tree_id")])]
        credit_token_def: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(signer)]
        user_credit_holding: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        #[account(init, pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        amount_to_burn: u64,
        subtree_id: u32,
    ) -> SpelResult {
        Ok(handlers::register_with_credits(
            config,
            credit_token_def,
            tree_main,
            user_credit_holding,
            bottom_subtree,
            clock_account,
            membership,
            tree_id,
            id_commitment,
            amount_to_burn,
            subtree_id,
        ))
    }

    #[instruction]
    pub fn slash(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
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
            tree_id,
            id_commitment,
            identity_secret,
            subtree_id,
        ))
    }

    #[instruction]
    pub fn extend(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
    ) -> SpelResult {
        let _ = id_commitment; // declared so the macro resolves the membership PDA seed
        Ok(handlers::extend(config, membership, clock_account, tree_id))
    }

    #[instruction]
    pub fn erase(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        membership: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        clock_account: AccountWithMetadata,
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
            tree_id,
            subtree_id,
        ))
    }
}
