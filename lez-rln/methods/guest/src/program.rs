//! RLN registration guest program — 7 SPEL instructions covering setup,
//! direct-payment and credit-burn registration, slash, extend, and erase.

use borsh::{BorshDeserialize, BorshSerialize};
use crate::hash::{hash_single, validate_field_element};
use crate::registration::{
    calculate_payment_amount, compute_registration_leaf, parse_token_holding, read_tree_next_index,
    require_clock, validate_rate_limit,
};
use rln_layouts::{
    combine_seeds, is_expired, is_in_grace_period, label_seed, u32_seed,
    ConfigState as SharedConfigState, MembershipState as SharedMembershipState, MerkleOpcode,
    SUBTREE_LEAVES,
};
use spel_framework::prelude::*;

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
    fn can_register(&self, rate_limit: u64) -> bool {
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

/// Compute the merkle program's tree-main PDA seed from tree_id (under SPEL).
fn main_seed_for(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

/// Compute the merkle program's subtree PDA seed under SPEL.
fn subtree_seed_for(tree_id: &[u8; 32], subtree_id: u32) -> [u8; 32] {
    combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)])
}

/// Build an authorized chained call to the merkle program (tree_main + subtree).
/// `payload` is the merkle program's instruction body (pre-`risc0_zkvm::serde`).
/// Used by the four sites that insert/remove via chained calls (register,
/// register_with_credits, slash, erase).
fn merkle_chained_call(
    merkle_program_id: [u8; 32],
    tree_main: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    tree_id: &[u8; 32],
    subtree_id: u32,
    payload: Vec<u8>,
    serde_err: &'static str,
) -> ChainedCall {
    let mut tree_main_auth = tree_main.clone();
    tree_main_auth.is_authorized = true;
    let mut subtree_auth = bottom_subtree.clone();
    subtree_auth.is_authorized = true;
    ChainedCall {
        program_id: bytemuck::cast(merkle_program_id),
        pre_states: vec![tree_main_auth, subtree_auth],
        instruction_data: risc0_zkvm::serde::to_vec(&payload).expect(serde_err),
        pda_seeds: vec![
            PdaSeed::new(main_seed_for(tree_id)),
            PdaSeed::new(subtree_seed_for(tree_id, subtree_id)),
        ],
    }
}

fn merkle_insert_payload(next_index: u64, leaf_value: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(41);
    payload.push(MerkleOpcode::Insert as u8);
    payload.extend_from_slice(&next_index.to_le_bytes());
    payload.extend_from_slice(leaf_value);
    payload
}

fn merkle_remove_payload(leaf_index: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9);
    payload.push(MerkleOpcode::Remove as u8);
    payload.extend_from_slice(&leaf_index.to_le_bytes());
    payload
}

/// Build a fresh `MembershipState` for a new registration (used by both register
/// and register_with_credits).
fn new_membership_state(
    next_index: u64,
    rate_limit: u64,
    id_commitment: [u8; 32],
    grace_period_start_timestamp: u64,
    config_state: &ConfigState,
) -> MembershipState {
    MembershipState {
        leaf_index: next_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp,
        active_duration: config_state.active_duration_for_new_memberships,
        grace_period_duration: config_state.grace_period_duration_for_new_memberships,
    }
}

#[lez_program]
pub mod rln_registration {
    #[allow(unused_imports)]
    use super::*;

    /// Initialize a new RLN tree.
    ///
    /// Only `config` is claimed by us (`init`). The other three PDAs are
    /// declared with bare `pda = ...` (seed validation only) — they're claimed
    /// by the chained-call recipients (token program for credit_token+supply,
    /// merkle program for tree_main).
    #[instruction]
    pub fn initialize(
        #[account(init, pda = [literal("config"), arg("tree_id")])]
        mut config: AccountWithMetadata,
        #[account(pda = [literal("receipt"), arg("tree_id")])]
        credit_token: AccountWithMetadata,
        #[account(pda = [literal("supply"), arg("tree_id")])]
        credit_supply: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
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
        assert!(max_total_rate_limit > 0, "Max total rate limit must be positive");
        assert!(
            active_duration_for_new_memberships > 0,
            "Active duration must be positive"
        );

        let config_state = ConfigState {
            merkle_program_id,
            tree_id,
            payment_token_id,
            receipt_token_id: *credit_token.account_id.value(),
            price_per_unit,
            treasury_account_id,
            total_registrations: 0,
            max_total_rate_limit,
            current_total_rate_limit: 0,
            active_duration_for_new_memberships,
            grace_period_duration_for_new_memberships,
            token_program_id,
        };

        let config_bytes = borsh::to_vec(&config_state).expect("borsh serialize ConfigState");
        config.account.data = config_bytes
            .try_into()
            .expect("config data fits in account.data");

        let receipt_seed = combine_seeds(&[&label_seed("receipt"), &tree_id]);
        let supply_seed = combine_seeds(&[&label_seed("supply"), &tree_id]);
        let main_seed = main_seed_for(&tree_id);

        let mut credit_token_auth = credit_token.clone();
        credit_token_auth.is_authorized = true;
        let mut credit_supply_auth = credit_supply.clone();
        credit_supply_auth.is_authorized = true;
        let mut tree_main_auth = tree_main.clone();
        tree_main_auth.is_authorized = true;

        let token_create_instr = token_core::Instruction::NewFungibleDefinition {
            name: "RLNREC".to_string(),
            total_supply: 0,
        };
        let token_create_call = ChainedCall::new(
            bytemuck::cast(token_program_id),
            vec![credit_token_auth, credit_supply_auth],
            &token_create_instr,
        )
        .with_pda_seeds(vec![PdaSeed::new(receipt_seed), PdaSeed::new(supply_seed)]);

        let merkle_init_call = ChainedCall {
            program_id: bytemuck::cast(merkle_program_id),
            pre_states: vec![tree_main_auth],
            instruction_data: risc0_zkvm::serde::to_vec(&vec![MerkleOpcode::Initialize as u8])
                .expect("serialize merkle init"),
            pda_seeds: vec![PdaSeed::new(main_seed)],
        };

        Ok(SpelOutput::execute(
            vec![config, credit_token, credit_supply, tree_main],
            vec![token_create_call, merkle_init_call],
        ))
    }

    /// Direct-payment registration: pay tokens, claim membership, insert leaf.
    #[instruction]
    pub fn register(
        #[account(pda = [literal("config"), arg("tree_id")])]
        mut config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(signer)]
        user_holding: AccountWithMetadata,
        treasury_holding: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        #[account(init, pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        mut membership: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        rate_limit: u64,
        subtree_id: u32,
    ) -> SpelResult {
        validate_field_element(&id_commitment);
        validate_rate_limit(rate_limit);

        let mut config_state = ConfigState::try_from_slice(config.account.data.as_ref())
            .expect("decode ConfigState");
        assert_eq!(config_state.tree_id, tree_id, "tree_id arg must match config");
        assert!(config_state.can_register(rate_limit), "Would exceed max total rate limit");

        let now = require_clock(&clock_account);
        let grace_period_start_timestamp =
            now.saturating_add(config_state.active_duration_for_new_memberships as u64);
        let payment_amount = calculate_payment_amount(rate_limit, config_state.price_per_unit);

        assert!(user_holding.is_authorized, "User must authorize payment");
        let (user_token, user_balance) =
            parse_token_holding(user_holding.account.data.as_ref());
        assert_eq!(user_token, config_state.payment_token_id, "Wrong payment token");
        assert!(user_balance >= payment_amount, "Insufficient balance");

        let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
        assert_eq!(treasury_id, config_state.treasury_account_id, "Wrong treasury");

        let next_index = read_tree_next_index(tree_main.account.data.as_ref());
        let expected_subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
        assert_eq!(subtree_id, expected_subtree_id, "subtree_id arg must match next_index/SUBTREE_LEAVES");

        let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

        config_state.total_registrations = config_state.total_registrations.saturating_add(1);
        config_state.current_total_rate_limit =
            config_state.current_total_rate_limit.saturating_add(rate_limit);
        config.account.data = borsh::to_vec(&config_state)
            .expect("re-serialize ConfigState")
            .try_into()
            .expect("updated config fits");

        let membership_state = new_membership_state(
            next_index,
            rate_limit,
            id_commitment,
            grace_period_start_timestamp,
            &config_state,
        );
        membership.account.data = borsh::to_vec(&membership_state)
            .expect("borsh serialize MembershipState")
            .try_into()
            .expect("membership data fits");

        let mut user_holding_auth = user_holding.clone();
        user_holding_auth.is_authorized = true;
        let token_transfer_instr = token_core::Instruction::Transfer {
            amount_to_transfer: payment_amount,
        };
        let token_transfer_call = ChainedCall::new(
            user_holding.account.program_owner,
            vec![user_holding_auth, treasury_holding.clone()],
            &token_transfer_instr,
        );

        let merkle_insert_call = merkle_chained_call(
            config_state.merkle_program_id,
            &tree_main,
            &bottom_subtree,
            &tree_id,
            subtree_id,
            merkle_insert_payload(next_index, &leaf_value),
            "serialize merkle insert",
        );

        Ok(SpelOutput::execute(
            vec![
                config,
                tree_main,
                user_holding,
                treasury_holding,
                bottom_subtree,
                clock_account,
                membership,
            ],
            vec![token_transfer_call, merkle_insert_call],
        ))
    }

    /// Buy receipt-token credits with payment tokens.
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
        assert!(amount > 0, "Amount must be positive");

        let config_state = ConfigState::try_from_slice(config.account.data.as_ref())
            .expect("decode ConfigState");
        assert_eq!(config_state.tree_id, tree_id, "tree_id arg must match config");

        let payment_amount = config_state.price_per_unit.saturating_mul(amount);

        let receipt_def_id: [u8; 32] = *credit_token_def.account_id.value();
        assert_eq!(receipt_def_id, config_state.receipt_token_id, "Wrong receipt token definition");

        assert!(user_payment_holding.is_authorized, "User must authorize payment");
        let (user_token, user_balance) =
            parse_token_holding(user_payment_holding.account.data.as_ref());
        assert_eq!(user_token, config_state.payment_token_id, "Wrong payment token");
        assert!(user_balance >= payment_amount, "Insufficient balance");

        let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
        assert_eq!(treasury_id, config_state.treasury_account_id, "Wrong treasury");

        let token_program_id = user_payment_holding.account.program_owner;

        let mut user_payment_auth = user_payment_holding.clone();
        user_payment_auth.is_authorized = true;
        let transfer_instr = token_core::Instruction::Transfer {
            amount_to_transfer: payment_amount,
        };
        let transfer_call = ChainedCall::new(
            token_program_id,
            vec![user_payment_auth, treasury_holding.clone()],
            &transfer_instr,
        );

        let mut credit_token_def_auth = credit_token_def.clone();
        credit_token_def_auth.is_authorized = true;
        let mint_instr = token_core::Instruction::Mint { amount_to_mint: amount };
        let receipt_seed = combine_seeds(&[&label_seed("receipt"), &tree_id]);
        let mint_call = ChainedCall::new(
            token_program_id,
            vec![credit_token_def_auth, user_credit_holding.clone()],
            &mint_instr,
        )
        .with_pda_seeds(vec![PdaSeed::new(receipt_seed)]);

        Ok(SpelOutput::execute(
            vec![
                config,
                credit_token_def,
                user_payment_holding,
                treasury_holding,
                user_credit_holding,
            ],
            vec![transfer_call, mint_call],
        ))
    }

    /// Burn-credits registration: burn receipt tokens, claim membership, insert leaf.
    #[instruction]
    pub fn register_with_credits(
        #[account(pda = [literal("config"), arg("tree_id")])]
        mut config: AccountWithMetadata,
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
        mut membership: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        amount_to_burn: u64,
        subtree_id: u32,
    ) -> SpelResult {
        validate_field_element(&id_commitment);
        let rate_limit = amount_to_burn;
        validate_rate_limit(rate_limit);

        let mut config_state = ConfigState::try_from_slice(config.account.data.as_ref())
            .expect("decode ConfigState");
        assert_eq!(config_state.tree_id, tree_id, "tree_id arg must match config");
        assert!(config_state.can_register(rate_limit), "Would exceed max total rate limit");

        let now = require_clock(&clock_account);
        let grace_period_start_timestamp =
            now.saturating_add(config_state.active_duration_for_new_memberships as u64);

        let receipt_def_id: [u8; 32] = *credit_token_def.account_id.value();
        assert_eq!(receipt_def_id, config_state.receipt_token_id, "Wrong receipt token");

        assert!(user_credit_holding.is_authorized, "User must authorize burn");
        let (user_token, user_balance) =
            parse_token_holding(user_credit_holding.account.data.as_ref());
        assert_eq!(user_token, config_state.receipt_token_id, "Wrong token type");
        assert!(user_balance >= rate_limit as u128, "Insufficient receipt tokens");

        let next_index = read_tree_next_index(tree_main.account.data.as_ref());
        let expected_subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
        assert_eq!(subtree_id, expected_subtree_id, "subtree_id arg must match next_index/SUBTREE_LEAVES");

        let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

        config_state.total_registrations = config_state.total_registrations.saturating_add(1);
        config_state.current_total_rate_limit =
            config_state.current_total_rate_limit.saturating_add(rate_limit);
        config.account.data = borsh::to_vec(&config_state)
            .expect("re-serialize ConfigState")
            .try_into()
            .expect("updated config fits");

        let membership_state = new_membership_state(
            next_index,
            rate_limit,
            id_commitment,
            grace_period_start_timestamp,
            &config_state,
        );
        membership.account.data = borsh::to_vec(&membership_state)
            .expect("borsh serialize MembershipState")
            .try_into()
            .expect("membership data fits");

        let token_program_id = user_credit_holding.account.program_owner;
        let mut user_credit_auth = user_credit_holding.clone();
        user_credit_auth.is_authorized = true;
        let burn_instr = token_core::Instruction::Burn { amount_to_burn: rate_limit as u128 };
        let burn_call = ChainedCall::new(
            token_program_id,
            vec![credit_token_def.clone(), user_credit_auth],
            &burn_instr,
        );

        let merkle_insert_call = merkle_chained_call(
            config_state.merkle_program_id,
            &tree_main,
            &bottom_subtree,
            &tree_id,
            subtree_id,
            merkle_insert_payload(next_index, &leaf_value),
            "serialize merkle insert",
        );

        Ok(SpelOutput::execute(
            vec![
                config,
                credit_token_def,
                tree_main,
                user_credit_holding,
                bottom_subtree,
                clock_account,
                membership,
            ],
            vec![burn_call, merkle_insert_call],
        ))
    }

    /// Slash a spammer: derive id_commitment from identity_secret, zero membership,
    /// remove leaf from the tree, return rate_limit to the pool.
    #[instruction]
    pub fn slash(
        #[account(pda = [literal("config"), arg("tree_id")])]
        mut config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        mut membership: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        identity_secret: [u8; 32],
        subtree_id: u32,
    ) -> SpelResult {
        validate_field_element(&identity_secret);

        let derived_commitment = hash_single(&identity_secret);
        assert_eq!(
            derived_commitment, id_commitment,
            "id_commitment arg must match hash(identity_secret)"
        );

        let mut config_state = ConfigState::try_from_slice(config.account.data.as_ref())
            .expect("decode ConfigState");
        assert_eq!(config_state.tree_id, tree_id, "tree_id arg must match config");

        let membership_bytes = membership.account.data.as_ref();
        assert!(
            !membership_bytes.is_empty(),
            "Membership account is empty - member doesn't exist or already slashed"
        );
        let membership_state = MembershipState::try_from_slice(membership_bytes)
            .expect("decode MembershipState");
        assert_eq!(
            membership_state.id_commitment, id_commitment,
            "membership id_commitment mismatch"
        );

        let expected_subtree_id =
            (membership_state.leaf_index / SUBTREE_LEAVES as u64) as u32;
        assert_eq!(subtree_id, expected_subtree_id, "subtree_id must match membership leaf_index");

        config_state.current_total_rate_limit = config_state
            .current_total_rate_limit
            .saturating_sub(membership_state.rate_limit);
        config_state.total_registrations =
            config_state.total_registrations.saturating_sub(1);
        config.account.data = borsh::to_vec(&config_state)
            .expect("re-serialize ConfigState")
            .try_into()
            .expect("updated config fits");

        membership.account.data = Vec::new()
            .try_into()
            .expect("empty data is always valid");

        let merkle_remove_call = merkle_chained_call(
            config_state.merkle_program_id,
            &tree_main,
            &bottom_subtree,
            &tree_id,
            subtree_id,
            merkle_remove_payload(membership_state.leaf_index),
            "serialize merkle remove",
        );

        Ok(SpelOutput::execute(
            vec![config, tree_main, membership, bottom_subtree],
            vec![merkle_remove_call],
        ))
    }

    /// Renew a membership during its grace period.
    #[instruction]
    pub fn extend(
        #[account(pda = [literal("config"), arg("tree_id")])]
        config: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        mut membership: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
    ) -> SpelResult {
        let now = require_clock(&clock_account);
        let _ = id_commitment; // referenced via PDA seed; not used in body otherwise

        let config_state = ConfigState::try_from_slice(config.account.data.as_ref())
            .expect("decode ConfigState");
        assert_eq!(config_state.tree_id, tree_id, "tree_id arg must match config");

        let membership_bytes = membership.account.data.as_ref();
        assert!(
            !membership_bytes.is_empty(),
            "Membership account is empty - cannot extend a non-existent membership"
        );
        let mut membership_state = MembershipState::try_from_slice(membership_bytes)
            .expect("decode MembershipState");

        assert!(
            is_in_grace_period(
                membership_state.grace_period_start_timestamp,
                membership_state.grace_period_duration,
                now,
            ),
            "CannotExtendNonGracePeriodMembership: membership is not in its grace period"
        );

        membership_state.grace_period_start_timestamp = membership_state
            .grace_period_start_timestamp
            .saturating_add(membership_state.grace_period_duration as u64)
            .saturating_add(membership_state.active_duration as u64);

        membership.account.data = borsh::to_vec(&membership_state)
            .expect("re-serialize MembershipState")
            .try_into()
            .expect("updated membership fits");

        Ok(SpelOutput::execute(
            vec![config, membership, clock_account],
            vec![],
        ))
    }

    /// Garbage-collect an expired membership. Open to any caller.
    #[instruction]
    pub fn erase(
        #[account(pda = [literal("config"), arg("tree_id")])]
        mut config: AccountWithMetadata,
        #[account(pda = [literal("main"), arg("tree_id")])]
        tree_main: AccountWithMetadata,
        #[account(pda = [literal("membership"), arg("tree_id"), arg("id_commitment")])]
        mut membership: AccountWithMetadata,
        #[account(pda = [literal("subtree"), arg("tree_id"), arg("subtree_id")])]
        bottom_subtree: AccountWithMetadata,
        clock_account: AccountWithMetadata,
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        subtree_id: u32,
    ) -> SpelResult {
        let _ = id_commitment;
        let now = require_clock(&clock_account);

        let mut config_state = ConfigState::try_from_slice(config.account.data.as_ref())
            .expect("decode ConfigState");
        assert_eq!(config_state.tree_id, tree_id, "tree_id arg must match config");

        let membership_bytes = membership.account.data.as_ref();
        assert!(
            !membership_bytes.is_empty(),
            "Membership account is empty - nothing to erase"
        );
        let membership_state = MembershipState::try_from_slice(membership_bytes)
            .expect("decode MembershipState");

        assert!(
            is_expired(
                membership_state.grace_period_start_timestamp,
                membership_state.grace_period_duration,
                now,
            ),
            "CannotEraseUnexpiredMembership: membership has not expired yet"
        );

        let expected_subtree_id =
            (membership_state.leaf_index / SUBTREE_LEAVES as u64) as u32;
        assert_eq!(subtree_id, expected_subtree_id, "subtree_id must match membership leaf_index");

        config_state.current_total_rate_limit = config_state
            .current_total_rate_limit
            .saturating_sub(membership_state.rate_limit);
        config_state.total_registrations =
            config_state.total_registrations.saturating_sub(1);
        config.account.data = borsh::to_vec(&config_state)
            .expect("re-serialize ConfigState")
            .try_into()
            .expect("updated config fits");

        membership.account.data = Vec::new()
            .try_into()
            .expect("empty data is always valid");

        let merkle_remove_call = merkle_chained_call(
            config_state.merkle_program_id,
            &tree_main,
            &bottom_subtree,
            &tree_id,
            subtree_id,
            merkle_remove_payload(membership_state.leaf_index),
            "serialize merkle remove",
        );

        Ok(SpelOutput::execute(
            vec![config, tree_main, membership, bottom_subtree, clock_account],
            vec![merkle_remove_call],
        ))
    }
}
