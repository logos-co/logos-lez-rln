//! Pure-logic implementations of each RLN registration instruction.
//!
//! Each function takes typed `AccountWithMetadata` inputs + instruction args,
//! performs all parsing/validation/computation, and returns the
//! `(post_states, chained_calls)` pair that the SPEL macro handler in
//! `program.rs` wraps with `SpelOutput::execute`. Keeping the logic out of
//! the macro-processed module makes it directly callable from unit tests
//! without going through the zkVM.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, Claim, PdaSeed},
};
use rln_layouts::{
    MerkleOpcode, SUBTREE_LEAVES, TokenHoldingLayout, combine_seeds, is_expired,
    is_in_grace_period, label_seed, u32_seed,
};
use spel_framework::prelude::SpelOutput;

use crate::{
    hash::{hash_single, validate_field_element},
    program::{ConfigState, MembershipState},
    registration::{
        TokenHolding, calculate_payment_amount, compute_registration_leaf, parse_token_holding,
        read_tree_next_index, require_clock, validate_rate_limit,
    },
};

type Output = SpelOutput;

// ─── seed helpers ──────────────────────────────────────────────────────

fn config_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("config"), tree_id])
}

fn payment_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("payment"), tree_id])
}

fn payment_supply_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("payment_supply"), tree_id])
}

fn escrow_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("escrow"), tree_id])
}

fn main_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

fn subtree_seed(tree_id: &[u8; 32], subtree_id: u32) -> [u8; 32] {
    combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)])
}

fn membership_seed(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("membership"), tree_id, id_commitment])
}

fn authorized(account: &AccountWithMetadata) -> AccountWithMetadata {
    let mut a = account.clone();
    a.is_authorized = true;
    a
}

fn merkle_payload_insert(next_index: u64, leaf_value: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(41);
    payload.push(MerkleOpcode::Insert as u8);
    payload.extend_from_slice(&next_index.to_le_bytes());
    payload.extend_from_slice(leaf_value);
    payload
}

fn merkle_payload_replace(leaf_index: u64, leaf_value: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(41);
    payload.push(MerkleOpcode::Replace as u8);
    payload.extend_from_slice(&leaf_index.to_le_bytes());
    payload.extend_from_slice(leaf_value);
    payload
}

fn merkle_payload_remove(leaf_index: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9);
    payload.push(MerkleOpcode::Remove as u8);
    payload.extend_from_slice(&leaf_index.to_le_bytes());
    payload
}

fn merkle_chained_call(
    merkle_program_id: [u8; 32],
    tree_main: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    tree_id: &[u8; 32],
    subtree_id: u32,
    payload: Vec<u8>,
) -> ChainedCall {
    ChainedCall {
        program_id: bytemuck::cast(merkle_program_id),
        pre_states: vec![authorized(tree_main), authorized(bottom_subtree)],
        instruction_data: risc0_zkvm::serde::to_vec(&payload).expect("serialize merkle payload"),
        pda_seeds: vec![
            PdaSeed::new(main_seed(tree_id)),
            PdaSeed::new(subtree_seed(tree_id, subtree_id)),
        ],
    }
}

fn new_membership_state(
    next_index: u64,
    rate_limit: u64,
    id_commitment: [u8; 32],
    grace_period_start_timestamp: u64,
    holder: [u8; 32],
    deposit_amount: u128,
    config_state: &ConfigState,
) -> MembershipState {
    MembershipState {
        leaf_index: next_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp,
        active_duration: config_state.active_duration_for_new_memberships,
        grace_period_duration: config_state.grace_period_duration_for_new_memberships,
        holder,
        deposit_amount,
        exiting: 0,
    }
}

/// Chained transfer of `amount` out of the tree's escrow into `destination`.
fn escrow_payout(
    config_state: &ConfigState,
    escrow: &AccountWithMetadata,
    destination: &AccountWithMetadata,
    tree_id: &[u8; 32],
    amount: u128,
) -> ChainedCall {
    ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(escrow), destination.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![PdaSeed::new(escrow_seed(tree_id))])
}

/// The escrow as a later chained call in the same transaction must declare it.
/// A chained call's pre-state has to equal the previous call's output byte for
/// byte, so the balance is patched in place rather than a holding re-encoded.
fn escrow_after_credit(escrow: &AccountWithMetadata, credited: u128) -> AccountWithMetadata {
    let mut after = escrow.clone();
    let mut data = after.account.data.as_ref().to_vec();
    assert!(
        data.len() >= TokenHoldingLayout::SIZE,
        "escrow must be an initialized holding to be debited in the same transaction"
    );
    let updated = TokenHoldingLayout::parse(&data)
        .balance()
        .checked_add(credited)
        .expect("escrow balance overflow");
    data[TokenHoldingLayout::BALANCE_OFFSET..TokenHoldingLayout::SIZE]
        .copy_from_slice(&updated.to_le_bytes());
    after.account.data = data.try_into().expect("holding data fits");
    after
}

/// Validate the payer's holding and build the transfer that escrows
/// `deposit_amount`. A still-default escrow is created by this transfer.
fn escrow_deposit(
    config_state: &ConfigState,
    user_holding: &AccountWithMetadata,
    escrow: &AccountWithMetadata,
    tree_id: &[u8; 32],
    deposit_amount: u128,
) -> ChainedCall {
    assert!(
        user_holding.is_authorized,
        "User must authorize the deposit"
    );
    let TokenHolding {
        definition_id: user_token,
        balance: user_balance,
    } = parse_token_holding(user_holding.account.data.as_ref());
    assert_eq!(
        user_token, config_state.payment_token_id,
        "Wrong payment token"
    );
    assert!(user_balance >= deposit_amount, "Insufficient balance");

    // The holding's self-reported data is attacker-controllable; only the
    // owning program is not. Require it to be the configured token program so
    // the deposit can't be routed to an attacker's no-op program.
    let user_holding_owner: [u8; 32] = bytemuck::cast(user_holding.account.program_owner);
    assert_eq!(
        user_holding_owner, config_state.token_program_id,
        "Payment holding not owned by the configured token program"
    );

    ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(user_holding), authorized(escrow)],
        &token_core::Instruction::Transfer {
            amount_to_transfer: deposit_amount,
        },
    )
    .with_pda_seeds(vec![PdaSeed::new(escrow_seed(tree_id))])
}

/// Assert `holding` is the account the membership recorded as its depositor.
fn require_holder(holding: &AccountWithMetadata, membership_state: &MembershipState) {
    assert_eq!(
        *holding.account_id.value(),
        membership_state.holder,
        "account is not this membership's holder"
    );
}

fn write_borsh<T: BorshSerialize>(
    account: &mut AccountWithMetadata,
    value: &T,
    what: &'static str,
) {
    account.account.data = borsh::to_vec(value)
        .unwrap_or_else(|_| panic!("borsh serialize {what}"))
        .try_into()
        .unwrap_or_else(|_| panic!("{what} fits in account.data"));
}

/// Decode the config PDA, binding it to the `tree_id` the caller asked for.
/// Callee program ids come from here and never from an instruction arg: these
/// handlers hand the callee seeds that authorize claiming this program's PDAs,
/// so a caller-named program would be handed those seeds.
fn require_config(config: &AccountWithMetadata, tree_id: &[u8; 32]) -> ConfigState {
    let config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, *tree_id,
        "tree_id arg must match config"
    );
    config_state
}

// ─── instruction handlers ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn initialize(
    mut config: AccountWithMetadata,
    merkle_program_id: [u8; 32],
    token_program_id: [u8; 32],
    tree_id: [u8; 32],
    payment_token_id: [u8; 32],
    price_per_unit: u128,
    treasury_account_id: [u8; 32],
    max_total_rate_limit: u64,
    active_duration_for_new_memberships: u32,
    grace_period_duration_for_new_memberships: u32,
    authorized_registrar: [u8; 32],
    free_quota: u64,
    faucet_claim_cap: u128,
) -> Output {
    assert!(
        max_total_rate_limit > 0,
        "Max total rate limit must be positive"
    );
    assert!(
        active_duration_for_new_memberships > 0,
        "Active duration must be positive"
    );
    assert!(
        free_quota == 0 || authorized_registrar != [0u8; 32],
        "Free quota requires an authorized registrar"
    );

    let config_state = ConfigState {
        merkle_program_id,
        tree_id,
        payment_token_id,
        price_per_unit,
        treasury_account_id,
        total_registrations: 0,
        max_total_rate_limit,
        current_total_rate_limit: 0,
        active_duration_for_new_memberships,
        grace_period_duration_for_new_memberships,
        token_program_id,
        authorized_registrar,
        free_quota_remaining: free_quota,
        faucet_claim_cap,
    };
    write_borsh(&mut config, &config_state, "ConfigState");

    let states = vec![AccountPostState::new_claimed_if_default(
        config.account,
        Claim::Pda(PdaSeed::new(config_seed(&tree_id))),
    )];
    SpelOutput::execute(states, vec![])
}

pub fn initialize_payment_token(
    config: AccountWithMetadata,
    payment_token: AccountWithMetadata,
    payment_supply: AccountWithMetadata,
    tree_id: [u8; 32],
) -> Output {
    let config_state = require_config(&config, &tree_id);
    let token_create = ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(&payment_token), authorized(&payment_supply)],
        &token_core::Instruction::NewFungibleDefinition {
            name: "RLNTOK".to_string(),
            total_supply: 0,
        },
    )
    .with_pda_seeds(vec![
        PdaSeed::new(payment_seed(&tree_id)),
        PdaSeed::new(payment_supply_seed(&tree_id)),
    ]);

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(payment_token.account),
        AccountPostState::new(payment_supply.account),
    ];
    SpelOutput::execute(states, vec![token_create])
}

pub fn claim_tokens(
    config: AccountWithMetadata,
    payment_token_def: AccountWithMetadata,
    dest_holding: AccountWithMetadata,
    tree_id: [u8; 32],
    amount: u128,
) -> Output {
    assert!(amount > 0, "Amount must be positive");

    let config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );
    assert!(
        config_state.faucet_claim_cap > 0,
        "Faucet disabled for this deployment"
    );
    assert!(
        amount <= config_state.faucet_claim_cap,
        "Amount exceeds faucet claim cap"
    );

    let def_id: [u8; 32] = *payment_token_def.account_id.value();
    assert_eq!(
        def_id, config_state.payment_token_id,
        "Wrong payment token definition"
    );

    // Program-authority mint: the `payment` PDA seed alone authorizes it, so
    // no human mint key exists in faucet deployments.
    let mint = ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(&payment_token_def), dest_holding.clone()],
        &token_core::Instruction::Mint {
            amount_to_mint: amount,
        },
    )
    .with_pda_seeds(vec![PdaSeed::new(payment_seed(&tree_id))]);

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(payment_token_def.account),
        AccountPostState::new(dest_holding.account),
    ];
    SpelOutput::execute(states, vec![mint])
}

pub fn initialize_merkle_tree(
    config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    tree_id: [u8; 32],
) -> Output {
    let config_state = require_config(&config, &tree_id);
    let merkle_init = ChainedCall {
        program_id: bytemuck::cast(config_state.merkle_program_id),
        pre_states: vec![authorized(&tree_main)],
        instruction_data: risc0_zkvm::serde::to_vec(&vec![MerkleOpcode::Initialize as u8])
            .expect("serialize merkle init"),
        pda_seeds: vec![PdaSeed::new(main_seed(&tree_id))],
    };

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
    ];
    SpelOutput::execute(states, vec![merkle_init])
}

#[allow(clippy::too_many_arguments)]
pub fn register(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    user_holding: AccountWithMetadata,
    escrow_holding: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    tree_id: [u8; 32],
    id_commitment: [u8; 32],
    rate_limit: u64,
    subtree_id: u32,
) -> Output {
    validate_field_element(&id_commitment);
    validate_rate_limit(rate_limit);

    let mut config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );
    assert!(
        config_state.can_register(rate_limit),
        "Would exceed max total rate limit"
    );

    let now = require_clock(&clock_account);
    let grace_period_start_timestamp =
        now.saturating_add(config_state.active_duration_for_new_memberships as u64);
    let deposit_amount = calculate_payment_amount(rate_limit, config_state.price_per_unit);

    let deposit_transfer = escrow_deposit(
        &config_state,
        &user_holding,
        &escrow_holding,
        &tree_id,
        deposit_amount,
    );

    let next_index = read_tree_next_index(tree_main.account.data.as_ref());
    let expected_subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    assert_eq!(
        subtree_id, expected_subtree_id,
        "subtree_id arg must match next_index/SUBTREE_LEAVES"
    );

    let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

    config_state.total_registrations = config_state.total_registrations.saturating_add(1);
    config_state.current_total_rate_limit = config_state
        .current_total_rate_limit
        .saturating_add(rate_limit);
    write_borsh(&mut config, &config_state, "ConfigState");

    let membership_state = new_membership_state(
        next_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp,
        *user_holding.account_id.value(),
        deposit_amount,
        &config_state,
    );
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let merkle_insert = merkle_chained_call(
        config_state.merkle_program_id,
        &tree_main,
        &bottom_subtree,
        &tree_id,
        subtree_id,
        merkle_payload_insert(next_index, &leaf_value),
    );

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(user_holding.account),
        AccountPostState::new(escrow_holding.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
        AccountPostState::new_claimed_if_default(
            membership.account,
            Claim::Pda(PdaSeed::new(membership_seed(&tree_id, &id_commitment))),
        ),
    ];
    SpelOutput::execute(states, vec![deposit_transfer, merkle_insert])
}

/// Register by displacing an EXPIRED membership, taking over its leaf index
/// and refunding its holder. The only way in once `max_total_rate_limit` is
/// reached, since nothing returns a slot to the pool until an expired
/// membership is erased.
///
/// The leaf is overwritten in place by a single `Replace` rather than removed
/// and re-inserted: a chained call must declare the previous call's output as
/// its pre-state, and this program cannot predict a merkle root.
#[allow(clippy::too_many_arguments)]
pub fn register_replacing(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    user_holding: AccountWithMetadata,
    escrow_holding: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    mut old_membership: AccountWithMetadata,
    old_holder_holding: AccountWithMetadata,
    tree_id: [u8; 32],
    id_commitment: [u8; 32],
    rate_limit: u64,
    subtree_id: u32,
) -> Output {
    validate_field_element(&id_commitment);
    validate_rate_limit(rate_limit);

    let mut config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );

    let now = require_clock(&clock_account);

    let old_bytes = old_membership.account.data.as_ref();
    assert!(
        !old_bytes.is_empty(),
        "Membership account is empty - nothing to replace"
    );
    let old_state = MembershipState::try_from_slice(old_bytes).expect("decode MembershipState");
    assert_ne!(
        old_state.id_commitment, id_commitment,
        "a membership cannot replace itself"
    );
    assert!(
        is_expired(
            old_state.grace_period_start_timestamp,
            old_state.grace_period_duration,
            now,
        ),
        "CannotReplaceUnexpiredMembership: the membership holding this slot has not expired"
    );
    require_holder(&old_holder_holding, &old_state);

    // The new leaf lands on the displaced one's index, so this is the OLD
    // membership's subtree, not `next_index`'s.
    let expected_subtree_id = (old_state.leaf_index / SUBTREE_LEAVES as u64) as u32;
    assert_eq!(
        subtree_id, expected_subtree_id,
        "subtree_id must match the replaced membership's leaf_index"
    );

    // Net: the freed slot is what makes room for the one being taken.
    let net_total_rate_limit = config_state
        .current_total_rate_limit
        .saturating_sub(old_state.rate_limit)
        .saturating_add(rate_limit);
    assert!(
        net_total_rate_limit <= config_state.max_total_rate_limit,
        "Would exceed max total rate limit"
    );

    let deposit_amount = calculate_payment_amount(rate_limit, config_state.price_per_unit);
    let deposit_transfer = escrow_deposit(
        &config_state,
        &user_holding,
        &escrow_holding,
        &tree_id,
        deposit_amount,
    );

    let grace_period_start_timestamp =
        now.saturating_add(config_state.active_duration_for_new_memberships as u64);
    let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

    // One membership leaves as one arrives, so `total_registrations` holds.
    config_state.current_total_rate_limit = net_total_rate_limit;
    write_borsh(&mut config, &config_state, "ConfigState");

    let membership_state = new_membership_state(
        old_state.leaf_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp,
        *user_holding.account_id.value(),
        deposit_amount,
        &config_state,
    );
    write_borsh(&mut membership, &membership_state, "MembershipState");
    old_membership.account.data = Vec::new().try_into().expect("empty data is always valid");

    let mut calls = vec![deposit_transfer];

    if old_state.deposit_amount > 0 {
        // Same rule `register` applies to the account it debits.
        let holder_owner: [u8; 32] = bytemuck::cast(old_holder_holding.account.program_owner);
        assert_eq!(
            holder_owner, config_state.token_program_id,
            "Refund destination not owned by the configured token program"
        );
        calls.push(escrow_payout(
            &config_state,
            &escrow_after_credit(&escrow_holding, deposit_amount),
            &old_holder_holding,
            &tree_id,
            old_state.deposit_amount,
        ));
    }

    calls.push(merkle_chained_call(
        config_state.merkle_program_id,
        &tree_main,
        &bottom_subtree,
        &tree_id,
        subtree_id,
        merkle_payload_replace(old_state.leaf_index, &leaf_value),
    ));

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(user_holding.account),
        AccountPostState::new(escrow_holding.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
        AccountPostState::new_claimed_if_default(
            membership.account,
            Claim::Pda(PdaSeed::new(membership_seed(&tree_id, &id_commitment))),
        ),
        AccountPostState::new(old_membership.account),
        AccountPostState::new(old_holder_holding.account),
    ];
    SpelOutput::execute(states, calls)
}

#[allow(clippy::too_many_arguments)]
pub fn register_free(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    registrar: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    tree_id: [u8; 32],
    id_commitment: [u8; 32],
    rate_limit: u64,
    subtree_id: u32,
) -> Output {
    validate_field_element(&id_commitment);
    validate_rate_limit(rate_limit);

    let mut config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );
    assert!(
        config_state.can_register(rate_limit),
        "Would exceed max total rate limit"
    );

    assert_ne!(
        config_state.authorized_registrar, [0u8; 32],
        "No authorized registrar configured"
    );
    assert!(registrar.is_authorized, "Registrar must sign");
    assert_eq!(
        *registrar.account_id.value(),
        config_state.authorized_registrar,
        "Not the authorized registrar"
    );
    // Declared accounts are echoed into the output, and LEZ rejects a
    // DEFAULT-owned account that is no longer pristine. Signing bumps the
    // nonce, so a plain-wallet registrar would work exactly ONCE and then have
    // every call dropped at block inclusion. Fail here instead.
    assert_ne!(
        registrar.account.program_owner,
        nssa_core::program::DEFAULT_PROGRAM_ID,
        "Registrar must be a program-owned account, not a plain wallet"
    );
    assert!(
        config_state.free_quota_remaining > 0,
        "Free-registration quota exhausted"
    );

    let now = require_clock(&clock_account);
    let grace_period_start_timestamp =
        now.saturating_add(config_state.active_duration_for_new_memberships as u64);

    let next_index = read_tree_next_index(tree_main.account.data.as_ref());
    let expected_subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    assert_eq!(
        subtree_id, expected_subtree_id,
        "subtree_id arg must match next_index/SUBTREE_LEAVES"
    );

    let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

    config_state.total_registrations = config_state.total_registrations.saturating_add(1);
    config_state.current_total_rate_limit = config_state
        .current_total_rate_limit
        .saturating_add(rate_limit);
    config_state.free_quota_remaining -= 1;
    write_borsh(&mut config, &config_state, "ConfigState");

    // No deposit to refund; the registrar stands as holder so `erase`'s
    // destination check stays uniform.
    let membership_state = new_membership_state(
        next_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp,
        *registrar.account_id.value(),
        0,
        &config_state,
    );
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let merkle_insert = merkle_chained_call(
        config_state.merkle_program_id,
        &tree_main,
        &bottom_subtree,
        &tree_id,
        subtree_id,
        merkle_payload_insert(next_index, &leaf_value),
    );

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(registrar.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
        AccountPostState::new_claimed_if_default(
            membership.account,
            Claim::Pda(PdaSeed::new(membership_seed(&tree_id, &id_commitment))),
        ),
    ];
    SpelOutput::execute(states, vec![merkle_insert])
}

#[allow(clippy::too_many_arguments)]
pub fn slash(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    escrow_holding: AccountWithMetadata,
    payment_token_def: AccountWithMetadata,
    tree_id: [u8; 32],
    id_commitment: [u8; 32],
    identity_secret: [u8; 32],
    subtree_id: u32,
) -> Output {
    validate_field_element(&identity_secret);
    assert_eq!(
        hash_single(&identity_secret),
        id_commitment,
        "id_commitment arg must match hash(identity_secret)"
    );

    let mut config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );

    let membership_bytes = membership.account.data.as_ref();
    assert!(
        !membership_bytes.is_empty(),
        "Membership account is empty - member doesn't exist or already slashed"
    );
    let membership_state =
        MembershipState::try_from_slice(membership_bytes).expect("decode MembershipState");
    assert_eq!(
        membership_state.id_commitment, id_commitment,
        "membership id_commitment mismatch"
    );

    let expected_subtree_id = (membership_state.leaf_index / SUBTREE_LEAVES as u64) as u32;
    assert_eq!(
        subtree_id, expected_subtree_id,
        "subtree_id must match membership leaf_index"
    );

    config_state.current_total_rate_limit = config_state
        .current_total_rate_limit
        .saturating_sub(membership_state.rate_limit);
    config_state.total_registrations = config_state.total_registrations.saturating_sub(1);
    write_borsh(&mut config, &config_state, "ConfigState");

    membership.account.data = Vec::new().try_into().expect("empty data is always valid");

    let merkle_remove = merkle_chained_call(
        config_state.merkle_program_id,
        &tree_main,
        &bottom_subtree,
        &tree_id,
        subtree_id,
        merkle_payload_remove(membership_state.leaf_index),
    );

    let mut calls = vec![merkle_remove];

    // Asserted even with nothing to burn: the definition is echoed into the
    // output either way, and a caller-chosen one can trip LEZ rule 7.
    assert_eq!(
        *payment_token_def.account_id.value(),
        config_state.payment_token_id,
        "Wrong payment token definition"
    );
    if membership_state.deposit_amount > 0 {
        calls.push(
            ChainedCall::new(
                bytemuck::cast(config_state.token_program_id),
                vec![payment_token_def.clone(), authorized(&escrow_holding)],
                &token_core::Instruction::Burn {
                    amount_to_burn: membership_state.deposit_amount,
                },
            )
            .with_pda_seeds(vec![PdaSeed::new(escrow_seed(&tree_id))]),
        );
    }

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(membership.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(escrow_holding.account),
        AccountPostState::new(payment_token_def.account),
    ];
    SpelOutput::execute(states, calls)
}

/// Renew a membership from inside its grace period, priced at what its rate
/// limit would cost to register. Anyone may pay for anyone's renewal: the
/// charge, not the caller's identity, is what stops a passer-by pinning an
/// abandoned membership's share of the rate-limit budget alive.
pub fn extend(
    config: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    payer_holding: AccountWithMetadata,
    treasury_holding: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    tree_id: [u8; 32],
) -> Output {
    let now = require_clock(&clock_account);

    let config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );

    let membership_bytes = membership.account.data.as_ref();
    assert!(
        !membership_bytes.is_empty(),
        "Membership account is empty - cannot extend a non-existent membership"
    );
    let mut membership_state =
        MembershipState::try_from_slice(membership_bytes).expect("decode MembershipState");

    assert!(
        is_in_grace_period(
            membership_state.grace_period_start_timestamp,
            membership_state.grace_period_duration,
            now,
        ),
        "CannotExtendNonGracePeriodMembership: membership is not in its grace period"
    );
    // Without this, a third party could reverse a holder's exit by renewing.
    assert_eq!(
        membership_state.exiting, 0,
        "CannotExtendExitingMembership: the holder has started this membership's wind-down"
    );

    // Priced off the membership's own rate limit, exactly as registration is.
    let payment_amount =
        calculate_payment_amount(membership_state.rate_limit, config_state.price_per_unit);

    assert!(payer_holding.is_authorized, "Payer must authorize payment");
    let TokenHolding {
        definition_id: payer_token,
        balance: payer_balance,
    } = parse_token_holding(payer_holding.account.data.as_ref());
    assert_eq!(
        payer_token, config_state.payment_token_id,
        "Wrong payment token"
    );
    assert!(payer_balance >= payment_amount, "Insufficient balance");

    // Same reasoning as `register`: holding data is attacker-controllable, the
    // owning program is not.
    let payer_holding_owner: [u8; 32] = bytemuck::cast(payer_holding.account.program_owner);
    assert_eq!(
        payer_holding_owner, config_state.token_program_id,
        "Payment holding not owned by the configured token program"
    );

    let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
    assert_eq!(
        treasury_id, config_state.treasury_account_id,
        "Wrong treasury"
    );

    membership_state.grace_period_start_timestamp = membership_state
        .grace_period_start_timestamp
        .saturating_add(membership_state.grace_period_duration as u64)
        .saturating_add(membership_state.active_duration as u64);
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let token_transfer = ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(&payer_holding), treasury_holding.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: payment_amount,
        },
    );

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(membership.account),
        AccountPostState::new(payer_holding.account),
        AccountPostState::new(treasury_holding.account),
        AccountPostState::new(clock_account.account),
    ];
    SpelOutput::execute(states, vec![token_transfer])
}

/// Bring a membership's grace period forward to now, at its holder's request
/// — the counterweight to renewal being permissionless, which would otherwise
/// let a third party keep a stranger's deposit escrowed indefinitely.
///
/// The deposit is not released here: the leaf stays in the tree until `erase`,
/// so the wind-down window is also the interval in which `slash` can burn it.
pub fn force_expire(
    mut membership: AccountWithMetadata,
    holder_holding: AccountWithMetadata,
    clock_account: AccountWithMetadata,
) -> Output {
    let now = require_clock(&clock_account);

    let membership_bytes = membership.account.data.as_ref();
    assert!(
        !membership_bytes.is_empty(),
        "Membership account is empty - nothing to expire"
    );
    let mut membership_state =
        MembershipState::try_from_slice(membership_bytes).expect("decode MembershipState");

    assert!(
        holder_holding.is_authorized,
        "Holder must authorize the exit"
    );
    require_holder(&holder_holding, &membership_state);
    // A free membership records its registrar as `holder`; without this the
    // registrar could wind down anything it ever gifted.
    assert!(
        membership_state.deposit_amount > 0,
        "CannotForceExpireFreeMembership: no deposit is escrowed for this membership"
    );

    // Only ever earlier, so this can never postpone expiry.
    membership_state.grace_period_start_timestamp =
        membership_state.grace_period_start_timestamp.min(now);
    membership_state.exiting = 1;
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let states = vec![
        AccountPostState::new(membership.account),
        AccountPostState::new(holder_holding.account),
        AccountPostState::new(clock_account.account),
    ];
    SpelOutput::execute(states, vec![])
}

#[allow(clippy::too_many_arguments)]
pub fn erase(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    escrow_holding: AccountWithMetadata,
    holder_holding: AccountWithMetadata,
    tree_id: [u8; 32],
    subtree_id: u32,
) -> Output {
    let now = require_clock(&clock_account);

    let mut config_state =
        ConfigState::try_from_slice(config.account.data.as_ref()).expect("decode ConfigState");
    assert_eq!(
        config_state.tree_id, tree_id,
        "tree_id arg must match config"
    );

    let membership_bytes = membership.account.data.as_ref();
    assert!(
        !membership_bytes.is_empty(),
        "Membership account is empty - nothing to erase"
    );
    let membership_state =
        MembershipState::try_from_slice(membership_bytes).expect("decode MembershipState");

    assert!(
        is_expired(
            membership_state.grace_period_start_timestamp,
            membership_state.grace_period_duration,
            now,
        ),
        "CannotEraseUnexpiredMembership: membership has not expired yet"
    );

    let expected_subtree_id = (membership_state.leaf_index / SUBTREE_LEAVES as u64) as u32;
    assert_eq!(
        subtree_id, expected_subtree_id,
        "subtree_id must match membership leaf_index"
    );

    // Erase is permissionless and the caller names the refund destination;
    // this is what stops that being their own. Checked with the other
    // preconditions rather than in the payout branch below.
    require_holder(&holder_holding, &membership_state);

    config_state.current_total_rate_limit = config_state
        .current_total_rate_limit
        .saturating_sub(membership_state.rate_limit);
    config_state.total_registrations = config_state.total_registrations.saturating_sub(1);
    write_borsh(&mut config, &config_state, "ConfigState");

    membership.account.data = Vec::new().try_into().expect("empty data is always valid");

    let merkle_remove = merkle_chained_call(
        config_state.merkle_program_id,
        &tree_main,
        &bottom_subtree,
        &tree_id,
        subtree_id,
        merkle_payload_remove(membership_state.leaf_index),
    );

    let mut calls = vec![merkle_remove];

    if membership_state.deposit_amount > 0 {
        // Same rule `register` applies to the account it debits.
        let holder_owner: [u8; 32] = bytemuck::cast(holder_holding.account.program_owner);
        assert_eq!(
            holder_owner, config_state.token_program_id,
            "Refund destination not owned by the configured token program"
        );
        calls.push(escrow_payout(
            &config_state,
            &escrow_holding,
            &holder_holding,
            &tree_id,
            membership_state.deposit_amount,
        ));
    }

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(membership.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
        AccountPostState::new(escrow_holding.account),
        AccountPostState::new(holder_holding.account),
    ];
    SpelOutput::execute(states, calls)
}
