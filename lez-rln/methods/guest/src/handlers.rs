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
    account::{AccountId, AccountWithMetadata},
    program::{ChainedCall, PdaSeed},
};
use rln_layouts::{
    MerkleOpcode, SUBTREE_LEAVES, combine_seeds, is_expired, is_in_grace_period, label_seed,
    secs_to_millis, u32_seed,
};
use spel_framework::prelude::SpelOutput;

use crate::{
    hash::{hash_single, validate_field_element},
    program::{ConfigState, MembershipState},
    registration::{
        calculate_payment_amount, compute_registration_leaf, read_tree_next_index,
        require_clock_ms, validate_rate_limit,
    },
};

type Output = SpelOutput;

// ─── seed helpers ──────────────────────────────────────────────────────

fn main_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

fn subtree_seed(tree_id: &[u8; 32], subtree_id: u32) -> [u8; 32] {
    combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)])
}

fn merkle_payload_insert(next_index: u64, leaf_value: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(41);
    payload.push(MerkleOpcode::Insert as u8);
    payload.extend_from_slice(&next_index.to_le_bytes());
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
        program_account_id: AccountId::new(merkle_program_id),
        pre_state_ids: vec![tree_main.account_id, bottom_subtree.account_id],
        instruction_data: borsh::to_vec(&payload).expect("serialize merkle payload"),
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
    grace_period_start_timestamp_ms: u64,
    config_state: &ConfigState,
) -> MembershipState {
    MembershipState {
        leaf_index: next_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp_ms,
        active_duration_sec: config_state.active_duration_for_new_memberships_sec,
        grace_period_duration_sec: config_state.grace_period_duration_for_new_memberships_sec,
    }
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
///
/// The callee program ids live here and nowhere else: an instruction arg
/// naming the merkle or token program is attacker-controllable, and these
/// handlers hand the callee `pda_seeds` that authorize it to claim this
/// program's PDAs. Read the target from config, never from the caller.
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
    tree_id: [u8; 32],
    price_per_unit: u128,
    treasury_account_id: [u8; 32],
    max_total_rate_limit: u64,
    active_duration_for_new_memberships_sec: u32,
    grace_period_duration_for_new_memberships_sec: u32,
) -> Output {
    assert!(
        max_total_rate_limit > 0,
        "Max total rate limit must be positive"
    );
    assert!(
        active_duration_for_new_memberships_sec > 0,
        "Active duration must be positive"
    );

    let config_state = ConfigState {
        merkle_program_id,
        tree_id,
        price_per_unit,
        treasury_account_id,
        total_registrations: 0,
        max_total_rate_limit,
        current_total_rate_limit: 0,
        active_duration_for_new_memberships_sec,
        grace_period_duration_for_new_memberships_sec,
    };
    write_borsh(&mut config, &config_state, "ConfigState");

    let states = vec![config.account];
    SpelOutput::execute(states, vec![])
}

pub fn initialize_merkle_tree(
    config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    tree_id: [u8; 32],
) -> Output {
    let config_state = require_config(&config, &tree_id);
    let merkle_init = ChainedCall {
        program_account_id: AccountId::new(config_state.merkle_program_id),
        pre_state_ids: vec![tree_main.account_id],
        instruction_data: borsh::to_vec(&vec![MerkleOpcode::Initialize as u8])
            .expect("serialize merkle init"),
        pda_seeds: vec![PdaSeed::new(main_seed(&tree_id))],
    };

    let states = vec![config.account, tree_main.account];
    SpelOutput::execute(states, vec![merkle_init])
}

#[allow(clippy::too_many_arguments)]
pub fn register(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    mut payer: AccountWithMetadata,
    mut treasury: AccountWithMetadata,
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

    let now_ms = require_clock_ms(&clock_account);
    let grace_period_start_timestamp_ms = now_ms.saturating_add(secs_to_millis(
        config_state.active_duration_for_new_memberships_sec,
    ));
    let payment_amount = calculate_payment_amount(rate_limit, config_state.price_per_unit);

    // The price moves in NATIVE balance, so nothing here is self-reported: the
    // protocol resolves the payer's real pre-state, refuses a decrease on an
    // unauthorized account (UnauthorizedBalanceDecrease), and refuses a diff
    // whose credits do not equal its debits (MismatchedTotalBalance). That is
    // what the old "holding must be owned by the token program" assert was
    // standing in for, now enforced by consensus instead of by this guest.
    //
    // The one thing the protocol will not decide is WHERE the credit lands, so
    // the treasury check below stays and is the only routing guarantee left.
    assert!(payer.is_authorized, "Payer must authorize payment");
    assert!(
        payer.account.balance >= payment_amount,
        "Insufficient balance"
    );

    let treasury_id: [u8; 32] = *treasury.account_id.value();
    assert_eq!(
        treasury_id, config_state.treasury_account_id,
        "Wrong treasury"
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
        grace_period_start_timestamp_ms,
        &config_state,
    );
    write_borsh(&mut membership, &membership_state, "MembershipState");

    // The SPEL macro derives each account's BalanceDiff from the post-account
    // returned here, so moving value is assignment on accounts this handler
    // already declares — no chained call to authenticated_transfer, and no
    // second zkVM session for a two-line move.
    payer.account.balance -= payment_amount;
    treasury.account.balance += payment_amount;

    let merkle_insert = merkle_chained_call(
        config_state.merkle_program_id,
        &tree_main,
        &bottom_subtree,
        &tree_id,
        subtree_id,
        merkle_payload_insert(next_index, &leaf_value),
    );

    let states = vec![
        config.account,
        tree_main.account,
        payer.account,
        treasury.account,
        bottom_subtree.account,
        clock_account.account,
        membership.account,
    ];
    SpelOutput::execute(states, vec![merkle_insert])
}

pub fn slash(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
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

    let states = vec![
        config.account,
        tree_main.account,
        membership.account,
        bottom_subtree.account,
    ];
    SpelOutput::execute(states, vec![merkle_remove])
}

/// Renew a membership from inside its grace period, at the same price its
/// rate limit would cost to register.
///
/// Anyone may pay for anyone's renewal — the membership records no owner, and
/// a third party topping up a member is harmless. What is NOT harmless is
/// renewal being FREE: `erase` only reclaims a membership's `rate_limit` once
/// it is expired, so a free extension lets any passer-by pin an abandoned
/// membership's share of `max_total_rate_limit` forever, one cheap tx per
/// grace window, and eventually block all new registrations. Charging the
/// registration price makes that grief cost exactly as much as holding the
/// slot legitimately, and gives `active_duration_sec` economic force.
pub fn extend(
    config: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    mut payer: AccountWithMetadata,
    mut treasury: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    tree_id: [u8; 32],
) -> Output {
    let now_ms = require_clock_ms(&clock_account);

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
            membership_state.grace_period_start_timestamp_ms,
            secs_to_millis(membership_state.grace_period_duration_sec),
            now_ms,
        ),
        "CannotExtendNonGracePeriodMembership: membership is not in its grace period"
    );

    // Priced off the membership's own rate limit, exactly as registration is.
    let payment_amount =
        calculate_payment_amount(membership_state.rate_limit, config_state.price_per_unit);

    // Native, exactly as `register` pays: authorization and conservation are
    // the protocol's to enforce, the destination is ours.
    assert!(payer.is_authorized, "Payer must authorize payment");
    assert!(
        payer.account.balance >= payment_amount,
        "Insufficient balance"
    );

    let treasury_id: [u8; 32] = *treasury.account_id.value();
    assert_eq!(
        treasury_id, config_state.treasury_account_id,
        "Wrong treasury"
    );

    membership_state.grace_period_start_timestamp_ms = membership_state
        .grace_period_start_timestamp_ms
        .saturating_add(secs_to_millis(membership_state.grace_period_duration_sec))
        .saturating_add(secs_to_millis(membership_state.active_duration_sec));
    write_borsh(&mut membership, &membership_state, "MembershipState");

    payer.account.balance -= payment_amount;
    treasury.account.balance += payment_amount;

    let states = vec![
        config.account,
        membership.account,
        payer.account,
        treasury.account,
        clock_account.account,
    ];
    SpelOutput::execute(states, vec![])
}

pub fn erase(
    mut config: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    tree_id: [u8; 32],
    subtree_id: u32,
) -> Output {
    let now_ms = require_clock_ms(&clock_account);

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
            membership_state.grace_period_start_timestamp_ms,
            secs_to_millis(membership_state.grace_period_duration_sec),
            now_ms,
        ),
        "CannotEraseUnexpiredMembership: membership has not expired yet"
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

    let states = vec![
        config.account,
        tree_main.account,
        membership.account,
        bottom_subtree.account,
        clock_account.account,
    ];
    SpelOutput::execute(states, vec![merkle_remove])
}
