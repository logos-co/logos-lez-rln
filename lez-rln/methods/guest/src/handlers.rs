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
    MerkleOpcode, SUBTREE_LEAVES, combine_seeds, is_expired, is_in_grace_period, label_seed,
    u32_seed,
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

fn receipt_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("receipt"), tree_id])
}

fn supply_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("supply"), tree_id])
}

fn payment_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("payment"), tree_id])
}

fn payment_supply_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("payment_supply"), tree_id])
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
        receipt_token_id: *credit_token.account_id.value(),
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

pub fn initialize_credit_token(
    config: AccountWithMetadata,
    credit_token: AccountWithMetadata,
    credit_supply: AccountWithMetadata,
    tree_id: [u8; 32],
) -> Output {
    let config_state = require_config(&config, &tree_id);
    let token_create = ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(&credit_token), authorized(&credit_supply)],
        &token_core::Instruction::NewFungibleDefinition {
            name: "RLNREC".to_string(),
            total_supply: 0,
        },
    )
    .with_pda_seeds(vec![
        PdaSeed::new(receipt_seed(&tree_id)),
        PdaSeed::new(supply_seed(&tree_id)),
    ]);

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(credit_token.account),
        AccountPostState::new(credit_supply.account),
    ];
    SpelOutput::execute(states, vec![token_create])
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

    // Program-authority mint: the definition is this program's `payment` PDA,
    // so the seed alone authorizes it — no human mint key exists in faucet
    // deployments. The destination arrives tx-signed (fresh holdings are
    // claimed Claim::Authorized by the token program).
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
    treasury_holding: AccountWithMetadata,
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
    let payment_amount = calculate_payment_amount(rate_limit, config_state.price_per_unit);

    assert!(user_holding.is_authorized, "User must authorize payment");
    let TokenHolding {
        definition_id: user_token,
        balance: user_balance,
    } = parse_token_holding(user_holding.account.data.as_ref());
    assert_eq!(
        user_token, config_state.payment_token_id,
        "Wrong payment token"
    );
    assert!(user_balance >= payment_amount, "Insufficient balance");

    // The holding's self-reported data is attacker-controllable; only the
    // owning program is not. Require it to be the configured token program so
    // the payment can't be routed to an attacker's no-op program.
    let user_holding_owner: [u8; 32] = bytemuck::cast(user_holding.account.program_owner);
    assert_eq!(
        user_holding_owner, config_state.token_program_id,
        "Payment holding not owned by the configured token program"
    );

    let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
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
        grace_period_start_timestamp,
        &config_state,
    );
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let token_transfer = ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![authorized(&user_holding), treasury_holding.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: payment_amount,
        },
    );

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
        AccountPostState::new(treasury_holding.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
        AccountPostState::new_claimed_if_default(
            membership.account,
            Claim::Pda(PdaSeed::new(membership_seed(&tree_id, &id_commitment))),
        ),
    ];
    SpelOutput::execute(states, vec![token_transfer, merkle_insert])
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

    let membership_state = new_membership_state(
        next_index,
        rate_limit,
        id_commitment,
        grace_period_start_timestamp,
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

pub fn buy_credits(
    config: AccountWithMetadata,
    credit_token_def: AccountWithMetadata,
    user_payment_holding: AccountWithMetadata,
    treasury_holding: AccountWithMetadata,
    user_credit_holding: AccountWithMetadata,
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

    let payment_amount = config_state.price_per_unit.saturating_mul(amount);

    let receipt_def_id: [u8; 32] = *credit_token_def.account_id.value();
    assert_eq!(
        receipt_def_id, config_state.receipt_token_id,
        "Wrong receipt token definition"
    );

    assert!(
        user_payment_holding.is_authorized,
        "User must authorize payment"
    );
    let TokenHolding {
        definition_id: user_token,
        balance: user_balance,
    } = parse_token_holding(user_payment_holding.account.data.as_ref());
    assert_eq!(
        user_token, config_state.payment_token_id,
        "Wrong payment token"
    );
    assert!(user_balance >= payment_amount, "Insufficient balance");

    let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
    assert_eq!(
        treasury_id, config_state.treasury_account_id,
        "Wrong treasury"
    );

    // The holding's owner is the only field an attacker can't forge; require it
    // to be the configured token program and dispatch to that trusted id, not
    // to whatever program the holding claims to belong to.
    let payment_holding_owner: [u8; 32] =
        bytemuck::cast(user_payment_holding.account.program_owner);
    assert_eq!(
        payment_holding_owner, config_state.token_program_id,
        "Payment holding not owned by the configured token program"
    );
    let token_program_id = bytemuck::cast(config_state.token_program_id);
    let transfer = ChainedCall::new(
        token_program_id,
        vec![authorized(&user_payment_holding), treasury_holding.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: payment_amount,
        },
    );
    let mint = ChainedCall::new(
        token_program_id,
        vec![authorized(&credit_token_def), user_credit_holding.clone()],
        &token_core::Instruction::Mint {
            amount_to_mint: amount,
        },
    )
    .with_pda_seeds(vec![PdaSeed::new(receipt_seed(&tree_id))]);

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(credit_token_def.account),
        AccountPostState::new(user_payment_holding.account),
        AccountPostState::new(treasury_holding.account),
        AccountPostState::new(user_credit_holding.account),
    ];
    SpelOutput::execute(states, vec![transfer, mint])
}

#[allow(clippy::too_many_arguments)]
pub fn register_with_credits(
    mut config: AccountWithMetadata,
    credit_token_def: AccountWithMetadata,
    tree_main: AccountWithMetadata,
    user_credit_holding: AccountWithMetadata,
    bottom_subtree: AccountWithMetadata,
    clock_account: AccountWithMetadata,
    mut membership: AccountWithMetadata,
    tree_id: [u8; 32],
    id_commitment: [u8; 32],
    amount_to_burn: u64,
    subtree_id: u32,
) -> Output {
    validate_field_element(&id_commitment);
    let rate_limit = amount_to_burn;
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

    let receipt_def_id: [u8; 32] = *credit_token_def.account_id.value();
    assert_eq!(
        receipt_def_id, config_state.receipt_token_id,
        "Wrong receipt token"
    );

    assert!(
        user_credit_holding.is_authorized,
        "User must authorize burn"
    );
    let TokenHolding {
        definition_id: user_token,
        balance: user_balance,
    } = parse_token_holding(user_credit_holding.account.data.as_ref());
    assert_eq!(
        user_token, config_state.receipt_token_id,
        "Wrong token type"
    );
    assert!(
        user_balance >= rate_limit as u128,
        "Insufficient receipt tokens"
    );

    // Only the owning program is unforgeable; require it to be the configured
    // token program so the burn can't be dispatched to an attacker's no-op.
    let credit_holding_owner: [u8; 32] = bytemuck::cast(user_credit_holding.account.program_owner);
    assert_eq!(
        credit_holding_owner, config_state.token_program_id,
        "Credit holding not owned by the configured token program"
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
        &config_state,
    );
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let burn = ChainedCall::new(
        bytemuck::cast(config_state.token_program_id),
        vec![credit_token_def.clone(), authorized(&user_credit_holding)],
        &token_core::Instruction::Burn {
            amount_to_burn: rate_limit as u128,
        },
    );
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
        AccountPostState::new(credit_token_def.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(user_credit_holding.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
        AccountPostState::new_claimed_if_default(
            membership.account,
            Claim::Pda(PdaSeed::new(membership_seed(&tree_id, &id_commitment))),
        ),
    ];
    SpelOutput::execute(states, vec![burn, merkle_insert])
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
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(membership.account),
        AccountPostState::new(bottom_subtree.account),
    ];
    SpelOutput::execute(states, vec![merkle_remove])
}

pub fn extend(
    config: AccountWithMetadata,
    mut membership: AccountWithMetadata,
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

    membership_state.grace_period_start_timestamp = membership_state
        .grace_period_start_timestamp
        .saturating_add(membership_state.grace_period_duration as u64)
        .saturating_add(membership_state.active_duration as u64);
    write_borsh(&mut membership, &membership_state, "MembershipState");

    let states = vec![
        AccountPostState::new(config.account),
        AccountPostState::new(membership.account),
        AccountPostState::new(clock_account.account),
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
        AccountPostState::new(config.account),
        AccountPostState::new(tree_main.account),
        AccountPostState::new(membership.account),
        AccountPostState::new(bottom_subtree.account),
        AccountPostState::new(clock_account.account),
    ];
    SpelOutput::execute(states, vec![merkle_remove])
}
