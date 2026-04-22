//! RLN Registration Program
//!
//! This program controls access to an incremental merkle tree. It is the only
//! entity that can initialize or insert leaves into the tree, enforced via
//! `is_authorized` checks in the merkle tree program.
//!
//! # Architecture
//!
//! Tree accounts are PDAs derived from this registration program's ID:
//! - `tree_main = PDA(registration_program_id, tree_id + "__main__")`
//! - `subtree = PDA(registration_program_id, tree_id + 0xFF + subtree_id)`
//! - `credit_token_def = PDA(registration_program_id, tree_id + "_receipt")`
//!
//! # Registration Flows
//!
//! ## Direct Flow (instruction 1: `register`)
//! Single transaction: payment and registration happen atomically.
//! Simple but payment is publicly linked to registration.
//!
//! ## Credit Flow (instructions 2 + 3: `buy_credits` + `register_with_credits`)
//! Two-phase flow for unlinkable registration:
//! 1. Buy credits: Pay X tokens → receive X credits (private to private)
//! 2. Register: Burn Y credits → register with rate_limit = Y (private to public)
//!
//! Credits can be privately transferred between purchase and registration,
//! breaking the on-chain link between payment and identity.
//!
//! # Instructions (via `Instruction` enum)
//!
//! - `Initialize` - Setup config, create credit token, init merkle tree
//! - `Register` - Direct payment + registration (atomic, linked)
//! - `BuyCredits` - Swap payment tokens for credits
//! - `RegisterWithCredits` - Burn credits to register (rate_limit = amount burned)
//! - `Slash` - Remove a spammer by providing their identity_secret
//!
//! # Rate Limit
//!
//! Rate limit must be between 100 and 600.
//! - Direct: specified in instruction, payment = rate_limit * price_per_unit
//! - With credits: equals the number of credits burned

use logos_lez_rln_guest::layouts::Instruction;
use logos_lez_rln_guest::registration::{
    // Config operations
    RegistrationConfig, build_config_data,
    // Token operations
    parse_token_holding,
    // Merkle operations
    read_tree_next_index,
    // Validation and computation
    validate_rate_limit, compute_registration_leaf, calculate_payment_amount,
    // PDA seeds
    derive_config_seed, derive_tree_main_seed,
    derive_credit_token_seed, derive_credit_supply_seed,
    derive_membership_seed,
    // Membership operations
    create_membership_data, MembershipData,
    // Chained call helpers
    serialize_token_instruction, authorize,
    build_merkle_insert_instruction, build_merkle_remove_instruction,
    prepare_merkle_accounts,
};
use logos_lez_rln_guest::merkle_tree::SUBTREE_LEAVES;
use logos_lez_rln_guest::hash::{hash_single, validate_field_element};
use nssa_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{
        AccountPostState, ChainedCall, Claim, ProgramId, ProgramInput, ProgramOutput,
        read_nssa_inputs,
    },
};

fn main() {
    let (ProgramInput { pre_states, instruction }, instruction_data) =
        read_nssa_inputs::<Instruction>();

    match instruction {
        Instruction::Initialize {
            registration_program_id, merkle_program_id, tree_id,
            payment_token_id, price_per_unit, treasury_account_id,
            token_program_id, max_total_rate_limit,
        } => {
            initialize(
                registration_program_id, merkle_program_id, tree_id,
                payment_token_id, price_per_unit, treasury_account_id,
                token_program_id, max_total_rate_limit,
                instruction_data,
            )
        }
        Instruction::Register { registration_program_id, id_commitment, rate_limit } => {
            assert!(pre_states.len() == 5, "Register requires exactly 5 accounts");
            register(
                registration_program_id, id_commitment, rate_limit,
                &pre_states[0], &pre_states[1], &pre_states[2], &pre_states[3],
                &pre_states[4],
                instruction_data,
            )
        }
        Instruction::BuyCredits { amount } => {
            assert!(pre_states.len() >= 5, "BuyCredits requires 5 accounts");
            buy_credits(
                amount,
                &pre_states[0], &pre_states[1], &pre_states[2],
                &pre_states[3], &pre_states[4],
                instruction_data,
            )
        }
        Instruction::RegisterWithCredits {
            registration_program_id, id_commitment, amount_to_burn,
        } => {
            assert!(pre_states.len() == 5, "RegisterWithCredits requires exactly 5 accounts");
            register_with_credits(
                registration_program_id, id_commitment, amount_to_burn,
                &pre_states[0], &pre_states[1], &pre_states[2], &pre_states[3],
                &pre_states[4],
                instruction_data,
            )
        }
        Instruction::Slash { identity_secret } => {
            assert!(pre_states.len() == 4, "Slash requires exactly 4 accounts");
            slash(
                identity_secret,
                &pre_states[0], &pre_states[1], &pre_states[2], &pre_states[3],
                instruction_data,
            )
        }
    }
}

// ============================================================================
// Initialize
// ============================================================================

fn initialize(
    registration_program_id: [u8; 32],
    merkle_program_id: [u8; 32],
    tree_id: [u8; 24],
    payment_token_id: [u8; 32],
    price_per_unit: u128,
    treasury_account_id: [u8; 32],
    token_program_id: [u8; 32],
    max_total_rate_limit: u64,
    instruction_data: Vec<u32>,
) {
    assert!(max_total_rate_limit > 0, "Max total rate limit must be positive");

    let reg_program_id: ProgramId = bytemuck::cast(registration_program_id);
    let config_id = AccountId::from((&reg_program_id, &derive_config_seed(&tree_id)));
    let credit_token_id = AccountId::from((&reg_program_id, &derive_credit_token_seed(&tree_id)));
    let credit_supply_id = AccountId::from((&reg_program_id, &derive_credit_supply_seed(&tree_id)));
    let tree_main_id = AccountId::from((&reg_program_id, &derive_tree_main_seed(&tree_id)));

    let config = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: config_id,
    };
    let credit_token_def = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: credit_token_id.clone(),
    };
    let credit_supply = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: credit_supply_id,
    };
    let tree_main = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: tree_main_id,
    };

    let credit_token_id_bytes: [u8; 32] = *credit_token_id.value();
    let config_data = build_config_data(
        &merkle_program_id,
        &tree_id,
        &payment_token_id,
        &credit_token_id_bytes,
        price_per_unit,
        &treasury_account_id,
        max_total_rate_limit,
    );
    let mut config_post = config.account.clone();
    config_post.data = config_data.try_into().unwrap();

    let token_create_instruction = token_core::Instruction::NewFungibleDefinition {
        name: "RLNREC".to_string(),
        total_supply: 0,
    };

    let token_create_call = ChainedCall {
        program_id: bytemuck::cast(token_program_id),
        instruction_data: serialize_token_instruction(&token_create_instruction),
        pre_states: vec![authorize(&credit_token_def), authorize(&credit_supply)],
        pda_seeds: vec![
            derive_credit_token_seed(&tree_id),
            derive_credit_supply_seed(&tree_id),
        ],
    };

    let merkle_init_instruction: Vec<u8> = vec![0u8];
    let merkle_chained_call = ChainedCall {
        program_id: bytemuck::cast(merkle_program_id),
        instruction_data: risc0_zkvm::serde::to_vec(&merkle_init_instruction).unwrap(),
        pre_states: vec![authorize(&tree_main)],
        pda_seeds: vec![derive_tree_main_seed(&tree_id)],
    };

    let output_pre_states = vec![config, credit_token_def, credit_supply, tree_main];
    let post_states = vec![
        AccountPostState::new_claimed_if_default(config_post, Claim::Pda(derive_config_seed(&tree_id))),
        AccountPostState::new(Account::default()),
        AccountPostState::new(Account::default()),
        AccountPostState::new(Account::default()),
    ];
    ProgramOutput::new(instruction_data, output_pre_states, post_states)
        .with_chained_calls(vec![token_create_call, merkle_chained_call])
        .write();
}

fn register(
    registration_program_id: [u8; 32],
    id_commitment: [u8; 32],
    rate_limit: u64,
    config_account: &AccountWithMetadata,
    tree_main: &AccountWithMetadata,
    user_holding: &AccountWithMetadata,
    treasury_holding: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    instruction_data: Vec<u32>,
) {
    validate_field_element(&id_commitment);
    validate_rate_limit(rate_limit);

    let config = RegistrationConfig::from_data(config_account.account.data.as_ref());

    assert!(config.can_register(rate_limit), "Would exceed max total rate limit");

    let payment_amount = calculate_payment_amount(rate_limit, config.price_per_unit);

    let reg_program_id: ProgramId = bytemuck::cast(registration_program_id);
    let membership_seed = derive_membership_seed(&config.tree_id, &id_commitment);
    let membership_id = AccountId::from((&reg_program_id, &membership_seed));
    let membership = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: membership_id,
    };

    assert!(user_holding.is_authorized, "User must authorize payment");

    let (user_token, user_balance) = parse_token_holding(user_holding.account.data.as_ref());
    assert!(user_token == config.payment_token_id, "Wrong payment token");
    assert!(user_balance >= payment_amount, "Insufficient balance");

    let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
    assert!(treasury_id == config.treasury_account_id, "Wrong treasury");

    let token_program_id = user_holding.account.program_owner;
    let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

    let next_index = read_tree_next_index(tree_main.account.data.as_ref());
    let subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    let updated_config = config.with_registration(rate_limit);

    let (merkle_accounts, pda_seeds) = prepare_merkle_accounts(
        tree_main, bottom_subtree, &config.tree_id, subtree_id,
    );

    let merkle_instruction = build_merkle_insert_instruction(next_index, &leaf_value);

    let merkle_call = ChainedCall {
        program_id: bytemuck::cast(config.merkle_program_id),
        instruction_data: risc0_zkvm::serde::to_vec(&merkle_instruction).unwrap(),
        pre_states: merkle_accounts,
        pda_seeds,
    };

    let token_instruction = token_core::Instruction::Transfer { amount_to_transfer: payment_amount };
    let token_call = ChainedCall {
        program_id: token_program_id,
        instruction_data: serialize_token_instruction(&token_instruction),
        pre_states: vec![authorize(user_holding), treasury_holding.clone()],
        pda_seeds: vec![],
    };

    let membership_data = create_membership_data(next_index, rate_limit, &id_commitment);
    let mut membership_post = membership.account.clone();
    membership_post.data = membership_data.try_into().unwrap();

    let mut config_post = config_account.account.clone();
    config_post.data = updated_config.to_bytes().try_into().unwrap();

    let output_pre_states = vec![
        config_account.clone(), tree_main.clone(),
        user_holding.clone(), treasury_holding.clone(),
        bottom_subtree.clone(),
        membership,
    ];
    let post_states = vec![
        AccountPostState::new(config_post),
        AccountPostState::new(tree_main.account.clone()),
        AccountPostState::new(user_holding.account.clone()),
        AccountPostState::new(treasury_holding.account.clone()),
        AccountPostState::new(bottom_subtree.account.clone()),
        AccountPostState::new_claimed_if_default(membership_post, Claim::Pda(membership_seed)),
    ];

    ProgramOutput::new(instruction_data, output_pre_states, post_states)
        .with_chained_calls(vec![token_call, merkle_call])
        .write();
}

fn buy_credits(
    amount: u128,
    config_account: &AccountWithMetadata,
    credit_token_def: &AccountWithMetadata,
    user_payment_holding: &AccountWithMetadata,
    treasury_holding: &AccountWithMetadata,
    user_credit_holding: &AccountWithMetadata,
    instruction_data: Vec<u32>,
) {

    assert!(amount > 0, "Amount must be positive");

    let config = RegistrationConfig::from_data(config_account.account.data.as_ref());
    let payment_amount = config.price_per_unit * amount;

    let receipt_def_id: [u8; 32] = *credit_token_def.account_id.value();
    assert!(receipt_def_id == config.receipt_token_id, "Wrong receipt token definition");

    assert!(user_payment_holding.is_authorized, "User must authorize payment");
    let (user_token, user_balance) = parse_token_holding(user_payment_holding.account.data.as_ref());
    assert!(user_token == config.payment_token_id, "Wrong payment token");
    assert!(user_balance >= payment_amount, "Insufficient balance");

    let treasury_id: [u8; 32] = *treasury_holding.account_id.value();
    assert!(treasury_id == config.treasury_account_id, "Wrong treasury");

    let token_program_id = user_payment_holding.account.program_owner;

    let transfer_instruction = token_core::Instruction::Transfer { amount_to_transfer: payment_amount };
    let transfer_call = ChainedCall {
        program_id: token_program_id,
        instruction_data: serialize_token_instruction(&transfer_instruction),
        pre_states: vec![authorize(user_payment_holding), treasury_holding.clone()],
        pda_seeds: vec![],
    };

    let mint_instruction = token_core::Instruction::Mint { amount_to_mint: amount };
    let mint_call = ChainedCall {
        program_id: token_program_id,
        instruction_data: serialize_token_instruction(&mint_instruction),
        pre_states: vec![authorize(credit_token_def), user_credit_holding.clone()],
        pda_seeds: vec![derive_credit_token_seed(&config.tree_id)],
    };

    let post_states = vec![
        AccountPostState::new(config_account.account.clone()),
        AccountPostState::new(credit_token_def.account.clone()),
        AccountPostState::new(user_payment_holding.account.clone()),
        AccountPostState::new(treasury_holding.account.clone()),
        AccountPostState::new(user_credit_holding.account.clone()),
    ];

    let output_pre_states = vec![
        config_account.clone(), credit_token_def.clone(),
        user_payment_holding.clone(), treasury_holding.clone(),
        user_credit_holding.clone(),
    ];

    ProgramOutput::new(instruction_data, output_pre_states, post_states)
        .with_chained_calls(vec![transfer_call, mint_call])
        .write();
}

fn register_with_credits(
    registration_program_id: [u8; 32],
    id_commitment: [u8; 32],
    amount_to_burn: u64,
    config_account: &AccountWithMetadata,
    credit_token_def: &AccountWithMetadata,
    tree_main: &AccountWithMetadata,
    user_credit_holding: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    instruction_data: Vec<u32>,
) {
    validate_field_element(&id_commitment);

    let rate_limit = amount_to_burn;
    validate_rate_limit(rate_limit);

    let config = RegistrationConfig::from_data(config_account.account.data.as_ref());

    assert!(config.can_register(rate_limit), "Would exceed max total rate limit");

    let reg_program_id: ProgramId = bytemuck::cast(registration_program_id);
    let membership_seed = derive_membership_seed(&config.tree_id, &id_commitment);
    let membership_id = AccountId::from((&reg_program_id, &membership_seed));
    let membership = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: membership_id,
    };

    let receipt_def_id: [u8; 32] = *credit_token_def.account_id.value();
    assert!(receipt_def_id == config.receipt_token_id, "Wrong receipt token");

    assert!(user_credit_holding.is_authorized, "User must authorize burn");
    let (user_token, user_balance) = parse_token_holding(user_credit_holding.account.data.as_ref());
    assert!(user_token == config.receipt_token_id, "Wrong token type");
    assert!(user_balance >= rate_limit as u128, "Insufficient receipt tokens");

    let token_program_id = user_credit_holding.account.program_owner;

    let burn_instruction = token_core::Instruction::Burn { amount_to_burn: rate_limit as u128 };
    let burn_call = ChainedCall {
        program_id: token_program_id,
        instruction_data: serialize_token_instruction(&burn_instruction),
        pre_states: vec![credit_token_def.clone(), authorize(user_credit_holding)],
        pda_seeds: vec![],
    };

    let leaf_value = compute_registration_leaf(&id_commitment, rate_limit);

    let next_index = read_tree_next_index(tree_main.account.data.as_ref());
    let subtree_id = (next_index / SUBTREE_LEAVES as u64) as u32;
    let updated_config = config.with_registration(rate_limit);

    let (merkle_accounts, merkle_pda_seeds) = prepare_merkle_accounts(
        tree_main, bottom_subtree, &config.tree_id, subtree_id,
    );

    let merkle_instruction = build_merkle_insert_instruction(next_index, &leaf_value);

    let merkle_call = ChainedCall {
        program_id: bytemuck::cast(config.merkle_program_id),
        instruction_data: risc0_zkvm::serde::to_vec(&merkle_instruction).unwrap(),
        pre_states: merkle_accounts,
        pda_seeds: merkle_pda_seeds,
    };

    let membership_data = create_membership_data(next_index, rate_limit, &id_commitment);
    let mut membership_post = membership.account.clone();
    membership_post.data = membership_data.try_into().unwrap();

    let mut config_post = config_account.account.clone();
    config_post.data = updated_config.to_bytes().try_into().unwrap();

    let output_pre_states = vec![
        config_account.clone(), credit_token_def.clone(),
        tree_main.clone(), user_credit_holding.clone(),
        bottom_subtree.clone(),
        membership,
    ];
    let post_states = vec![
        AccountPostState::new(config_post),
        AccountPostState::new(credit_token_def.account.clone()),
        AccountPostState::new(tree_main.account.clone()),
        AccountPostState::new(user_credit_holding.account.clone()),
        AccountPostState::new(bottom_subtree.account.clone()),
        AccountPostState::new_claimed_if_default(membership_post, Claim::Pda(membership_seed)),
    ];

    ProgramOutput::new(instruction_data, output_pre_states, post_states)
        .with_chained_calls(vec![burn_call, merkle_call])
        .write();
}

fn slash(
    identity_secret: [u8; 32],
    config_account: &AccountWithMetadata,
    tree_main: &AccountWithMetadata,
    membership_account: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    instruction_data: Vec<u32>,
) {
    validate_field_element(&identity_secret);

    let id_commitment = hash_single(&identity_secret);
    let config = RegistrationConfig::from_data(config_account.account.data.as_ref());

    let membership_bytes = membership_account.account.data.as_ref();
    assert!(!membership_bytes.is_empty(), "Membership account is empty - member doesn't exist or already slashed");

    let membership = MembershipData::from_data(membership_bytes);
    assert!(membership.id_commitment == id_commitment, "id_commitment mismatch - provided identity_secret doesn't match membership");

    let subtree_id = (membership.leaf_index / SUBTREE_LEAVES as u64) as u32;

    let (merkle_accounts, pda_seeds) = prepare_merkle_accounts(
        tree_main, bottom_subtree, &config.tree_id, subtree_id,
    );

    let merkle_instruction = build_merkle_remove_instruction(membership.leaf_index);

    let merkle_call = ChainedCall {
        program_id: bytemuck::cast(config.merkle_program_id),
        instruction_data: risc0_zkvm::serde::to_vec(&merkle_instruction).unwrap(),
        pre_states: merkle_accounts,
        pda_seeds,
    };

    let mut membership_post = membership_account.account.clone();
    membership_post.data = vec![].try_into().unwrap();

    let updated_config = config.with_erasure(membership.rate_limit);
    let mut config_post = config_account.account.clone();
    config_post.data = updated_config.to_bytes().try_into().unwrap();

    let output_pre_states = vec![
        config_account.clone(), tree_main.clone(),
        membership_account.clone(), bottom_subtree.clone(),
    ];
    let post_states = vec![
        AccountPostState::new(config_post),
        AccountPostState::new(tree_main.account.clone()),
        AccountPostState::new(membership_post),
        AccountPostState::new(bottom_subtree.account.clone()),
    ];

    ProgramOutput::new(instruction_data, output_pre_states, post_states)
        .with_chained_calls(vec![merkle_call])
        .write();
}
