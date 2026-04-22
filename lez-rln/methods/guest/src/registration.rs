//! RLN Registration logic.
//!
//! This module provides the core business logic for RLN registration,
//! separate from the RISC-V I/O handling in the binary.
//!
//! # Registration Flows
//!
//! ## Direct Flow
//! Single atomic transaction: payment and registration happen together.
//!
//! ## Credit Flow
//! Two-phase flow for unlinkable registration:
//! 1. Buy credits: Pay tokens -> receive credits
//! 2. Register: Burn credits -> register with rate_limit = amount burned

use crate::hash::{hash_pair, validate_field_element};
use crate::layouts;
use crate::merkle_tree::SUBTREE_LEAVES;
use nssa_core::Timestamp;
use nssa_core::account::AccountWithMetadata;
use nssa_core::program::{ChainedCall, PdaSeed};

// Re-export rate limit and expiration constants / helpers from shared crate
pub use crate::layouts::{
    MIN_RATE_LIMIT, MAX_RATE_LIMIT,
    CLOCK_50_ACCOUNT_ID_BYTES,
    is_in_grace_period, is_expired,
};

// ============================================================================
// Account Size Constants (re-exported from layouts)
// ============================================================================

/// Total size of config account data (224 bytes).
pub use crate::layouts::ConfigLayout;
pub const CONFIG_SIZE: usize = ConfigLayout::SIZE;

/// Size of token holding account (49 bytes).
pub use crate::layouts::TokenHoldingLayout;
pub const TOKEN_HOLDING_SIZE: usize = TokenHoldingLayout::SIZE;

// ============================================================================
// Merkle Tree Account Layout
// ============================================================================

pub use rln_layouts::OFFSET_NEXT_INDEX as TREE_OFFSET_NEXT_INDEX;

/// Size of membership account data (72 bytes).
pub use crate::layouts::MembershipLayout;
pub const MEMBERSHIP_SIZE: usize = MembershipLayout::SIZE;

// ============================================================================
// Config Data Operations
// ============================================================================

/// Parsed configuration from config account.
#[derive(Debug, Clone)]
pub struct RegistrationConfig {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 24],
    pub payment_token_id: [u8; 32],
    pub receipt_token_id: [u8; 32],
    pub price_per_unit: u128,
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships: u32,
    pub grace_period_duration_for_new_memberships: u32,
}

impl RegistrationConfig {
    /// Parse config from account data using zero-copy layout.
    pub fn from_data(data: &[u8]) -> Self {
        assert!(data.len() >= CONFIG_SIZE, "Config data too short");
        let layout = layouts::ConfigLayout::parse(data);

        Self {
            merkle_program_id: layout.merkle_program_id,
            tree_id: layout.tree_id,
            payment_token_id: layout.payment_token_id,
            receipt_token_id: layout.receipt_token_id,
            price_per_unit: layout.price_per_unit(),
            treasury_account_id: layout.treasury_account_id,
            total_registrations: layout.total_registrations(),
            max_total_rate_limit: layout.max_total_rate_limit(),
            current_total_rate_limit: layout.current_total_rate_limit(),
            active_duration_for_new_memberships: layout.active_duration_for_new_memberships(),
            grace_period_duration_for_new_memberships: layout.grace_period_duration_for_new_memberships(),
        }
    }

    /// Serialize config to bytes using zero-copy layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![0u8; CONFIG_SIZE];
        let layout = layouts::ConfigLayout::parse_mut(&mut data);

        layout.merkle_program_id = self.merkle_program_id;
        layout.tree_id = self.tree_id;
        layout.payment_token_id = self.payment_token_id;
        layout.receipt_token_id = self.receipt_token_id;
        layout.set_price_per_unit(self.price_per_unit);
        layout.treasury_account_id = self.treasury_account_id;
        layout.set_total_registrations(self.total_registrations);
        layout.set_max_total_rate_limit(self.max_total_rate_limit);
        layout.set_current_total_rate_limit(self.current_total_rate_limit);
        layout.set_active_duration_for_new_memberships(self.active_duration_for_new_memberships);
        layout.set_grace_period_duration_for_new_memberships(self.grace_period_duration_for_new_memberships);

        data
    }

    /// Create config with updated rate limit tracking for registration.
    /// Increments total_registrations and current_total_rate_limit.
    pub fn with_registration(&self, rate_limit: u64) -> Self {
        let mut new = self.clone();
        new.total_registrations += 1;
        new.current_total_rate_limit += rate_limit;
        new
    }

    /// Create config with updated tracking for erasure (slash/expire).
    /// Decrements total_registrations and current_total_rate_limit.
    pub fn with_erasure(&self, rate_limit: u64) -> Self {
        let mut new = self.clone();
        new.total_registrations = new.total_registrations.saturating_sub(1);
        new.current_total_rate_limit = new.current_total_rate_limit.saturating_sub(rate_limit);
        new
    }

    /// Check if adding a new registration with the given rate limit would
    /// exceed the maximum total rate limit.
    pub fn can_register(&self, rate_limit: u64) -> bool {
        self.current_total_rate_limit + rate_limit <= self.max_total_rate_limit
    }
}

/// Build initial config data for initialization.
pub fn build_config_data(
    merkle_program_id: &[u8; 32],
    tree_id: &[u8; 24],
    payment_token_id: &[u8; 32],
    credit_token_id: &[u8; 32],
    price_per_unit: u128,
    treasury_account_id: &[u8; 32],
    max_total_rate_limit: u64,
    active_duration_for_new_memberships: u32,
    grace_period_duration_for_new_memberships: u32,
) -> Vec<u8> {
    let config = RegistrationConfig {
        merkle_program_id: *merkle_program_id,
        tree_id: *tree_id,
        payment_token_id: *payment_token_id,
        receipt_token_id: *credit_token_id,
        price_per_unit,
        treasury_account_id: *treasury_account_id,
        total_registrations: 0,
        max_total_rate_limit,
        current_total_rate_limit: 0,
        active_duration_for_new_memberships,
        grace_period_duration_for_new_memberships,
    };
    config.to_bytes()
}

// ============================================================================
// Token Operations
// ============================================================================

pub fn parse_token_holding(data: &[u8]) -> (/* definition_id */ [u8; 32], /* balance */ u128) {
    let layout = layouts::TokenHoldingLayout::parse(data);
    (layout.definition_id, layout.balance())
}

// ============================================================================
// Validation
// ============================================================================

/// Validate rate limit is within allowed range.
///
/// # Panics
/// If rate_limit is below MIN_RATE_LIMIT or above MAX_RATE_LIMIT.
pub fn validate_rate_limit(rate_limit: u64) {
    assert!(
        rate_limit >= MIN_RATE_LIMIT,
        "Rate limit {} below minimum {}",
        rate_limit, MIN_RATE_LIMIT
    );
    assert!(
        rate_limit <= MAX_RATE_LIMIT,
        "Rate limit {} above maximum {}",
        rate_limit, MAX_RATE_LIMIT
    );
}

/// Calculate payment amount for a given rate limit.
pub fn calculate_payment_amount(rate_limit: u64, price_per_unit: u128) -> u128 {
    price_per_unit * (rate_limit as u128)
}

// ============================================================================
// Leaf Computation
// ============================================================================

/// Compute the leaf value for merkle tree insertion.
///
/// The leaf is H(id_commitment, rate_limit).
pub fn compute_registration_leaf(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
    validate_field_element(id_commitment);
    let mut rate_bytes = [0u8; 32];
    rate_bytes[..8].copy_from_slice(&rate_limit.to_le_bytes());
    hash_pair(id_commitment, &rate_bytes)
}

// ============================================================================
// PDA Seed Derivation
// ============================================================================

/// Derive PDA seed for tree main account.
pub fn derive_tree_main_seed(tree_id: &[u8; 24]) -> PdaSeed {
    PdaSeed::new(rln_layouts::main_seed(tree_id))
}

/// Derive PDA seed for bottom subtree account.
pub fn derive_subtree_seed(tree_id: &[u8; 24], subtree_id: u32) -> PdaSeed {
    PdaSeed::new(rln_layouts::subtree_seed(tree_id, subtree_id))
}

/// Derive PDA seed for credit token definition.
pub fn derive_credit_token_seed(tree_id: &[u8; 24]) -> PdaSeed {
    PdaSeed::new(rln_layouts::credit_token_seed(tree_id))
}

/// Derive PDA seed for config account.
pub fn derive_config_seed(tree_id: &[u8; 24]) -> PdaSeed {
    PdaSeed::new(rln_layouts::config_seed(tree_id))
}

/// Derive PDA seed for credit supply holder account.
pub fn derive_credit_supply_seed(tree_id: &[u8; 24]) -> PdaSeed {
    PdaSeed::new(rln_layouts::credit_supply_seed(tree_id))
}

/// Derive PDA seed for membership account.
///
/// The seed is hash(tree_id || id_commitment) to create a unique 32-byte seed.
pub fn derive_membership_seed(tree_id: &[u8; 24], id_commitment: &[u8; 32]) -> PdaSeed {
    let seed = membership_seed_bytes(tree_id, id_commitment);
    PdaSeed::new(seed)
}

/// Compute the raw 32-byte seed for membership PDA derivation.
///
/// This is separate from derive_membership_seed for cases where you need
/// the raw bytes without wrapping in PdaSeed.
pub fn membership_seed_bytes(tree_id: &[u8; 24], id_commitment: &[u8; 32]) -> [u8; 32] {
    validate_field_element(id_commitment);
    let mut tree_id_padded = [0u8; 32];
    tree_id_padded[0..24].copy_from_slice(tree_id);
    hash_pair(&tree_id_padded, id_commitment)
}

// ============================================================================
// Membership Account Operations
// ============================================================================

/// Parsed membership account data.
#[derive(Debug, Clone)]
pub struct MembershipData {
    pub leaf_index: u64,
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    pub grace_period_start_timestamp: Timestamp,
    pub active_duration: u32,
    pub grace_period_duration: u32,
    pub holder_account_id: [u8; 32],
}

impl MembershipData {
    /// Parse membership data from account data using zero-copy layout.
    pub fn from_data(data: &[u8]) -> Self {
        assert!(data.len() >= MEMBERSHIP_SIZE, "Membership data too short");
        let layout = layouts::MembershipLayout::parse(data);

        Self {
            leaf_index: layout.leaf_index(),
            rate_limit: layout.rate_limit(),
            id_commitment: layout.id_commitment,
            grace_period_start_timestamp: layout.grace_period_start_timestamp(),
            active_duration: layout.active_duration(),
            grace_period_duration: layout.grace_period_duration(),
            holder_account_id: layout.holder_account_id,
        }
    }

    /// Serialize membership data to bytes using zero-copy layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![0u8; MEMBERSHIP_SIZE];
        let layout = layouts::MembershipLayout::parse_mut(&mut data);

        layout.set_leaf_index(self.leaf_index);
        layout.set_rate_limit(self.rate_limit);
        layout.id_commitment = self.id_commitment;
        layout.set_grace_period_start_timestamp(self.grace_period_start_timestamp);
        layout.set_active_duration(self.active_duration);
        layout.set_grace_period_duration(self.grace_period_duration);
        layout.holder_account_id = self.holder_account_id;

        data
    }
}

/// Create membership account data.
pub fn create_membership_data(
    leaf_index: u64,
    rate_limit: u64,
    id_commitment: &[u8; 32],
    grace_period_start_timestamp: Timestamp,
    active_duration: u32,
    grace_period_duration: u32,
    holder_account_id: &[u8; 32],
) -> Vec<u8> {
    let membership = MembershipData {
        leaf_index,
        rate_limit,
        id_commitment: *id_commitment,
        grace_period_start_timestamp,
        active_duration,
        grace_period_duration,
        holder_account_id: *holder_account_id,
    };
    membership.to_bytes()
}

// ============================================================================
// Merkle Tree Helpers
// ============================================================================

/// Read next_index from tree main account data.
pub fn read_tree_next_index(tree_main_data: &[u8]) -> u64 {
    u64::from_le_bytes(
        tree_main_data[TREE_OFFSET_NEXT_INDEX..TREE_OFFSET_NEXT_INDEX + 8].try_into().unwrap()
    )
}

// ============================================================================
// Chained Call Helpers
// ============================================================================

/// Serialize a token instruction for use in a chained call.
pub fn serialize_token_instruction(instruction: &token_core::Instruction) -> Vec<u32> {
    risc0_zkvm::serde::to_vec(instruction).unwrap()
}

/// Clone an account with `is_authorized` set to true.
pub fn authorize(account: &AccountWithMetadata) -> AccountWithMetadata {
    let mut authorized = account.clone();
    authorized.is_authorized = true;
    authorized
}

/// Build a merkle insert instruction for a chained call.
///
/// Format: `[opcode=1(1), expected_index(8), leaf_value(32)]` = 41 bytes.
pub fn build_merkle_insert_instruction(next_index: u64, leaf_value: &[u8; 32]) -> Vec<u8> {
    let mut instruction = vec![1u8]; // Insert opcode
    instruction.extend_from_slice(&next_index.to_le_bytes());
    instruction.extend_from_slice(leaf_value);
    instruction
}

/// Build a merkle remove instruction for a chained call.
///
/// Format: `[opcode=2(1), leaf_index(8)]` = 9 bytes.
pub fn build_merkle_remove_instruction(leaf_index: u64) -> Vec<u8> {
    let mut instruction = vec![2u8]; // Remove opcode
    instruction.extend_from_slice(&leaf_index.to_le_bytes());
    instruction
}

/// Prepare authorized merkle accounts (tree_main + bottom subtree) and PDA seeds
/// for a chained call to the merkle tree program.
pub fn prepare_merkle_accounts(
    tree_main: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    tree_id: &[u8; 24],
    subtree_id: u32,
) -> (Vec<AccountWithMetadata>, Vec<PdaSeed>) {
    let merkle_accounts = vec![
        authorize(tree_main),
        authorize(bottom_subtree),
    ];
    let pda_seeds = vec![
        derive_tree_main_seed(tree_id),
        derive_subtree_seed(tree_id, subtree_id),
    ];
    (merkle_accounts, pda_seeds)
}

/// Build the merkle `remove` chained call for a membership being torn down.
/// Shared by the `slash` and `erase` flows.
pub fn build_membership_remove_call(
    config: &RegistrationConfig,
    tree_main: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    leaf_index: u64,
) -> ChainedCall {
    let subtree_id = (leaf_index / SUBTREE_LEAVES as u64) as u32;
    let (pre_states, pda_seeds) = prepare_merkle_accounts(
        tree_main, bottom_subtree, &config.tree_id, subtree_id,
    );
    ChainedCall {
        program_id: bytemuck::cast(config.merkle_program_id),
        instruction_data: risc0_zkvm::serde::to_vec(&build_merkle_remove_instruction(leaf_index)).unwrap(),
        pre_states,
        pda_seeds,
    }
}

// ============================================================================
// Clock Helpers
// ============================================================================

/// Decode a clock account's borsh-encoded `ClockAccountData` blob and return
/// its unix timestamp field.
pub fn parse_clock_timestamp(data: &[u8]) -> Timestamp {
    clock_core::ClockAccountData::from_bytes(data).timestamp
}

/// Validate that `clock_account` is the expected CLOCK_50 system account and
/// return its current unix timestamp.
pub fn require_clock(clock_account: &AccountWithMetadata) -> Timestamp {
    assert!(
        *clock_account.account_id.value() == CLOCK_50_ACCOUNT_ID_BYTES,
        "Wrong clock account provided"
    );
    parse_clock_timestamp(clock_account.account.data.as_ref())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Config Tests
    // ========================================================================

    #[test]
    fn test_config_roundtrip() {
        let config = RegistrationConfig {
            merkle_program_id: [1u8; 32],
            tree_id: [2u8; 24],
            payment_token_id: [3u8; 32],
            receipt_token_id: [4u8; 32],
            price_per_unit: 1000,
            treasury_account_id: [5u8; 32],
            total_registrations: 42,
            max_total_rate_limit: 100000,
            current_total_rate_limit: 5000,
            active_duration_for_new_memberships: 2_592_000,
            grace_period_duration_for_new_memberships: 604_800,
        };

        let bytes = config.to_bytes();
        let parsed = RegistrationConfig::from_data(&bytes);

        assert_eq!(parsed.merkle_program_id, config.merkle_program_id);
        assert_eq!(parsed.tree_id, config.tree_id);
        assert_eq!(parsed.payment_token_id, config.payment_token_id);
        assert_eq!(parsed.receipt_token_id, config.receipt_token_id);
        assert_eq!(parsed.price_per_unit, config.price_per_unit);
        assert_eq!(parsed.treasury_account_id, config.treasury_account_id);
        assert_eq!(parsed.total_registrations, config.total_registrations);
        assert_eq!(parsed.max_total_rate_limit, config.max_total_rate_limit);
        assert_eq!(parsed.current_total_rate_limit, config.current_total_rate_limit);
        assert_eq!(parsed.active_duration_for_new_memberships, config.active_duration_for_new_memberships);
        assert_eq!(parsed.grace_period_duration_for_new_memberships, config.grace_period_duration_for_new_memberships);
    }

    #[test]
    fn test_build_config_data() {
        let merkle_id = [1u8; 32];
        let tree_id = [2u8; 24];
        let payment_id = [3u8; 32];
        let receipt_id = [4u8; 32];
        let price = 500u128;
        let treasury = [5u8; 32];
        let max_rate_limit = 100000u64;

        let data = build_config_data(
            &merkle_id, &tree_id, &payment_id, &receipt_id, price, &treasury,
            max_rate_limit, 3600, 1800,
        );
        let config = RegistrationConfig::from_data(&data);

        assert_eq!(config.merkle_program_id, merkle_id);
        assert_eq!(config.tree_id, tree_id);
        assert_eq!(config.total_registrations, 0);
        assert_eq!(config.max_total_rate_limit, max_rate_limit);
        assert_eq!(config.current_total_rate_limit, 0);
        assert_eq!(config.active_duration_for_new_memberships, 3600);
        assert_eq!(config.grace_period_duration_for_new_memberships, 1800);
    }

    #[test]
    fn test_config_rate_limit_tracking() {
        let config = RegistrationConfig {
            merkle_program_id: [0u8; 32],
            tree_id: [0u8; 24],
            payment_token_id: [0u8; 32],
            receipt_token_id: [0u8; 32],
            price_per_unit: 0,
            treasury_account_id: [0u8; 32],
            total_registrations: 0,
            max_total_rate_limit: 1000,
            current_total_rate_limit: 0,
            active_duration_for_new_memberships: 0,
            grace_period_duration_for_new_memberships: 0,
        };

        // Can register with 500 rate limit
        assert!(config.can_register(500));

        // Register and check tracking
        let after_reg = config.with_registration(500);
        assert_eq!(after_reg.total_registrations, 1);
        assert_eq!(after_reg.current_total_rate_limit, 500);

        // Can register another 500
        assert!(after_reg.can_register(500));
        // Cannot register 501 (would exceed max)
        assert!(!after_reg.can_register(501));

        // Erase and check tracking
        let after_erase = after_reg.with_erasure(500);
        assert_eq!(after_erase.total_registrations, 0);
        assert_eq!(after_erase.current_total_rate_limit, 0);
    }

    // ========================================================================
    // Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_rate_limit_valid() {
        validate_rate_limit(MIN_RATE_LIMIT);
        validate_rate_limit(MAX_RATE_LIMIT);
        validate_rate_limit(300);
    }

    #[test]
    #[should_panic(expected = "below minimum")]
    fn test_validate_rate_limit_too_low() {
        validate_rate_limit(MIN_RATE_LIMIT - 1);
    }

    #[test]
    #[should_panic(expected = "above maximum")]
    fn test_validate_rate_limit_too_high() {
        validate_rate_limit(MAX_RATE_LIMIT + 1);
    }

    #[test]
    fn test_calculate_payment_amount() {
        let price_per_unit = 10u128;
        let rate_limit = 100u64;
        assert_eq!(calculate_payment_amount(rate_limit, price_per_unit), 1000);

        assert_eq!(calculate_payment_amount(600, 5), 3000);
    }

    // ========================================================================
    // Leaf Computation Tests
    // ========================================================================

    #[test]
    fn test_compute_registration_leaf() {
        let id_commitment = [1u8; 32];
        let rate_limit = 100u64;

        let leaf = compute_registration_leaf(&id_commitment, rate_limit);

        // Should be deterministic
        let leaf2 = compute_registration_leaf(&id_commitment, rate_limit);
        assert_eq!(leaf, leaf2);

        // Different inputs should produce different leaves
        let leaf3 = compute_registration_leaf(&id_commitment, 200);
        assert_ne!(leaf, leaf3);
    }

    // ========================================================================
    // PDA Seed Tests
    // ========================================================================

    #[test]
    fn test_derive_tree_main_seed_deterministic() {
        let tree_id = [1u8; 24];
        let seed1 = derive_tree_main_seed(&tree_id);
        let seed2 = derive_tree_main_seed(&tree_id);
        assert!(seed1 == seed2, "Same input should produce same seed");
    }

    #[test]
    fn test_derive_tree_main_seed_different_for_different_trees() {
        let tree_id1 = [1u8; 24];
        let tree_id2 = [2u8; 24];
        let seed1 = derive_tree_main_seed(&tree_id1);
        let seed2 = derive_tree_main_seed(&tree_id2);
        assert!(seed1 != seed2, "Different trees should produce different seeds");
    }

    #[test]
    fn test_derive_subtree_seed_deterministic() {
        let tree_id = [1u8; 24];
        let seed1 = derive_subtree_seed(&tree_id, 5);
        let seed2 = derive_subtree_seed(&tree_id, 5);
        assert!(seed1 == seed2, "Same input should produce same seed");
    }

    #[test]
    fn test_derive_subtree_seed_different_for_different_ids() {
        let tree_id = [1u8; 24];
        let seed1 = derive_subtree_seed(&tree_id, 5);
        let seed2 = derive_subtree_seed(&tree_id, 6);
        assert!(seed1 != seed2, "Different subtree IDs should produce different seeds");
    }

    #[test]
    fn test_derive_credit_token_seed_deterministic() {
        let tree_id = [1u8; 24];
        let seed1 = derive_credit_token_seed(&tree_id);
        let seed2 = derive_credit_token_seed(&tree_id);
        assert!(seed1 == seed2, "Same input should produce same seed");
    }

    #[test]
    fn test_derive_config_seed_deterministic() {
        let tree_id = [1u8; 24];
        let seed1 = derive_config_seed(&tree_id);
        let seed2 = derive_config_seed(&tree_id);
        assert!(seed1 == seed2, "Same input should produce same seed");
    }

    #[test]
    fn test_all_seed_types_are_distinct() {
        // Verify that main, subtree, credit, and config seeds are all different
        let tree_id = [1u8; 24];
        let main_seed = derive_tree_main_seed(&tree_id);
        let subtree_seed = derive_subtree_seed(&tree_id, 0);
        let credit_seed = derive_credit_token_seed(&tree_id);
        let config_seed = derive_config_seed(&tree_id);

        assert!(main_seed != subtree_seed, "main and subtree seeds should differ");
        assert!(main_seed != credit_seed, "main and credit seeds should differ");
        assert!(main_seed != config_seed, "main and config seeds should differ");
        assert!(subtree_seed != credit_seed, "subtree and credit seeds should differ");
        assert!(subtree_seed != config_seed, "subtree and config seeds should differ");
        assert!(credit_seed != config_seed, "credit and config seeds should differ");
    }

    // ========================================================================
    // Membership Tests
    // ========================================================================

    #[test]
    fn test_membership_data_roundtrip() {
        let leaf_index = 42u64;
        let rate_limit = 300u64;
        let id_commitment = [7u8; 32];
        let grace_start = 1_700_000_000u64;
        let active = 2_592_000u32;
        let grace = 604_800u32;
        let holder = [9u8; 32];

        let data = create_membership_data(
            leaf_index, rate_limit, &id_commitment, grace_start, active, grace, &holder,
        );
        let parsed = MembershipData::from_data(&data);

        assert_eq!(parsed.leaf_index, leaf_index);
        assert_eq!(parsed.rate_limit, rate_limit);
        assert_eq!(parsed.id_commitment, id_commitment);
        assert_eq!(parsed.grace_period_start_timestamp, grace_start);
        assert_eq!(parsed.active_duration, active);
        assert_eq!(parsed.grace_period_duration, grace);
        assert_eq!(parsed.holder_account_id, holder);
    }

    #[test]
    fn test_membership_data_size() {
        let data = create_membership_data(0, 100, &[0u8; 32], 0, 0, 0, &[0u8; 32]);
        assert_eq!(data.len(), MEMBERSHIP_SIZE);
    }

    #[test]
    fn test_is_in_grace_period_boundaries() {
        let start = 1_000u64;
        let duration = 100u32;
        assert!(!is_in_grace_period(start, duration, 999));
        assert!(is_in_grace_period(start, duration, 1000));
        assert!(is_in_grace_period(start, duration, 1099));
        assert!(!is_in_grace_period(start, duration, 1100));
        assert!(!is_in_grace_period(start, duration, 5000));
    }

    #[test]
    fn test_is_expired_boundaries() {
        let start = 1_000u64;
        let duration = 100u32;
        assert!(!is_expired(start, duration, 999));
        assert!(!is_expired(start, duration, 1099));
        assert!(is_expired(start, duration, 1100));
        assert!(is_expired(start, duration, 5000));
    }

    #[test]
    fn test_grace_period_zero_duration_transitions_directly_to_expired() {
        let start = 1_000u64;
        assert!(!is_in_grace_period(start, 0, 1_000));
        assert!(is_expired(start, 0, 1_000));
    }

    #[test]
    fn test_derive_membership_seed_deterministic() {
        let tree_id = [1u8; 24];
        let id_commitment = [2u8; 32];

        let seed1 = derive_membership_seed(&tree_id, &id_commitment);
        let seed2 = derive_membership_seed(&tree_id, &id_commitment);
        assert!(seed1 == seed2, "Same input should produce same seed");
    }

    #[test]
    fn test_derive_membership_seed_different_for_different_commitments() {
        let tree_id = [1u8; 24];
        let commit1 = [1u8; 32];
        let commit2 = [2u8; 32];

        let seed1 = derive_membership_seed(&tree_id, &commit1);
        let seed2 = derive_membership_seed(&tree_id, &commit2);
        assert!(seed1 != seed2, "Different commitments should produce different seeds");
    }

    #[test]
    fn test_derive_membership_seed_different_for_different_trees() {
        let tree_id1 = [1u8; 24];
        let tree_id2 = [2u8; 24];
        let id_commitment = [3u8; 32];

        let seed1 = derive_membership_seed(&tree_id1, &id_commitment);
        let seed2 = derive_membership_seed(&tree_id2, &id_commitment);
        assert!(seed1 != seed2, "Different trees should produce different seeds");
    }

    #[test]
    fn test_membership_seed_bytes_matches_derive() {
        let tree_id = [1u8; 24];
        let id_commitment = [2u8; 32];

        let seed_bytes = membership_seed_bytes(&tree_id, &id_commitment);
        let pda_seed = derive_membership_seed(&tree_id, &id_commitment);

        // PdaSeed internally stores the bytes, so comparing should work
        assert!(pda_seed == PdaSeed::new(seed_bytes));
    }
}
