//! Byte offsets and sizes for `ConfigState` / `MembershipState` so the host
//! can read individual fields without pulling in Borsh + the full struct decl.
//!
//! Hand-computed: Borsh writes fixed-width primitives in declaration order
//! with no length prefix for fixed-size arrays, so each offset is the running
//! sum of the preceding field sizes. Source of truth for field order is the
//! guest's `#[account_type]` definitions (kept in sync via a size_of assert
//! against `rln_layouts::{ConfigState, MembershipState}`).

pub use crate::merkle_tree::{SUBTREE_LEAVES, TREE_DEPTH};

/// Computes the subtree ID for a given leaf index.
pub fn subtree_id_for_index(leaf_index: u64) -> u32 {
    (leaf_index / SUBTREE_LEAVES as u64) as u32
}

pub use rln_layouts::{MAX_RATE_LIMIT, MIN_RATE_LIMIT};

// Layout source of truth: `rln_layouts::ConfigState`.
//
// There is no version discriminator in the account, so a reader that has not
// been regenerated after a field moved decodes the wrong bytes without
// erroring — a plausible wrong treasury, a plausible wrong price. CONFIG_SIZE
// is the only thing that tells one layout from another: assert it before
// trusting any offset below.
pub const CONFIG_OFFSET_MERKLE_PROGRAM_ID: usize = 0;
pub const CONFIG_OFFSET_TREE_ID: usize = 32;
pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = 64;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 80;
pub const CONFIG_OFFSET_TOTAL_REGISTRATIONS: usize = 112;
pub const CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT: usize = 120;
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = 128;
pub const CONFIG_OFFSET_ACTIVE_DURATION: usize = 136;
pub const CONFIG_OFFSET_GRACE_PERIOD_DURATION: usize = 140;
pub const CONFIG_SIZE: usize = rln_layouts::state::CONFIG_STATE_SIZE;

// Layout source of truth: `rln_layouts::MembershipState`.
pub const MEMBERSHIP_OFFSET_LEAF_INDEX: usize = 0;
pub const MEMBERSHIP_OFFSET_RATE_LIMIT: usize = 8;
pub const MEMBERSHIP_OFFSET_ID_COMMITMENT: usize = 16;
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP: usize = 48;
pub const MEMBERSHIP_OFFSET_ACTIVE_DURATION: usize = 56;
pub const MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION: usize = 60;
pub const MEMBERSHIP_OFFSET_HOLDER: usize = 64;
pub const MEMBERSHIP_OFFSET_DEPOSIT_AMOUNT: usize = 96;
pub const MEMBERSHIP_SIZE: usize = rln_layouts::state::MEMBERSHIP_STATE_SIZE;

pub use rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES;

#[cfg(test)]
mod tests {
    use rln_layouts::{ConfigState, MembershipState};

    use super::*;

    /// Every offset above recovers the field it names from a real serialized
    /// `ConfigState`. The module in logos-rln-modules keeps its own copy of
    /// this table, and the two drifting apart is how a registry read returns
    /// a confident wrong answer — so both sides pin it the same way.
    #[test]
    fn config_offsets_match_the_shared_layout() {
        let config = ConfigState {
            merkle_program_id: [0x11; 32],
            tree_id: [0x22; 32],
            price_per_unit: 0xDEAD_BEEF,
            treasury_account_id: [0x33; 32],
            total_registrations: 0x0A0B,
            max_total_rate_limit: 0x0C0D,
            current_total_rate_limit: 0x0E0F,
            active_duration_for_new_memberships_sec: 0x1011,
            grace_period_duration_for_new_memberships_sec: 0x1213,
        };
        let b = borsh::to_vec(&config).expect("ConfigState serializes");

        assert_eq!(b.len(), CONFIG_SIZE, "CONFIG_SIZE tracks the layout");
        assert_eq!(
            &b[CONFIG_OFFSET_MERKLE_PROGRAM_ID..CONFIG_OFFSET_MERKLE_PROGRAM_ID + 32],
            &[0x11; 32],
        );
        assert_eq!(
            &b[CONFIG_OFFSET_TREE_ID..CONFIG_OFFSET_TREE_ID + 32],
            &[0x22; 32]
        );
        assert_eq!(
            u128::from_le_bytes(
                b[CONFIG_OFFSET_PRICE_PER_UNIT..CONFIG_OFFSET_PRICE_PER_UNIT + 16]
                    .try_into()
                    .unwrap()
            ),
            0xDEAD_BEEF,
        );
        assert_eq!(
            &b[CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32],
            &[0x33; 32],
        );
        assert_eq!(
            u64::from_le_bytes(
                b[CONFIG_OFFSET_TOTAL_REGISTRATIONS..CONFIG_OFFSET_TOTAL_REGISTRATIONS + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0A0B,
        );
        assert_eq!(
            u64::from_le_bytes(
                b[CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT..CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0C0D,
        );
        assert_eq!(
            u64::from_le_bytes(
                b[CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT
                    ..CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0E0F,
        );
        assert_eq!(
            u32::from_le_bytes(
                b[CONFIG_OFFSET_ACTIVE_DURATION..CONFIG_OFFSET_ACTIVE_DURATION + 4]
                    .try_into()
                    .unwrap()
            ),
            0x1011,
        );
        assert_eq!(
            u32::from_le_bytes(
                b[CONFIG_OFFSET_GRACE_PERIOD_DURATION..CONFIG_OFFSET_GRACE_PERIOD_DURATION + 4]
                    .try_into()
                    .unwrap()
            ),
            0x1213,
        );
    }

    /// Same pin for `MembershipState`. `MEMBERSHIP_OFFSET_HOLDER` picks the
    /// account `Erase` refunds to, so an offset that has drifted does not read
    /// a wrong number — it sends the deposit to a wrong account, or refuses
    /// every erase.
    #[test]
    fn membership_offsets_match_the_shared_layout() {
        let membership = MembershipState {
            leaf_index: 0x0102,
            rate_limit: 0x0304,
            id_commitment: [0x44; 32],
            grace_period_start_timestamp_ms: 0x0506,
            active_duration_sec: 0x0708,
            grace_period_duration_sec: 0x090A,
            holder: [0x55; 32],
            deposit_amount: 0xFEED_FACE,
        };
        let b = borsh::to_vec(&membership).expect("MembershipState serializes");

        assert_eq!(
            b.len(),
            MEMBERSHIP_SIZE,
            "MEMBERSHIP_SIZE tracks the layout"
        );
        assert_eq!(
            u64::from_le_bytes(
                b[MEMBERSHIP_OFFSET_LEAF_INDEX..MEMBERSHIP_OFFSET_LEAF_INDEX + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0102,
        );
        assert_eq!(
            u64::from_le_bytes(
                b[MEMBERSHIP_OFFSET_RATE_LIMIT..MEMBERSHIP_OFFSET_RATE_LIMIT + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0304,
        );
        assert_eq!(
            &b[MEMBERSHIP_OFFSET_ID_COMMITMENT..MEMBERSHIP_OFFSET_ID_COMMITMENT + 32],
            &[0x44; 32],
        );
        assert_eq!(
            u64::from_le_bytes(
                b[MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP
                    ..MEMBERSHIP_OFFSET_GRACE_PERIOD_START_TIMESTAMP + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0506,
        );
        assert_eq!(
            u32::from_le_bytes(
                b[MEMBERSHIP_OFFSET_ACTIVE_DURATION..MEMBERSHIP_OFFSET_ACTIVE_DURATION + 4]
                    .try_into()
                    .unwrap()
            ),
            0x0708,
        );
        assert_eq!(
            u32::from_le_bytes(
                b[MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION
                    ..MEMBERSHIP_OFFSET_GRACE_PERIOD_DURATION + 4]
                    .try_into()
                    .unwrap()
            ),
            0x090A,
        );
        assert_eq!(
            &b[MEMBERSHIP_OFFSET_HOLDER..MEMBERSHIP_OFFSET_HOLDER + 32],
            &[0x55; 32],
        );
        assert_eq!(
            u128::from_le_bytes(
                b[MEMBERSHIP_OFFSET_DEPOSIT_AMOUNT..MEMBERSHIP_OFFSET_DEPOSIT_AMOUNT + 16]
                    .try_into()
                    .unwrap()
            ),
            0xFEED_FACE,
        );
    }
}
