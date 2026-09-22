//! Shared Borsh-encoded state structs for the SPEL `rln_registration` program.
//!
//! These mirror the `#[account_type]` definitions in
//! `methods/guest/src/bin/rln_registration.rs`. The guest binary re-uses
//! these by wrapping them in the `#[account_type]` macro; the host can either
//! deserialize via `borsh::from_slice` or read individual fields by the
//! offset constants in `src/rln/constants.rs` (kept consistent with this
//! struct's field declaration order).

use borsh::{BorshDeserialize, BorshSerialize};

/// Borsh layout for the registration program's config account.
///
/// Fixed size: 144 bytes. Field declaration order matches the byte layout
/// (Borsh encodes fixed-width primitives + fixed arrays in declaration order
/// with no length prefixes).
///
/// Offset-based readers (`src/rln/constants.rs`, and the module's own copy in
/// logos-rln-modules) resolve each field by byte position, and there is no
/// version discriminator to tell one layout from another. So a field removed
/// from the middle silently re-points every reader after it: an old config
/// read through new offsets decodes as plausible garbage — a wrong treasury,
/// a wrong price — rather than failing. Removing or reordering a field means
/// regenerating those tables in the same change, and readers should assert the
/// account's exact size before trusting any offset.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ConfigState {
    pub merkle_program_id: [u8; 32],
    pub tree_id: [u8; 32],
    /// Native atomic units charged per unit of rate limit.
    pub price_per_unit: u128,
    /// Plain public account the price is credited to.
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships_sec: u32,
    pub grace_period_duration_for_new_memberships_sec: u32,
}

/// Borsh layout for a per-member account in the SPEL registration program.
///
/// Fixed size: 112 bytes.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MembershipState {
    pub leaf_index: u64,
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    /// Snapshotted from the config at registration.
    pub grace_period_start_timestamp_ms: u64,
    pub active_duration_sec: u32,
    pub grace_period_duration_sec: u32,
    /// The account that paid the deposit, and the only one `Erase` refunds it
    /// to. `Slash` forfeits it to the treasury instead.
    pub holder: [u8; 32],
    /// Native atomic units held in the tree's escrow on this membership's
    /// behalf.
    pub deposit_amount: u128,
}

/// Serialized size of [`ConfigState`], in bytes.
///
/// Offset readers in the host and in `logos-lez-rln-module` assert an account
/// is exactly this long before trusting a byte offset into it. `ConfigState`
/// carries no version discriminator, so the length is the only thing that
/// distinguishes this layout from an older one.
pub const CONFIG_STATE_SIZE: usize = 144;

/// Serialized size of [`MembershipState`], in bytes.
pub const MEMBERSHIP_STATE_SIZE: usize = 112;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the byte layout both offset tables are derived from. A field added
    /// or removed changes this number, and a reader that was not regenerated
    /// decodes the wrong bytes without erroring — so this failing is the
    /// signal to go regenerate them.
    #[test]
    fn config_state_is_the_size_its_readers_assume() {
        let config = ConfigState {
            merkle_program_id: [1; 32],
            tree_id: [2; 32],
            price_per_unit: 3,
            treasury_account_id: [4; 32],
            total_registrations: 5,
            max_total_rate_limit: 6,
            current_total_rate_limit: 7,
            active_duration_for_new_memberships_sec: 8,
            grace_period_duration_for_new_memberships_sec: 9,
        };
        let bytes = borsh::to_vec(&config).expect("ConfigState serializes");
        assert_eq!(bytes.len(), CONFIG_STATE_SIZE);
    }

    /// Each field is recoverable at the offset its readers use. Size alone
    /// cannot catch a reorder that keeps the total the same.
    #[test]
    fn config_state_fields_sit_where_the_offset_readers_look() {
        let config = ConfigState {
            merkle_program_id: [0xAA; 32],
            tree_id: [0xBB; 32],
            price_per_unit: 0x1122_3344_5566_7788,
            treasury_account_id: [0xCC; 32],
            total_registrations: 0x0102_0304,
            max_total_rate_limit: 0x0506_0708,
            current_total_rate_limit: 0x090A_0B0C,
            active_duration_for_new_memberships_sec: 0x0D0E,
            grace_period_duration_for_new_memberships_sec: 0x0F10,
        };
        let b = borsh::to_vec(&config).expect("ConfigState serializes");
        assert_eq!(&b[0..32], &[0xAA; 32], "merkle_program_id @0");
        assert_eq!(&b[32..64], &[0xBB; 32], "tree_id @32");
        assert_eq!(
            u128::from_le_bytes(b[64..80].try_into().unwrap()),
            0x1122_3344_5566_7788,
            "price_per_unit @64",
        );
        assert_eq!(&b[80..112], &[0xCC; 32], "treasury_account_id @80");
        assert_eq!(
            u64::from_le_bytes(b[112..120].try_into().unwrap()),
            0x0102_0304,
            "total_registrations @112",
        );
        assert_eq!(
            u64::from_le_bytes(b[120..128].try_into().unwrap()),
            0x0506_0708,
            "max_total_rate_limit @120",
        );
        assert_eq!(
            u64::from_le_bytes(b[128..136].try_into().unwrap()),
            0x090A_0B0C,
            "current_total_rate_limit @128",
        );
        assert_eq!(
            u32::from_le_bytes(b[136..140].try_into().unwrap()),
            0x0D0E,
            "active_duration_sec @136",
        );
        assert_eq!(
            u32::from_le_bytes(b[140..144].try_into().unwrap()),
            0x0F10,
            "grace_period_duration_sec @140",
        );
    }

    #[test]
    fn membership_state_is_the_size_its_readers_assume() {
        let membership = MembershipState {
            leaf_index: 1,
            rate_limit: 2,
            id_commitment: [3; 32],
            grace_period_start_timestamp_ms: 4,
            active_duration_sec: 5,
            grace_period_duration_sec: 6,
            holder: [7; 32],
            deposit_amount: 8,
        };
        let bytes = borsh::to_vec(&membership).expect("MembershipState serializes");
        assert_eq!(bytes.len(), MEMBERSHIP_STATE_SIZE);
    }
}
