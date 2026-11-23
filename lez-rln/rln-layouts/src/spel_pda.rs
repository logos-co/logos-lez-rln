//! SPEL PDA seed-combination helpers shared between guest and host.
//!
//! SPEL's `compute_pda` combines seeds via `SHA-256(s1 || s2 || ...)`. Each
//! seed is a 32-byte array. Single-seed mode returns the seed verbatim
//! (matches SPEL's optimization). Labels are zero-padded UTF-8 (`seed_from_str`),
//! and `u32` args are LE bytes in the first 4 of a 32-byte buffer (`ToSeed for u32`).

use sha2::{Digest, Sha256};

/// Zero-pad a string label to 32 bytes (matches SPEL's `seed_from_str`).
pub fn label_seed(label: &str) -> [u8; 32] {
    let bytes = label.as_bytes();
    assert!(bytes.len() <= 32, "label too long");
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

/// Right-pad a `u32` arg into the 32-byte SPEL seed form (LE bytes in first 4).
pub fn u32_seed(v: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&v.to_le_bytes());
    out
}

/// The id of the tree `owner` creates under `label`: `["tree", owner, label]`.
///
/// The registration program computes it from the account that signed
/// `Initialize`, so a tree id names its creator: nobody else can initialize
/// that registry, and its id is known before anything is deployed. A string
/// label goes through `label_seed`.
pub fn owner_tree_id(owner: &[u8; 32], label: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("tree"), owner, label])
}

/// Seed of a tree's config PDA: `["config", tree_id]`.
pub fn config_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("config"), tree_id])
}

/// Seed of a tree's main PDA, the account the merkle program keeps the tree
/// at: `["main", tree_id]`. The registration program grants it to the merkle
/// program on every message it sends the tree.
pub fn main_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
}

/// Seed of a member's PDA: `["membership", tree_id, id_commitment]`.
pub fn membership_seed(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("membership"), tree_id, id_commitment])
}

/// SPEL `compute_pda` seed-combine: `SHA-256(s1 || s2 || ...)`. Single-seed mode
/// returns the seed verbatim (matches SPEL's optimization).
pub fn combine_seeds(seeds: &[&[u8; 32]]) -> [u8; 32] {
    assert!(!seeds.is_empty(), "PDA requires at least one seed");
    if seeds.len() == 1 {
        return *seeds[0];
    }
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host derives the same PDAs the guest checks its receivers
    /// against; these seeds must not drift.
    #[test]
    fn seeds_combine_label_and_args() {
        let tree_id = [0x11; 32];
        assert_eq!(
            config_seed(&tree_id),
            combine_seeds(&[&label_seed("config"), &tree_id])
        );
        assert_eq!(
            main_seed(&tree_id),
            combine_seeds(&[&label_seed("main"), &tree_id])
        );
        assert_eq!(
            membership_seed(&tree_id, &[1; 32]),
            combine_seeds(&[&label_seed("membership"), &tree_id, &[1; 32]])
        );
        assert_ne!(config_seed(&tree_id), main_seed(&tree_id));
        assert_ne!(
            membership_seed(&tree_id, &[1; 32]),
            membership_seed(&tree_id, &[2; 32])
        );
    }

    /// Pinned: a deployment plan is computed from this before the chain
    /// exists, so the value must never drift.
    #[test]
    fn owner_tree_id_is_pinned() {
        let owner = [0x11; 32];
        let relay = owner_tree_id(&owner, &label_seed("relay"));
        let pinned = [
            0x74, 0x38, 0xd4, 0xe1, 0xe3, 0xd0, 0x9a, 0x58, 0x0b, 0xe6, 0x6f, 0x11, 0xcc, 0x88,
            0xbb, 0x88, 0x5c, 0x81, 0xde, 0x22, 0x84, 0x74, 0x67, 0x40, 0xd7, 0x65, 0xcc, 0x40,
            0xb0, 0x59, 0x60, 0x46,
        ];
        assert_eq!(relay, pinned);
        assert_ne!(relay, owner_tree_id(&owner, &label_seed("mix")));
        assert_ne!(relay, owner_tree_id(&[0x12; 32], &label_seed("relay")));
    }
}
