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
