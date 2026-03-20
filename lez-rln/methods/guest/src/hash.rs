use rust_poseidon_bn254_pure::bn254::field::Felt;
use rust_poseidon_bn254_pure::poseidon::permutation::compress_2;

pub const ZERO: [u8; 32] = [0u8; 32];

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let hash_felt = compress_2([
        Felt::unsafe_from_le_bytes(left),
        Felt::unsafe_from_le_bytes(right),
    ]);
    Felt::to_le_bytes(&hash_felt)
}

/// Compute the default/empty hash for a given tree level.
///
/// At the leaf level, the default is `ZERO_VALUE`.
/// For each level up, it's `H(default[level+1], default[level+1])`.
///
/// # Arguments
/// * `depth` - The total depth of the tree
///
/// # Returns
/// A vector of default hashes, indexed by level (0 = root, depth = leaves)
pub fn compute_default_hashes(depth: usize) -> Vec<[u8; 32]> {
    let mut defaults = vec![[0u8; 32]; depth + 1];
    defaults[depth] = ZERO;

    for level in (0..depth).rev() {
        let child_hash = defaults[level + 1];
        defaults[level] = hash_pair(&child_hash, &child_hash);
    }

    defaults
}
