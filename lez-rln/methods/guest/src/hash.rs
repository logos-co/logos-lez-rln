use rln_layouts::TREE_DEPTH;
use rust_poseidon_bn254_pure::{
    bn254::field::Felt,
    poseidon::permutation::{compress_1, compress_2},
};

pub const ZERO: [u8; 32] = [0u8; 32];

pub fn validate_field_element(bytes: &[u8; 32]) {
    let felt = Felt::unsafe_from_le_bytes(bytes);
    assert!(
        Felt::is_valid(&felt),
        "Input is not a valid BN254 field element (must be < prime)"
    );
}

pub fn hash_single(input: &[u8; 32]) -> [u8; 32] {
    validate_field_element(input);
    let hash_felt = compress_1(Felt::unsafe_from_le_bytes(input));
    Felt::to_le_bytes(&hash_felt)
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    validate_field_element(left);
    validate_field_element(right);
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
    assert_eq!(
        depth, TREE_DEPTH,
        "only the pinned tree depth has a precomputed hash table"
    );
    DEFAULT_HASHES.to_vec()
}

/// The empty-subtree hash at every level of a `TREE_DEPTH` tree, root first.
///
/// These are constants — `H(zero, zero)` folded upward — but Poseidon is by far
/// the most expensive thing a guest does, and recomputing the whole ladder cost
/// twenty hashes on *every* merkle instruction. Under LEZ v0.2.5 that is the
/// difference between fitting a transaction's gas limit and being rejected
/// outright, since gas is cycles and the per-transaction ceiling is 10M.
///
/// `default_hashes_match_the_ladder` recomputes them and asserts equality, so
/// this table cannot drift from the hash function or the depth it was built
/// for.
pub const DEFAULT_HASHES: [[u8; 32]; TREE_DEPTH + 1] = [
    [
        71, 215, 252, 20, 166, 86, 33, 62, 171, 40, 226, 227, 204, 122, 94, 228, 102, 31, 148, 158,
        56, 128, 183, 236, 33, 253, 216, 208, 118, 67, 136, 14,
    ],
    [
        97, 204, 243, 153, 58, 190, 76, 68, 26, 33, 65, 74, 39, 46, 107, 97, 42, 71, 100, 69, 134,
        236, 27, 80, 166, 39, 96, 143, 241, 229, 165, 47,
    ],
    [
        157, 52, 135, 60, 190, 170, 164, 168, 127, 172, 181, 140, 168, 21, 5, 139, 123, 89, 57,
        182, 30, 96, 207, 130, 233, 132, 43, 162, 229, 149, 130, 7,
    ],
    [
        120, 157, 160, 46, 163, 221, 17, 29, 97, 83, 185, 81, 105, 30, 215, 254, 188, 225, 169,
        204, 34, 125, 234, 70, 150, 69, 102, 166, 197, 147, 238, 45,
    ],
    [
        85, 63, 24, 57, 22, 236, 92, 123, 77, 173, 178, 148, 140, 197, 153, 166, 7, 41, 243, 93,
        76, 31, 99, 201, 245, 179, 70, 135, 94, 207, 148, 43,
    ],
    [
        42, 149, 188, 157, 85, 151, 172, 202, 101, 130, 86, 26, 87, 40, 183, 241, 69, 35, 165, 59,
        233, 255, 32, 99, 211, 176, 23, 203, 55, 216, 249, 7,
    ],
    [
        56, 210, 86, 184, 178, 126, 213, 40, 213, 29, 55, 80, 234, 110, 124, 70, 6, 33, 247, 80,
        141, 117, 61, 46, 175, 226, 126, 83, 49, 51, 244, 24,
    ],
    [
        225, 241, 177, 96, 68, 119, 164, 103, 240, 141, 198, 157, 203, 68, 26, 38, 236, 167, 132,
        245, 111, 26, 48, 223, 99, 34, 177, 205, 61, 103, 105, 16,
    ],
    [
        100, 72, 182, 70, 132, 238, 57, 168, 35, 213, 254, 95, 213, 36, 49, 220, 129, 228, 129,
        123, 242, 195, 234, 60, 171, 158, 35, 158, 251, 245, 152, 32,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned table must equal the ladder it replaced. This is the only
    /// thing standing between a wrong constant and a tree whose empty subtrees
    /// hash to nonsense, which would be silent until a proof failed to verify.
    #[test]
    fn default_hashes_match_the_ladder() {
        let mut expected = vec![[0u8; 32]; TREE_DEPTH + 1];
        expected[TREE_DEPTH] = ZERO;
        for level in (0..TREE_DEPTH).rev() {
            let child = expected[level + 1];
            expected[level] = hash_pair(&child, &child);
        }
        assert_eq!(DEFAULT_HASHES.to_vec(), expected);
    }
}
