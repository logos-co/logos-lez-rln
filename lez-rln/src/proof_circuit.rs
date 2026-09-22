//! The RLN circuit this repo proves against, and the bridge from the on-chain
//! tree's depth up to it.
//!
//! The registry's Merkle tree is shallower than any published circuit, and has
//! to be. LEZ v0.2.5 meters a charged transaction by its declared gas limit at
//! one gas per cycle and refuses anything over ten million; an on-chain insert
//! costs one Poseidon compression — roughly 900,000 cycles — per level, so the
//! tree can afford [`rln_layouts::TREE_DEPTH`] levels and no more.
//!
//! The circuit still demands exactly [`CIRCUIT_DEPTH`] siblings and recomputes
//! the root from them. The levels the tree does not have are empty by
//! construction — nothing can be inserted above its own capacity — so each
//! missing sibling is the empty-subtree root of that height and the real tree
//! is always the left child. Padding is exact rather than approximate: the
//! circuit proves against the root the tree would have had if it had been built
//! to the circuit's depth.
//!
//! Any root the tree reports has to be folded the same way, or a proof's root
//! would never match the window it is checked against.

use std::sync::LazyLock;

use rln::prelude::{
    ArkGroth16Backend, Fr, Hasher, PoseidonHash, RLN, RLNBuilder, Stateless, graph_from_raw,
    zkey_from_raw,
};

/// The depth of the circuit we prove against.
///
/// Ten is the smallest zerokit publishes. It ships those artifacts in its
/// repository but excludes them from the crates.io package to stay under the
/// size limit, so they are vendored here; their circuit version is the one the
/// crate already carries, since the repository's pair is byte for byte the pair
/// embedded in `rln` 3.0.0.
pub const CIRCUIT_DEPTH: usize = 10;

const DEPTH_10_GRAPH: &[u8] = include_bytes!("../resources/tree_depth_10/graph.bin");
const DEPTH_10_ZKEY: &[u8] = include_bytes!("../resources/tree_depth_10/rln_final.arkzkey");

const _: () = assert!(
    rln_layouts::TREE_DEPTH <= CIRCUIT_DEPTH,
    "the on-chain tree cannot be deeper than the circuit that proves membership in it"
);

/// `zero_ladder()[h]` is the root of an all-empty subtree of height `h`, so
/// index 0 is the zero leaf itself.
fn zero_ladder() -> &'static [Fr] {
    static LADDER: LazyLock<Vec<Fr>> = LazyLock::new(|| {
        let mut ladder = vec![Fr::from(0u64)];
        for height in 1..=CIRCUIT_DEPTH {
            let below = ladder[height - 1];
            ladder.push(Hasher::<PoseidonHash>::hash_pair(below, below));
        }
        ladder
    });
    &LADDER
}

/// The stateless engine over the vendored depth-10 circuit, built once — the
/// zkey and graph are several MB and too expensive to clone per call.
///
/// `graph_from_raw` is told the depth it should find, so a mismatched artifact
/// fails here at first use rather than quietly proving against a tree shape
/// nobody expects.
pub fn engine() -> &'static RLN<Stateless, ArkGroth16Backend<PoseidonHash>> {
    static ENGINE: LazyLock<RLN<Stateless, ArkGroth16Backend<PoseidonHash>>> =
        LazyLock::new(|| {
            RLNBuilder::stateless()
                .graph(
                    graph_from_raw(DEPTH_10_GRAPH, Some(CIRCUIT_DEPTH), None)
                        .expect("vendored depth-10 graph must load"),
                )
                .zkey(zkey_from_raw(DEPTH_10_ZKEY).expect("vendored depth-10 zkey must load"))
                .build()
        });
    &ENGINE
}

/// Append the empty-subtree siblings that take a tree-depth path up to the
/// circuit's depth. A path already at that depth is left alone.
pub fn pad_path(elements: &mut Vec<Fr>, indices: &mut Vec<u8>) {
    for height in elements.len()..CIRCUIT_DEPTH {
        elements.push(zero_ladder()[height]);
        indices.push(0);
    }
}

/// Fold a tree-depth root up to the circuit's depth, the same way [`pad_path`]
/// folds the path that produces it.
#[must_use]
pub fn fold_root(mut root: Fr) -> Fr {
    for height in rln_layouts::TREE_DEPTH..CIRCUIT_DEPTH {
        root = Hasher::<PoseidonHash>::hash_pair(root, zero_ladder()[height]);
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Padding a path and folding a root have to agree, because the circuit
    /// derives the root it proves against from the path it is handed. If they
    /// ever disagreed, every proof's root would fall outside the window it is
    /// checked against and nothing would verify.
    #[test]
    fn padding_and_folding_agree() {
        let leaf = Hasher::<PoseidonHash>::hash_pair(Fr::from(11u64), Fr::from(22u64));
        let mut elements: Vec<Fr> = (0..rln_layouts::TREE_DEPTH)
            .map(|i| Fr::from(i as u64 + 7))
            .collect();
        let mut indices = vec![0u8; rln_layouts::TREE_DEPTH];

        let fold_through = |leaf: Fr, elements: &[Fr], indices: &[u8]| {
            let mut node = leaf;
            for (&sibling, &is_right) in elements.iter().zip(indices) {
                node = if is_right == 0 {
                    Hasher::<PoseidonHash>::hash_pair(node, sibling)
                } else {
                    Hasher::<PoseidonHash>::hash_pair(sibling, node)
                };
            }
            node
        };

        let tree_root = fold_through(leaf, &elements, &indices);
        let lifted = fold_root(tree_root);

        pad_path(&mut elements, &mut indices);
        assert_eq!(elements.len(), CIRCUIT_DEPTH);
        assert_eq!(fold_through(leaf, &elements, &indices), lifted);
    }
}
