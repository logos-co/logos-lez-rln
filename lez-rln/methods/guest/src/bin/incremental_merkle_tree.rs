//! Incremental Merkle Tree guest program.
//!
//! This program manages an incremental Merkle tree with subtree-based sparse storage.
//! All operations require authorization via `is_authorized` flag.
//!
//! # Instructions
//!
//! - `0`: Initialize - Create empty tree with default hashes
//! - `1`: Insert - Add a leaf at the next available index (sequential)
//! - `2`: Remove - Set a leaf to zero and recompute root (does not change next_index)
//! - `3`: Set - Set a leaf at a specific index (for index reuse, must be zeroed first)

use logos_lez_rln_guest::merkle_tree::{initialize_tree, insert_leaf, remove_leaf, set_leaf};
use nssa_core::program::{ProgramInput, ProgramOutput, read_nssa_inputs};

type Instruction = Vec<u8>;

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states = match instruction[0] {
        0 => initialize_tree(pre_states.clone()),
        1 => insert_leaf(pre_states.clone(), &instruction[1..]),
        2 => {
            let (states, _new_root) = remove_leaf(pre_states.clone(), &instruction[1..]);
            states
        }
        3 => set_leaf(pre_states.clone(), &instruction[1..]),
        _ => panic!("Invalid instruction type"),
    };

    ProgramOutput::new(instruction_words, pre_states, post_states).write();
}
