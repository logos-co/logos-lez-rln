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
use nssa_core::program::{ProgramInput, ProgramOutput, read_lee_inputs as read_nssa_inputs};
use rln_layouts::MerkleOpcode;

type Instruction = Vec<u8>;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let opcode = MerkleOpcode::from_u8(instruction[0]).expect("Invalid instruction type");
    let post_states = match opcode {
        MerkleOpcode::Initialize => initialize_tree(pre_states.clone()),
        MerkleOpcode::Insert => insert_leaf(pre_states.clone(), &instruction[1..]),
        MerkleOpcode::Remove => {
            let (states, _new_root) = remove_leaf(pre_states.clone(), &instruction[1..]);
            states
        }
        MerkleOpcode::Set => set_leaf(pre_states.clone(), &instruction[1..]),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
