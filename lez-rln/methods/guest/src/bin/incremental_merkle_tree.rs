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
use nssa_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};
use rln_layouts::MerkleOpcode;

type Instruction = Vec<u8>;

fn main() {
    let call = read_lee_call::<Instruction>();
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = match call {
        ProgramCall::Execute(input, data) => (input, data),
        // ProgramCall is #[non_exhaustive], so a wildcard is required; naming
        // Unsupported alongside it is what keeps clippy::wildcard_enum_match_arm
        // satisfied, and makes a future variant visible here rather than silently
        // absorbed.
        other @ ProgramCall::Unsupported(..) | other => respond_unsupported_call(other),
    };

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

    // Each handler returns one post-account per declared account, in the same
    // order, so the two zip cleanly. The tree only ever rewrites data, never
    // balances, hence the zero balance delta throughout.
    assert_eq!(
        pre_states.len(),
        post_states.len(),
        "merkle handler returned {} accounts for {} declared",
        post_states.len(),
        pre_states.len(),
    );
    let state_diffs: Vec<AccountStateDiff> = pre_states
        .into_iter()
        .zip(post_states)
        .map(|(pre, post)| AccountStateDiff::new(pre, BalanceDiff::Add(0), post.data))
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
