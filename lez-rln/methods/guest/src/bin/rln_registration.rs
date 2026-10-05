//! RLN registration guest program. The logic lives in
//! [`logos_lez_rln_guest::program`].

use logos_lez_rln_guest::program::{self, Effect};
use rln_layouts::Instruction;

fn main() {
    nssa_core::program::run_program::<Instruction, Effect, [u8], Vec<u8>>(
        program::plan,
        program::apply,
    )
}
