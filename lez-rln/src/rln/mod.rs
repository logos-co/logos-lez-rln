//! Host-side client for the RLN registration program: PDAs, layout offsets,
//! program-id records and transaction-building helpers. The `Instruction`
//! enum is re-exported from `rln-layouts`, which the guest decodes too.

pub mod client;
pub mod constants;
pub mod layouts;
pub mod pda;
pub mod program_ids;

pub use constants::*;
pub use pda::*;
pub use program_ids::{ProgramIds, program_ids_or_exit};
pub use rln_layouts::Instruction;
