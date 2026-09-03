//! Derive-only dump of program ids + tree-scoped PDAs for a tree id, as JSON.
//! Reuses the real derivation (no reimplemented PDA math) so a deployment
//! descriptor's `config_account` stays an honest cache of `tree_id`, and
//! `program_id` reflects the actual guest binaries — surfacing guest drift.
//!
//! ```bash
//! LEZ_RLN_TREE_ID_HEX=<64hex> cargo run --bin derive_accounts   # run from lez-rln/
//! ```

use logos_lez_rln::rln::{
    client::{load_programs, tree_id_from_env},
    derive_config_account, derive_escrow_account, derive_tree_main_account,
};
use nssa_core::program::ProgramId;

fn hex32(p: &ProgramId) -> String {
    let bytes: [u8; 32] = bytemuck::cast(*p);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let tree_id = tree_id_from_env();
    let (registration, merkle) = load_programs();
    let reg_id = registration.id();
    let merkle_id = merkle.id();
    println!(
        "{{\"registration_program_id\":\"{}\",\"merkle_program_id\":\"{}\",\"config_account\":\"{}\",\"tree_main_account\":\"{}\",\"escrow_account\":\"{}\"}}",
        hex32(&reg_id),
        hex32(&merkle_id),
        derive_config_account(&reg_id, &tree_id),
        derive_tree_main_account(&reg_id, &tree_id),
        derive_escrow_account(&reg_id, &tree_id),
    );
}
