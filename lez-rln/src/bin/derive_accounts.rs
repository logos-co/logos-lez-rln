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
    derive_config_account,
    derive_tree_main_account,
};
use nssa::AccountId;

fn hex32(id: &AccountId) -> String {
    id.value().iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let tree_id = tree_id_from_env();
    let (registration, merkle) = load_programs();
    // A program is addressed by the account its header sits at. The bytes are
    // the same ones the image id carried, so these JSON fields keep their shape.
    let reg_id = logos_lez_rln::spel_seeds::program_account(&registration.id());
    let merkle_id = logos_lez_rln::spel_seeds::program_account(&merkle.id());
    println!(
        "{{\"registration_program_id\":\"{}\",\"merkle_program_id\":\"{}\",\"config_account\":\"{}\",\"tree_main_account\":\"{}\"}}",
        hex32(&reg_id),
        hex32(&merkle_id),
        derive_config_account(&reg_id, &tree_id),
        derive_tree_main_account(&reg_id, &tree_id),
    );
}
