//! Deploy (or reuse) both programs, record their ids, and initialize the RLN
//! tree for `LEZ_RLN_TREE_ID_HEX`.
//!
//! Programs named by `LEZ_RLN_REGISTRATION_PROGRAM_ID` /
//! `LEZ_RLN_MERKLE_PROGRAM_ID` or by the tree's `programs_<tree>.json` record
//! are reused when their headers carry the local binaries' image ids; the rest
//! are deployed. Re-running against an initialized tree changes nothing.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin run_setup
//! ```

use logos_lez_rln::rln::{
    client::{
        init_wallet, load_programs, resolve_payer, run_setup, save_payment_account,
        tree_id_from_env,
    },
    derive_config_account, derive_tree_main_account,
    program_ids::hex_id,
};

#[tokio::main]
async fn main() {
    let payer = resolve_payer();
    let mut wallet_core = init_wallet().await;
    let tree_id = tree_id_from_env();
    let (registration_program, merkle_program) = load_programs();

    println!("=== RLN Setup ===\n");
    let programs = run_setup(
        &mut wallet_core,
        &registration_program,
        &merkle_program,
        &tree_id,
    )
    .await;

    save_payment_account(&tree_id, &payer);
    println!("Payment account saved: {payer}");
    println!("Registration program: {}", hex_id(&programs.registration));
    println!("Merkle program:       {}", hex_id(&programs.merkle));
    println!(
        "Tree main account:    {}",
        derive_tree_main_account(&programs.registration, &tree_id)
    );
    println!(
        "Config account:       {}",
        derive_config_account(&programs.registration, &tree_id)
    );
}
