//! Deploy programs, create token, initialize the RLN tree, and fund a payment account.
//!
//! Run this once after starting a fresh sequencer. Subsequent runs detect the existing
//! setup and only create a new funded payment account.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin run_setup
//! ```

use logos_lez_rln::rln::{
    client::{
        init_wallet, is_initialized, load_programs, resolve_payer, run_setup, save_payment_account,
        tree_id_from_env,
    },
    derive_config_account, derive_tree_main_account,
};

#[tokio::main]
async fn main() {
    let mut wallet_core = init_wallet().await;
    let tree_id = tree_id_from_env();
    let (registration_program, merkle_program) = load_programs();

    println!("=== RLN Setup ===\n");

    let user_holding_id = if is_initialized(&wallet_core, &registration_program, &tree_id).await {
        println!("Registration already initialized; registrations pay from LEZ_RLN_PAYER\n");
        resolve_payer()
    } else {
        println!("First run, deploying programs and initializing tree...\n");
        run_setup(
            &mut wallet_core,
            &registration_program,
            &merkle_program,
            &tree_id,
        )
        .await
    };

    let tree_main_id = derive_tree_main_account(
        &logos_lez_rln::spel_seeds::program_account(&registration_program.id()),
        &tree_id,
    );
    let config_account_id = derive_config_account(
        &logos_lez_rln::spel_seeds::program_account(&registration_program.id()),
        &tree_id,
    );

    save_payment_account(&tree_id, &user_holding_id);
    println!("Payment account saved: {}", user_holding_id);
    println!("Tree main account:    {}", tree_main_id);
    println!("Config account:       {}", config_account_id);
}
