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
        create_funded_user, init_wallet, is_initialized, load_programs, policy_from_env, run_setup,
        save_payment_account, tree_id_from_env,
    },
    derive_config_account, derive_tree_main_account,
};

/// 10 B RLNTOK funded per payment account. At PRICE_PER_UNIT=10_000 and the
/// demo's rateLimit=100, each registration burns 1 M tokens — so each payment
/// account hands out ~10K registrations before depletion forces a re-fund
/// from supply_holding. Tracks the TOKEN_SUPPLY 10x bump in client.rs (10 B
/// supply funded only ~1K regs per account, hit the wall in long dev cycles).
const USER_FUNDING: u128 = 10_000_000_000;

#[tokio::main]
async fn main() {
    let mut wallet_core = init_wallet().await;
    let tree_id = tree_id_from_env();
    let (registration_program, merkle_program) = load_programs();

    println!("=== RLN Setup ===\n");

    let user_holding_id = if is_initialized(&wallet_core, &registration_program, &tree_id).await {
        println!("Registration already initialized, creating new funded account...\n");
        create_funded_user(
            &mut wallet_core,
            &registration_program,
            &tree_id,
            USER_FUNDING,
        )
        .await
    } else {
        println!("First run, deploying programs and initializing tree...\n");
        run_setup(
            &mut wallet_core,
            &registration_program,
            &merkle_program,
            &tree_id,
            USER_FUNDING,
            &policy_from_env(),
        )
        .await
    };

    let tree_main_id = derive_tree_main_account(&registration_program.id(), &tree_id);
    let config_account_id = derive_config_account(&registration_program.id(), &tree_id);

    save_payment_account(&tree_id, &user_holding_id);
    println!("Payment account saved: {}", user_holding_id);
    println!("Tree main account:    {}", tree_main_id);
    println!("Config account:       {}", config_account_id);
}
