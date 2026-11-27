//! Deploy (or reuse) the registration and merkle programs, and print their
//! ids. Initializes no tree and writes no `programs_<tree>.json` record.
//!
//! Programs named by `LEZ_RLN_REGISTRATION_PROGRAM_ID` /
//! `LEZ_RLN_MERKLE_PROGRAM_ID` (64 hex each) are reused when their headers
//! carry the local binaries' image ids; the rest are deployed, paid by
//! `LEZ_RLN_PAYER`. A named id whose header is empty or carries another image
//! fails. `run_setup` then takes the printed ids through the same variables.
//!
//! With `LEZ_RLN_DEPLOY_SECRET_FILE` and `LEZ_RLN_DEPLOY_NAME` each program
//! is deployed at the account that deployment's key signs for
//! (`rln::deploy_keys`), so its id is known beforehand.
//!
//! The last lines on stdout, one `key=value` each (the wallet prints its own
//! progress lines before them):
//!
//! ```text
//! registration_program_id=<64 hex>
//! merkle_program_id=<64 hex>
//! registration_program_account=<base58>
//! merkle_program_account=<base58>
//! ```
//!
//! ```bash
//! LEE_WALLET_HOME_DIR=<dir> LEZ_RLN_PAYER=<id> cargo run --bin deploy_programs   # run from lez-rln/
//! ```

use logos_lez_rln::rln::{
    client::{ensure_programs, init_wallet, load_programs},
    deploy_keys::DeployKeys,
    program_ids::{env_program_ids, hex_id},
};

#[tokio::main]
async fn main() {
    let known = env_program_ids().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    let keys = DeployKeys::from_env().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    let mut wallet_core = init_wallet().await;
    let (registration_program, merkle_program) = load_programs();

    println!("=== RLN program deploy ===\n");
    let programs = ensure_programs(
        &mut wallet_core,
        &registration_program,
        &merkle_program,
        known,
        keys.as_ref(),
    )
    .await;

    println!("registration_program_id={}", hex_id(&programs.registration));
    println!("merkle_program_id={}", hex_id(&programs.merkle));
    println!("registration_program_account={}", programs.registration);
    println!("merkle_program_account={}", programs.merkle);
}
