//! Deploy (or reuse) both programs, record their ids, and initialize the RLN
//! registry its owner holds under `LEZ_RLN_TREE_LABEL`.
//!
//! The owner signs `Initialize`: `LEZ_RLN_REGISTRY_OWNER`, or the payer. The
//! tree id is made of the owner and the label, so it is printed here, not
//! given; a `LEZ_RLN_TREE_ID_HEX` naming another tree is refused before
//! anything is sent.
//!
//! Programs named by `LEZ_RLN_REGISTRATION_PROGRAM_ID` /
//! `LEZ_RLN_MERKLE_PROGRAM_ID` or by the tree's `programs_<tree>.json` record
//! are reused when their headers carry the local binaries' image ids; the rest
//! are deployed. Re-running against an initialized tree changes nothing.
//!
//! With `LEZ_RLN_DEPLOY_SECRET_FILE` and `LEZ_RLN_DEPLOY_NAME` the programs,
//! the owner and the treasury are the accounts that deployment derives
//! (`rln::deploy_keys`); `deploy_plan` does the same for a whole plan.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin run_setup
//! ```

use logos_lez_rln::rln::{
    client::{
        RegistryParams, TREE_ID_ENV, init_wallet, load_programs, public_key_of, registry_owner,
        resolve_payer, run_setup, save_payment_account, tree_label_from_env,
    },
    deploy_keys::DeployKeys,
    derive_config_account, derive_tree_main_account,
    program_ids::hex_id,
};
use rln_layouts::owner_tree_id;

#[tokio::main]
async fn main() {
    let payer = resolve_payer();
    let keys = DeployKeys::from_env().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    let tree_label = tree_label_from_env();
    let params = RegistryParams::from_env();
    let mut wallet_core = init_wallet().await;
    let (registration_program, merkle_program) = load_programs();

    let owner = registry_owner(&mut wallet_core, keys.as_ref());
    let tree_id = owner_tree_id(owner.value(), &tree_label);
    if let Ok(named) = std::env::var(TREE_ID_ENV)
        && named != hex::encode(tree_id)
    {
        eprintln!(
            "{TREE_ID_ENV} is {named}, but the registry {owner} owns under this label is {}.\n\
             A tree id is no longer chosen: it follows from the account that signs Initialize \
             and LEZ_RLN_TREE_LABEL.",
            hex::encode(tree_id)
        );
        std::process::exit(2);
    }

    println!("=== RLN Setup ===\n");
    let registry = run_setup(
        &mut wallet_core,
        &registration_program,
        &merkle_program,
        &tree_label,
        &params,
        keys.as_ref(),
    )
    .await;
    let programs = registry.programs;

    save_payment_account(&tree_id, &payer);
    println!("Payment account saved: {payer}");
    println!(
        "Payer public key: {}",
        public_key_of(&wallet_core, payer, "payer")
    );
    println!("Registry owner:       {}", registry.owner);
    println!("Tree id:              {}", hex::encode(registry.tree_id));
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
