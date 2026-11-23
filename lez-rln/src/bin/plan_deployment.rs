//! Print the plan of a deployment: every id it will have, before any of it
//! is on chain. Reads no chain and no wallet.
//!
//! The ids are a function of the deployment's secret, its name and the
//! registries' labels (`rln::deploy_keys`, `rln::deploy_plan`). The output is
//! public: account ids and public keys, safe to commit into a network preset.
//!
//! ```bash
//! LEZ_RLN_DEPLOY_SECRET_FILE=<file> LEZ_RLN_DEPLOY_NAME=<name> \
//!   cargo run --bin plan_deployment -- --registry relay:100:600 --registry mix:20:100
//! ```
//!
//! `--registry <label>[:<min rate>:<max rate>]` plans one registry; repeat it
//! for more. Bounds default to `LEZ_RLN_MIN_RATE_LIMIT` /
//! `LEZ_RLN_MAX_RATE_LIMIT`, durations to `LEZ_RLN_ACTIVE_DURATION_SECS` /
//! `LEZ_RLN_GRACE_PERIOD_DURATION_SECS`, as `run_setup` reads them.
//!
//! Run from `lez-rln/` with the guest binaries built and the plan records
//! their image ids, which `deploy_plan` then holds a deploy to. Without them
//! the plan records none: the ids do not depend on the code.

use logos_lez_rln::rln::{
    client::{MERKLE_TREE_BINARY, REGISTRATION_BINARY, RegistryParams},
    deploy_keys::{DEPLOY_NAME_ENV, DEPLOY_SECRET_FILE_ENV, DeployKeys},
    deploy_plan::{DeploymentPlan, RegistrySpec},
};
use nssa::program::Program;

fn usage() -> ! {
    eprintln!(
        "usage: plan_deployment --registry <label>[:<min rate>:<max rate>] [--registry ...]\n\
         \n\
         {DEPLOY_SECRET_FILE_ENV} names the file holding the deployment secret (64 hex\n\
         characters); {DEPLOY_NAME_ENV} names the deployment."
    );
    std::process::exit(2);
}

fn fail(message: &str) -> ! {
    eprintln!("plan_deployment: {message}");
    std::process::exit(2);
}

/// The image id of the guest binary at `path`, when it is there.
fn image_id(path: &str) -> Option<nssa_core::program::ProgramId> {
    let bytecode = std::fs::read(path).ok()?;
    let program = Program::new(bytecode.into())
        .unwrap_or_else(|e| fail(&format!("{path} is not a program binary: {e:?}")));
    Some(program.id())
}

fn main() {
    let defaults = RegistryParams::from_env();
    let mut registries = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--registry" => {
                let raw = args.next().unwrap_or_else(|| usage());
                registries.push(RegistrySpec::parse(&raw, defaults).unwrap_or_else(|e| fail(&e)));
            }
            _ => usage(),
        }
    }
    let keys = DeployKeys::from_env()
        .unwrap_or_else(|e| fail(&e))
        .unwrap_or_else(|| fail(&format!("{DEPLOY_SECRET_FILE_ENV} is not set")));
    let plan = DeploymentPlan::derive(&keys, &registries).unwrap_or_else(|e| fail(&e));

    let images = image_id(REGISTRATION_BINARY).zip(image_id(MERKLE_TREE_BINARY));
    if images.is_none() {
        eprintln!(
            "plan_deployment: no guest binaries at {REGISTRATION_BINARY}; the plan records no \
             image ids"
        );
    }
    let json = plan.to_json(
        images
            .as_ref()
            .map(|(registration, merkle)| (registration, merkle)),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json).expect("a plan serializes")
    );
}
