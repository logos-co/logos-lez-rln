//! Deploy what a plan says, where the plan says, and nothing else.
//!
//! The plan (`plan_deployment`) names every id; the deployment secret holds
//! the keys those ids come from. This tool recomputes the plan from the
//! secret, refuses a plan file that is not the one these keys derive, checks
//! the chain before it sends anything, deploys both programs immutable at
//! the planned accounts, initializes each registry, and reads it all back.
//!
//! Programs are immutable and `Initialize` is one-shot: a wrong binary at a
//! planned account, or a registry initialized with other parameters, is
//! there for good and the planned ids are spent. So nothing is sent unless
//! every planned account is either empty or already holds what the plan
//! says, and a deploy that was interrupted is finished by running again.
//!
//! ```bash
//! LEZ_RLN_DEPLOY_SECRET_FILE=<file> LEE_WALLET_HOME_DIR=<dir> LEZ_RLN_PAYER=<id> \
//!   cargo run --bin deploy_plan -- --plan <plan.json> [--check] [--out <file>]   # run from lez-rln/
//! ```
//!
//! - `--check` stops after the checks and sends nothing.
//! - `--out <file>` writes the plan as deployed: the plan's JSON with `deployed: true` and the
//!   payer that paid.
//! - `--allow-image-change` deploys local guest binaries whose image ids are not the plan's. The
//!   ids stay the plan's; the code does not.
//!
//! `LEZ_RLN_PAYER` pays for everything and names any funded account. Its key
//! is the one in `LEZ_RLN_PAYER_KEY_FILE` when that is set (the file must
//! hold the key of that very account), else the deployment secret's own
//! payer key when that is the account named, else a key the wallet already
//! holds. A payer nothing here can sign for is refused before anything is
//! sent. Exits 0 when the chain holds the plan, 1 when it cannot, 2 on a
//! malformed invocation.

use std::path::PathBuf;

use logos_lez_rln::rln::{
    ProgramIds,
    client::{
        MERKLE_TREE_BINARY, REGISTRATION_BINARY, Wallet, deploy_cost_estimate,
        deploy_segment_count, ensure_programs, import_key, init_wallet, initialize_registry,
        is_initialized, is_tree_initialized, load_programs, program_deployed_at, public_key_of,
        read_config, read_program_header, registry_owner, resolve_payer,
    },
    deploy_keys::{
        DEPLOY_NAME_ENV, DEPLOY_SECRET_FILE_ENV, DeployKeys, PAYER_KEY_FILE_ENV, account_of,
        payer_key_from_env,
    },
    deploy_plan::{
        DeploymentPlan, PlannedRegistry, config_differences, differences, image_mismatch, specs_of,
    },
    program_ids::KnownProgramIds,
};
use nssa::{AccountId, program::Program};
use serde_json::{Value, json};

fn usage() -> ! {
    eprintln!(
        "usage: deploy_plan --plan <plan.json> [--check] [--out <file>] [--allow-image-change]\n\
         \n\
         {DEPLOY_SECRET_FILE_ENV} names the deployment secret; LEE_WALLET_HOME_DIR the wallet;\n\
         LEZ_RLN_PAYER the funded account that pays; {PAYER_KEY_FILE_ENV}, when set, a file\n\
         holding that account's private key."
    );
    std::process::exit(2);
}

fn refuse(message: &str) -> ! {
    eprintln!("deploy_plan: {message}");
    std::process::exit(1);
}

/// What the chain holds at a planned account.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Found {
    Nothing,
    AsPlanned,
}

/// A planned program on chain: absent, or there with the local binary's
/// image. Anything else at its account cannot be undone.
async fn program_found(wallet: &Wallet, header: AccountId, program: &Program, name: &str) -> Found {
    match program_deployed_at(wallet, header, &program.id(), name).await {
        Ok(true) => Found::AsPlanned,
        Ok(false) => Found::Nothing,
        Err(what) => refuse(&format!(
            "the planned {name} account {header} {what}: that account is spent"
        )),
    }
}

/// A planned registry on chain: absent, or initialized as planned.
async fn registry_found(
    wallet: &Wallet,
    programs: &ProgramIds,
    registry: &PlannedRegistry,
) -> Found {
    if !is_initialized(wallet, programs, &registry.tree_id).await {
        return Found::Nothing;
    }
    let config = read_config(wallet, programs, &registry.tree_id).await;
    let found = config_differences(registry, &programs.merkle, &config);
    if !found.is_empty() {
        refuse(&format!(
            "the registry {:?} is initialized, but not as planned:\n  {}",
            registry.label,
            found.join("\n  ")
        ));
    }
    Found::AsPlanned
}

/// How many loader segments the binary at `path` uploads as.
fn segments_of(path: &str) -> usize {
    let bytecode =
        std::fs::read(path).unwrap_or_else(|e| refuse(&format!("cannot read {path}: {e}")));
    deploy_segment_count(&bytecode).unwrap_or_else(|what| refuse(&format!("{path}: {what}")))
}

#[tokio::main]
async fn main() {
    let mut plan_path: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut allow_image_change = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--plan" => plan_path = args.next().map(PathBuf::from),
            "--out" => out_path = args.next().map(PathBuf::from),
            "--check" => check_only = true,
            "--allow-image-change" => allow_image_change = true,
            _ => usage(),
        }
    }
    let plan_path = plan_path.unwrap_or_else(|| usage());

    // ── the plan, and that these keys derive it ───────────────────────
    let file: Value = std::fs::read_to_string(&plan_path)
        .map_err(|e| e.to_string())
        .and_then(|raw| serde_json::from_str(&raw).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| refuse(&format!("cannot read {}: {e}", plan_path.display())));
    let (name, specs) = specs_of(&file).unwrap_or_else(|e| refuse(&e));
    if let Ok(named) = std::env::var(DEPLOY_NAME_ENV)
        && named != name
    {
        refuse(&format!(
            "{DEPLOY_NAME_ENV} is {named:?}, the plan is of {name:?}"
        ));
    }
    let secret_file = std::env::var_os(DEPLOY_SECRET_FILE_ENV)
        .unwrap_or_else(|| refuse(&format!("{DEPLOY_SECRET_FILE_ENV} is not set")));
    let keys = DeployKeys::from_secret_file(std::path::Path::new(&secret_file), &name)
        .unwrap_or_else(|e| refuse(&e));
    let plan = DeploymentPlan::derive(&keys, &specs).unwrap_or_else(|e| refuse(&e));
    let found = differences(&plan.to_json(None), &file);
    if !found.is_empty() {
        refuse(&format!(
            "{} is not the plan this secret derives:\n  {}",
            plan_path.display(),
            found.join("\n  ")
        ));
    }

    // ── the binaries the plan was made for ────────────────────────────
    let (registration_program, merkle_program) = load_programs();
    let image_changes: Vec<String> = [
        image_mismatch(&file, "registration_image_id", &registration_program.id()),
        image_mismatch(&file, "merkle_image_id", &merkle_program.id()),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !image_changes.is_empty() {
        if !allow_image_change {
            refuse(&format!(
                "the local guest binaries are not the plan's (--allow-image-change deploys them \
                 anyway):\n  {}",
                image_changes.join("\n  ")
            ));
        }
        println!(
            "Deploying other images than the plan's:\n  {}",
            image_changes.join("\n  ")
        );
    }

    // ── the chain, before anything is sent ────────────────────────────
    let payer = resolve_payer();
    let payer_key = payer_key_from_env().unwrap_or_else(|e| refuse(&e));
    let mut wallet = init_wallet().await;
    // `plan` is derived from the secret alone, so `plan.payer` is the
    // secret's own payer, whatever the plan file names.
    match payer_key {
        Some(key) => {
            let signs_for = account_of(&key);
            if signs_for != payer {
                refuse(&format!(
                    "the key {PAYER_KEY_FILE_ENV} names signs for {signs_for}, and the payer is \
                     {payer}: name that account as the payer to pay from it"
                ));
            }
            import_key(&mut wallet, key);
        }
        None if payer == plan.payer => {
            import_key(&mut wallet, keys.payer());
        }
        None => {}
    }
    if wallet.get_account_public_signing_key(payer).is_none() {
        refuse(&format!(
            "nothing here signs for the payer {payer}: it is not the deployment secret's payer \
             ({}), {PAYER_KEY_FILE_ENV} names no key, and the wallet holds none for it",
            plan.payer
        ));
    }
    println!("=== Deployment {name} ===\n");
    let registration_found = program_found(
        &wallet,
        plan.programs.registration,
        &registration_program,
        "registration program",
    )
    .await;
    let merkle_found = program_found(
        &wallet,
        plan.programs.merkle,
        &merkle_program,
        "merkle program",
    )
    .await;
    let mut segments = 0;
    for (found, path, what, account) in [
        (
            merkle_found,
            MERKLE_TREE_BINARY,
            "Merkle program",
            plan.programs.merkle,
        ),
        (
            registration_found,
            REGISTRATION_BINARY,
            "Registration program",
            plan.programs.registration,
        ),
    ] {
        if found == Found::Nothing {
            segments += segments_of(path);
            println!("  {what}: to deploy at {account}");
        } else {
            println!("  {what}: deployed at {account}");
        }
    }
    let mut pending = 0;
    for registry in &plan.registries {
        // A registry of a program that is not deployed cannot exist.
        let found = if registration_found == Found::Nothing {
            Found::Nothing
        } else {
            registry_found(&wallet, &plan.programs, registry).await
        };
        let tree = found == Found::AsPlanned
            && is_tree_initialized(&wallet, &plan.programs, &registry.tree_id).await;
        if !tree {
            pending += 1;
        }
        println!(
            "  Registry {:?}: {} at {}",
            registry.label,
            match (found, tree) {
                (Found::Nothing, _) => "to initialize",
                (Found::AsPlanned, false) => "initialized, its tree is not",
                (Found::AsPlanned, true) => "initialized",
            },
            registry.config_account
        );
    }
    if segments == 0 && pending == 0 {
        println!("\nNothing to send: the chain holds the plan.");
    } else {
        let balance = wallet
            .get_account_balance(payer)
            .await
            .unwrap_or_else(|e| refuse(&format!("cannot read the payer {payer}'s balance: {e:?}")));
        let estimate = deploy_cost_estimate(&wallet, segments, pending).await;
        println!("\n  Payer {payer} holds {balance}; this run is estimated at up to {estimate}");
        if balance < estimate {
            refuse(&format!(
                "the payer {payer} holds {balance}, short of the estimated {estimate}"
            ));
        }
    }
    if check_only {
        println!("\n--check: nothing sent.");
        return;
    }

    // ── deploy and initialize ─────────────────────────────────────────
    let programs = ensure_programs(
        &mut wallet,
        &registration_program,
        &merkle_program,
        KnownProgramIds::default(),
        Some(&keys),
    )
    .await;
    assert_eq!(
        programs, plan.programs,
        "the programs are not where the plan put them"
    );
    let owner = registry_owner(&mut wallet, Some(&keys));
    assert_eq!(owner, plan.owner, "the owner is not the plan's");
    for registry in &plan.registries {
        println!("\nRegistry {:?}:", registry.label);
        let tree_id = initialize_registry(
            &mut wallet,
            &programs,
            owner,
            &registry.tree_label,
            &registry.params,
            Some(keys.treasury(&registry.tree_label)),
        )
        .await;
        assert_eq!(tree_id, registry.tree_id, "the tree id is not the plan's");
    }

    // ── read it back ──────────────────────────────────────────────────
    println!("\nReading the deployment back...");
    for (header, what) in [
        (programs.registration, "registration program"),
        (programs.merkle, "merkle program"),
    ] {
        let immutable = read_program_header(&wallet, header)
            .await
            .unwrap_or_else(|| refuse(&format!("the {what} at {header} holds no header")))
            .immutable;
        if !immutable {
            refuse(&format!("the {what} at {header} is not immutable"));
        }
    }
    for registry in &plan.registries {
        if registry_found(&wallet, &programs, registry).await != Found::AsPlanned
            || !is_tree_initialized(&wallet, &programs, &registry.tree_id).await
        {
            refuse(&format!(
                "the registry {:?} is not initialized",
                registry.label
            ));
        }
    }
    println!("The chain holds the plan.");

    // The wallet this leaves behind signs for what the deployment still
    // controls — its payer, its owner, each registry's treasury — whether
    // this run sent anything or found it all in place.
    for registry in &plan.registries {
        import_key(&mut wallet, keys.treasury(&registry.tree_label));
    }
    wallet
        .store_persistent_data()
        .unwrap_or_else(|e| refuse(&format!("cannot store the wallet: {e:?}")));

    if let Some(out_path) = out_path {
        let mut deployed = file;
        deployed["deployed"] = json!(true);
        deployed["payer_account"] = json!(payer.to_string());
        deployed["payer_public_key"] = json!(public_key_of(&wallet, payer, "payer").to_string());
        let pretty = serde_json::to_string_pretty(&deployed).expect("a plan serializes");
        std::fs::write(&out_path, pretty + "\n")
            .unwrap_or_else(|e| refuse(&format!("cannot write {}: {e}", out_path.display())));
        println!("Written to {}", out_path.display());
    }
}
