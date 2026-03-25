use crate::config::Paths;
use crate::process::run_command;
use std::env;
use std::fs;

pub struct DeployResult {
    pub tree_main_account: String,
}

pub async fn run_deploy(paths: &Paths) -> Result<DeployResult, String> {
    // Check for zkVM guest binaries
    let guest_bin = paths.lez_rln.join(
        "methods/guest/target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin",
    );

    if !guest_bin.exists() {
        // Check if cargo-risczero is available
        if run_command("which", &["cargo-risczero"], None).await.is_err() {
            return Err(
                "zkVM guest binaries not found and cargo-risczero not installed.\n\
                Install with: cargo install cargo-risczero && cargo risczero install\n\
                Requires Docker running for cross-compilation."
                    .to_string(),
            );
        }

        // Build guest programs
        run_command(
            "cargo",
            &[
                "risczero",
                "build",
                "--manifest-path",
                "methods/guest/Cargo.toml",
            ],
            Some(&paths.lez_rln),
        )
        .await
        .map_err(|e| format!("Guest program build failed: {}", e))?;
    }

    // Set up wallet environment
    let dev_dir = paths.rln_project.join("dev");
    fs::create_dir_all(&dev_dir).map_err(|e| e.to_string())?;

    env::set_var("NSSA_WALLET_HOME_DIR", &dev_dir);
    env::set_var("WALLET_CONFIG", &paths.wallet_config);
    env::set_var("WALLET_STORAGE", &paths.wallet_storage);
    env::set_var("RISC0_DEV_MODE", "1");

    // Clean old wallet state
    let _ = fs::remove_file(&paths.wallet_config);
    let _ = fs::remove_file(&paths.wallet_storage);

    // Run setup
    let output = run_command("cargo", &["run", "--bin", "run_setup"], Some(&paths.lez_rln))
        .await
        .map_err(|e| format!("run_setup failed: {}", e))?;

    // Parse tree main account
    let tree_main_account = output
        .lines()
        .find(|l| l.contains("Tree main account:"))
        .and_then(|l| l.split_whitespace().last())
        .ok_or("Could not parse tree main account from run_setup output")?
        .to_string();

    Ok(DeployResult { tree_main_account })
}
