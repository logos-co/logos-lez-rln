use crate::config::{Paths, PEER_IDS};
use crate::process::run_command;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    #[serde(rename = "leafIndex")]
    pub leaf_index: u64,
    #[serde(rename = "identitySecretHash")]
    pub identity_secret_hash: String,
    #[serde(rename = "rateLimit")]
    pub rate_limit: u64,
    #[serde(rename = "configAccount")]
    pub config_account: String,
}

pub struct RegisterResult {
    pub members: Vec<MemberInfo>,
    pub config_account: String,
    pub work_dir: PathBuf,
}

pub async fn run_register(
    paths: &Paths,
    num_members: usize,
    progress_callback: impl Fn(usize, usize),
) -> Result<RegisterResult, String> {
    // Build register_member
    run_command(
        "cargo",
        &["build", "--release", "--bin", "register_member"],
        Some(&paths.lez_rln),
    )
    .await
    .map_err(|e| format!("Failed to build register_member: {}", e))?;

    let register_bin = paths.lez_rln.join("target/release/register_member");
    if !register_bin.exists() {
        return Err(format!("register_member not found at {:?}", register_bin));
    }

    let work_dir = tempfile::tempdir()
        .map_err(|e| e.to_string())?
        .keep();

    let mut members = Vec::new();
    let mut config_account = String::new();

    for i in 0..num_members {
        progress_callback(i + 1, num_members);

        let output = run_command(
            register_bin.to_str().unwrap(),
            &[],
            Some(&paths.lez_rln),
        )
        .await
        .map_err(|e| format!("register_member failed: {}", e))?;

        let parse_line = |prefix: &str| -> Option<String> {
            output
                .lines()
                .find(|l| l.starts_with(prefix))
                .map(|l| l.split('=').nth(1).unwrap_or("").to_string())
        };

        config_account = parse_line("CONFIG_ACCOUNT=")
            .ok_or("Failed to parse CONFIG_ACCOUNT")?;
        let leaf_index: u64 = parse_line("LEAF_INDEX=")
            .ok_or("Failed to parse LEAF_INDEX")?
            .parse()
            .map_err(|_| "Invalid LEAF_INDEX")?;
        let identity_secret = parse_line("IDENTITY_SECRET_HASH=")
            .ok_or("Failed to parse IDENTITY_SECRET_HASH")?;

        members.push(MemberInfo {
            peer_id: PEER_IDS[i].to_string(),
            leaf_index,
            identity_secret_hash: identity_secret,
            rate_limit: 100,
            config_account: config_account.clone(),
        });
    }

    // Write manifest
    let manifest_path = work_dir.join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&members)
        .map_err(|e| e.to_string())?;
    fs::write(&manifest_path, &manifest_json).map_err(|e| e.to_string())?;

    // Generate keystores
    generate_keystores(paths, &work_dir, &manifest_path).await?;

    Ok(RegisterResult {
        members,
        config_account,
        work_dir,
    })
}

async fn generate_keystores(
    paths: &Paths,
    work_dir: &PathBuf,
    manifest_path: &PathBuf,
) -> Result<(), String> {
    // Build librln if needed
    let librln = paths.delivery.join("librln_v0.9.0.a");
    if !librln.exists() {
        run_command("make", &["librln"], Some(&paths.delivery))
            .await
            .map_err(|e| format!("Failed to build librln: {}", e))?;
    }

    // Generate nim paths if needed
    let nim_paths = paths.delivery.join("nimbus-build-system.paths");
    if !nim_paths.exists() {
        run_command("make", &["nimbus-build-system-paths"], Some(&paths.delivery))
            .await
            .map_err(|e| format!("Failed to generate nim paths: {}", e))?;
    }

    // Read nim paths
    let paths_content = fs::read_to_string(&nim_paths)
        .map_err(|e| format!("Failed to read nim paths: {}", e))?;
    let nim_path_args: Vec<String> = paths_content
        .lines()
        .map(|l| l.replace("\"", ""))
        .filter(|l| !l.is_empty())
        .collect();

    // Compile setup_keystores
    let setup_ks_nim = paths.simulation_dir.join("setup_keystores.nim");
    let setup_ks_bin = work_dir.join("setup_keystores");

    let mut args = vec![
        "c".to_string(),
        "-d:release".to_string(),
        "--mm:refc".to_string(),
    ];
    args.extend(nim_path_args);
    args.push(format!("--passL:{}", librln.display()));
    args.push("--passL:-lm".to_string());
    args.push(format!("-o:{}", setup_ks_bin.display()));
    args.push(setup_ks_nim.to_string_lossy().to_string());

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_command("nim", &args_refs, None)
        .await
        .map_err(|e| format!("Failed to compile setup_keystores: {}", e))?;

    // Run setup_keystores
    run_command(
        setup_ks_bin.to_str().unwrap(),
        &[manifest_path.to_str().unwrap()],
        Some(work_dir),
    )
    .await
    .map_err(|e| format!("setup_keystores failed: {}", e))?;

    Ok(())
}
