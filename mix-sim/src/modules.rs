use crate::config::{Paths, Platform};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[derive(Debug)]
pub struct StagedModules {
    pub dir: TempDir,
}

impl StagedModules {
    pub fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

pub fn stage_modules(paths: &Paths, platform: &Platform) -> Result<StagedModules, String> {
    let dir = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let mdir = dir.path();
    let ext = platform.lib_ext;
    let plat = platform.name;

    // Wallet module
    let wallet_dir = mdir.join("liblogos_execution_zone_wallet_module");
    fs::create_dir_all(&wallet_dir).map_err(|e| e.to_string())?;

    let wallet_lib = paths
        .wallet_module_result()
        .join(format!("lib/liblogos_execution_zone_wallet_module.{}", ext));
    copy_if_exists(&wallet_lib, &wallet_dir)?;

    let wallet_ffi = paths
        .wallet_module_result()
        .join(format!("lib/libwallet_ffi.{}", ext));
    let _ = copy_if_exists(&wallet_ffi, &wallet_dir);

    write_manifest(
        &wallet_dir,
        "liblogos_execution_zone_wallet_module",
        plat,
        &format!("liblogos_execution_zone_wallet_module.{}", ext),
        &[],
    )?;

    // RLN module
    let rln_dir = mdir.join("liblogos_rln_module");
    fs::create_dir_all(&rln_dir).map_err(|e| e.to_string())?;

    let rln_lib = paths
        .rln_module_result()
        .join(format!("lib/liblogos_rln_module.{}", ext));
    copy_if_exists(&rln_lib, &rln_dir)?;

    let rln_ffi = paths
        .rln_module_result()
        .join(format!("lib/liblez_rln_ffi.{}", ext));
    let _ = copy_if_exists(&rln_ffi, &rln_dir);

    write_manifest(
        &rln_dir,
        "liblogos_rln_module",
        plat,
        &format!("liblogos_rln_module.{}", ext),
        &["liblogos_execution_zone_wallet_module"],
    )?;

    // Delivery module
    let delivery_dir = mdir.join("delivery_module");
    fs::create_dir_all(&delivery_dir).map_err(|e| e.to_string())?;

    let delivery_lib = paths
        .delivery_module_result()
        .join(format!("lib/delivery_module_plugin.{}", ext));
    copy_if_exists(&delivery_lib, &delivery_dir)?;

    let delivery_ffi = paths
        .delivery_module_result()
        .join(format!("lib/liblogosdelivery.{}", ext));
    let _ = copy_if_exists(&delivery_ffi, &delivery_dir);

    // Copy libpq* files
    if let Ok(entries) = fs::read_dir(paths.delivery_module_result().join("lib")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("libpq") {
                let _ = fs::copy(entry.path(), delivery_dir.join(&name));
            }
        }
    }

    write_manifest(
        &delivery_dir,
        "delivery_module",
        plat,
        &format!("delivery_module_plugin.{}", ext),
        &[],
    )?;

    // Mix simulation module
    let mix_sim_dir = mdir.join("mix_simulation_module");
    fs::create_dir_all(&mix_sim_dir).map_err(|e| e.to_string())?;

    let mix_sim_lib = paths
        .mix_sim_module_result()
        .join(format!("lib/libmix_simulation_module.{}", ext));
    copy_if_exists(&mix_sim_lib, &mix_sim_dir)?;

    write_manifest(
        &mix_sim_dir,
        "mix_simulation_module",
        plat,
        &format!("libmix_simulation_module.{}", ext),
        &["delivery_module", "liblogos_rln_module"],
    )?;

    Ok(StagedModules { dir })
}

fn copy_if_exists(src: &PathBuf, dest_dir: &PathBuf) -> Result<(), String> {
    if src.exists() {
        let filename = src.file_name().ok_or("No filename")?;
        fs::copy(src, dest_dir.join(filename)).map_err(|e| format!("Copy failed: {}", e))?;
        Ok(())
    } else {
        Err(format!("File not found: {:?}", src))
    }
}

fn write_manifest(
    dir: &PathBuf,
    name: &str,
    platform: &str,
    main_file: &str,
    deps: &[&str],
) -> Result<(), String> {
    let deps_json: Vec<String> = deps.iter().map(|s| format!("\"{}\"", s)).collect();
    let manifest = format!(
        r#"{{"name":"{}","version":"1.0.0","type":"core","main":{{"{}":"{}"}},"dependencies":[{}],"capabilities":[]}}"#,
        name,
        platform,
        main_file,
        deps_json.join(",")
    );
    fs::write(dir.join("manifest.json"), manifest).map_err(|e| e.to_string())
}

pub fn check_modules_built(paths: &Paths, platform: &Platform) -> Vec<String> {
    let ext = platform.lib_ext;
    let mut missing = Vec::new();

    let checks = [
        (
            paths
                .rln_module_result()
                .join(format!("lib/liblogos_rln_module.{}", ext)),
            "RLN module",
        ),
        (
            paths
                .wallet_module_result()
                .join(format!("lib/liblogos_execution_zone_wallet_module.{}", ext)),
            "Wallet module",
        ),
        (
            paths
                .delivery_module_result()
                .join(format!("lib/delivery_module_plugin.{}", ext)),
            "Delivery module",
        ),
        (
            paths
                .mix_sim_module_result()
                .join(format!("lib/libmix_simulation_module.{}", ext)),
            "Mix simulation module",
        ),
    ];

    for (path, name) in checks {
        if !path.exists() {
            missing.push(name.to_string());
        }
    }

    missing
}
