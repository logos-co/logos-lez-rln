use crate::config::Paths;
use crate::process::run_command;

pub async fn run_build_modules(
    paths: &Paths,
    progress_callback: impl Fn(&str, usize, usize),
) -> Result<(), String> {
    let build_script = paths.rln_project.join("build_modules.sh");

    if !build_script.exists() {
        return Err(format!("build_modules.sh not found at {:?}", build_script));
    }

    progress_callback("Building modules", 0, 4);

    run_command("bash", &[build_script.to_str().unwrap()], Some(&paths.rln_project))
        .await
        .map_err(|e| format!("Module build failed: {}", e))?;

    progress_callback("Build complete", 4, 4);

    Ok(())
}
