use crate::config::{Paths, SEQUENCER_PORT};
use crate::process::{check_port, kill_process_on_port, run_command, wait_for_port, ManagedProcess};
use tokio::process::Command;

pub struct SequencerPhase {
    pub process: Option<ManagedProcess>,
}

impl SequencerPhase {
    pub fn new() -> Self {
        Self { process: None }
    }

    pub async fn run(&mut self, paths: &Paths) -> Result<(), String> {
        // Initialize submodule
        run_command("git", &["submodule", "update", "--init", "lssa"], Some(&paths.rln_project))
            .await
            .map_err(|e| format!("Failed to init lssa submodule: {}", e))?;

        // Kill existing process on port
        if check_port(SEQUENCER_PORT).await {
            kill_process_on_port(SEQUENCER_PORT).await?;
        }

        // Clean rocksdb
        let rocksdb_path = paths.lssa.join("rocksdb");
        if rocksdb_path.exists() {
            std::fs::remove_dir_all(&rocksdb_path)
                .map_err(|e| format!("Failed to clean rocksdb: {}", e))?;
        }

        // Build sequencer
        run_command(
            "cargo",
            &["build", "--features", "standalone", "-p", "sequencer_runner"],
            Some(&paths.lssa),
        )
        .await
        .map_err(|e| format!("Sequencer build failed: {}", e))?;

        // Start sequencer
        let sequencer_bin = paths.lssa.join("target/debug/sequencer_runner");
        let mut cmd = Command::new(&sequencer_bin);
        cmd.current_dir(&paths.lssa);
        cmd.arg("sequencer_runner/configs/debug");
        cmd.env("RUST_LOG", "info");
        cmd.env("TMPDIR", "/tmp");

        let process = ManagedProcess::spawn(cmd)
            .await
            .map_err(|e| format!("Failed to start sequencer: {}", e))?;

        self.process = Some(process);

        // Wait for port
        if !wait_for_port(SEQUENCER_PORT, 300).await {
            return Err("Sequencer did not start within 300s".to_string());
        }

        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(ref mut p) = self.process {
            p.kill();
        }
    }
}
