use crate::config::{NodeConfig, NUM_CORE_NODES, NUM_EDGE_NODES};
use crate::modules::check_modules_built;
use crate::phases::{
    build::run_build_modules,
    deploy::run_deploy,
    nodes::NodeInstance,
    register::run_register,
    stage::run_stage,
};
use crate::process::run_command;
use crate::tui::app::{App, DeployState, Phase, SequencerState};
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn run_orchestration(app: Arc<Mutex<App>>) -> Result<(), String> {
    let total_nodes = NUM_CORE_NODES + NUM_EDGE_NODES;

    // Phase 1: Sequencer
    {
        let mut app = app.lock().await;
        app.phase = Phase::Sequencer(SequencerState::Building);
        app.log("Starting sequencer...");
    }

    let paths = {
        let app = app.lock().await;
        app.paths.clone()
    };

    {
        let mut app = app.lock().await;
        app.phase = Phase::Sequencer(SequencerState::Starting);
    }

    {
        let mut app = app.lock().await;
        if let Err(e) = app.sequencer.run(&paths).await {
            app.phase = Phase::Failed(format!("Sequencer failed: {}", e));
            return Err(e);
        }
        app.phase = Phase::Sequencer(SequencerState::Ready);
        app.log("Sequencer ready on port 3040");
    }

    // Phase 2: Deploy
    {
        let mut app = app.lock().await;
        app.phase = Phase::Deploy(DeployState::RunningSetup);
        app.log("Deploying programs...");
    }

    let deploy_result = run_deploy(&paths).await;
    match deploy_result {
        Ok(result) => {
            let mut app = app.lock().await;
            app.log(format!("Tree main account: {}", result.tree_main_account));
            app.phase = Phase::Deploy(DeployState::Done);
        }
        Err(e) => {
            let mut app = app.lock().await;
            app.phase = Phase::Failed(format!("Deploy failed: {}", e));
            return Err(e);
        }
    }

    // Phase 3: Register
    {
        let mut app = app.lock().await;
        app.phase = Phase::Register {
            current: 0,
            total: total_nodes,
        };
        app.log(format!("Registering {} members...", total_nodes));
    }

    let register_result = run_register(&paths, total_nodes, |current, total| {
        // Progress callback - we can't easily update app here in sync context
        // so we'll rely on the final result
        let _ = (current, total);
    })
    .await;

    match register_result {
        Ok(result) => {
            let mut app = app.lock().await;
            let config_account = result.config_account.clone();
            let member_count = result.members.len();
            app.members = result.members;
            app.config_account = config_account.clone();
            app.work_dir = result.work_dir;
            app.log(format!("Config account: {}", config_account));
            app.log(format!("Registered {} members", member_count));
        }
        Err(e) => {
            let mut app = app.lock().await;
            app.phase = Phase::Failed(format!("Registration failed: {}", e));
            return Err(e);
        }
    }

    // Phase 4: Build modules
    let platform = {
        let app = app.lock().await;
        app.platform.clone()
    };

    let missing = check_modules_built(&paths, &platform);
    if !missing.is_empty() {
        {
            let mut app = app.lock().await;
            app.phase = Phase::Build {
                current: 0,
                total: 4,
                name: "modules".to_string(),
            };
            app.log(format!("Building missing modules: {:?}", missing));
        }

        if let Err(e) = run_build_modules(&paths, |name, current, total| {
            let _ = (name, current, total);
        })
        .await
        {
            let mut app = app.lock().await;
            app.phase = Phase::Failed(format!("Module build failed: {}", e));
            return Err(e);
        }
    }

    {
        let mut app = app.lock().await;
        app.log("All modules ready");
    }

    // Get logoscore path
    let logoscore_path = get_logoscore_path().await?;
    {
        let mut app = app.lock().await;
        app.logoscore_path = logoscore_path.clone();
        app.log(format!("Using logoscore: {}", logoscore_path));
    }

    // Phase 5: Stage modules
    {
        let mut app = app.lock().await;
        app.phase = Phase::Stage {
            current: 0,
            total: total_nodes,
        };
        app.log("Staging modules...");
    }

    let stage_result = run_stage(&paths, &platform, |current, total| {
        let _ = (current, total);
    });

    match stage_result {
        Ok(result) => {
            let mut app = app.lock().await;
            let count = result.modules.len();
            app.staged_modules = result.modules;
            app.log(format!("Staged modules for {} nodes", count));
        }
        Err(e) => {
            let mut app = app.lock().await;
            app.phase = Phase::Failed(format!("Staging failed: {}", e));
            return Err(e);
        }
    }

    // Phase 6: Start nodes
    {
        let mut app = app.lock().await;
        app.phase = Phase::StartingNodes {
            started: 0,
            total: total_nodes,
        };
        app.log("Starting nodes...");
    }

    // Create node instances
    {
        let mut app = app.lock().await;
        for i in 0..total_nodes {
            let leaf_index = app.members[i].leaf_index;
            let config = NodeConfig::new(i, leaf_index);
            let node = NodeInstance::new(config, &app.work_dir);
            app.nodes.push(node);
        }
    }

    // Start nodes sequentially
    for i in 0..total_nodes {
        let (paths, config_account, logoscore, work_dir) = {
            let app = app.lock().await;
            (
                app.paths.clone(),
                app.config_account.clone(),
                app.logoscore_path.clone(),
                app.work_dir.clone(),
            )
        };

        {
            let mut app = app.lock().await;
            app.log(format!("Starting node {}...", i));
            app.phase = Phase::StartingNodes {
                started: i,
                total: total_nodes,
            };
        }

        // Start the node - we need to get the staged path first, then start
        let staged_path = {
            let app = app.lock().await;
            app.staged_modules[i].path().to_path_buf()
        };

        let start_result = {
            let mut app = app.lock().await;
            // We pass the staged module reference by getting it again after releasing lock
            app.nodes[i]
                .start_with_path(&paths, &staged_path, &config_account, &logoscore, &work_dir)
                .await
        };

        if let Err(e) = start_result {
            let mut app = app.lock().await;
            app.phase = Phase::Failed(format!("Node {} failed to start: {}", i, e));
            return Err(e);
        }

        // Wait for node to initialize
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(90);

        loop {
            if start.elapsed() > timeout {
                let mut app = app.lock().await;
                app.phase = Phase::Failed(format!("Node {} timed out during initialization", i));
                return Err(format!("Node {} timed out", i));
            }

            let (is_ready, is_failed, fail_msg) = {
                let mut app = app.lock().await;
                app.nodes[i].update();

                match &app.nodes[i].state {
                    crate::phases::nodes::NodeState::Ready => (true, false, String::new()),
                    crate::phases::nodes::NodeState::Failed(msg) => (false, true, msg.clone()),
                    _ => (false, false, String::new()),
                }
            };

            if is_ready {
                let mut app = app.lock().await;
                app.log(format!("Node {} ready", i));
                break;
            }

            if is_failed {
                let mut app = app.lock().await;
                app.phase = Phase::Failed(format!("Node {} failed: {}", i, fail_msg));
                return Err(fail_msg);
            }

            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Small delay between nodes
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    // Peer discovery wait
    {
        let mut app = app.lock().await;
        app.log("Waiting for peer discovery (15s)...");
    }
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    // Phase 7: Running
    {
        let mut app = app.lock().await;
        let config_account = app.config_account.clone();
        let work_dir = app.work_dir.clone();
        app.phase = Phase::Running;
        app.log("Simulation running!");
        app.log(format!("Config account: {}", config_account));
        app.log(format!("Work dir: {:?}", work_dir));
    }

    Ok(())
}

async fn get_logoscore_path() -> Result<String, String> {
    // Try to get from nix build
    let output = run_command(
        "nix",
        &[
            "build",
            "github:logos-co/logos-liblogos/7df6195",
            "--override-input",
            "logos-cpp-sdk",
            "github:logos-co/logos-cpp-sdk/a4bd66c",
            "--no-link",
            "--print-out-paths",
        ],
        None,
    )
    .await
    .map_err(|e| format!("Failed to get logoscore path: {}", e))?;

    let path = output.trim();
    Ok(format!("{}/bin/logoscore", path))
}
