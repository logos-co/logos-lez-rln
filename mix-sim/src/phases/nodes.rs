use crate::config::{
    NodeConfig, NodeMode, Paths, CONTENT_TOPIC, MIX_PUBKEYS, NUM_CORE_NODES, PEER_IDS,
    BASE_TCP_PORT,
};
use crate::modules::StagedModules;
use crate::process::ManagedProcess;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    Pending,
    Starting,
    Initializing { completed: usize, expected: usize },
    Ready,
    Failed(String),
    Stopped,
}

impl std::fmt::Display for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeState::Pending => write!(f, "Pending"),
            NodeState::Starting => write!(f, "Starting"),
            NodeState::Initializing { completed, expected } => {
                write!(f, "Init ({}/{})", completed, expected)
            }
            NodeState::Ready => write!(f, "Ready"),
            NodeState::Failed(msg) => write!(f, "Failed: {}", msg),
            NodeState::Stopped => write!(f, "Stopped"),
        }
    }
}

pub struct NodeInstance {
    pub config: NodeConfig,
    pub state: NodeState,
    pub process: Option<ManagedProcess>,
    pub log_file: PathBuf,
}

impl NodeInstance {
    pub fn new(config: NodeConfig, work_dir: &PathBuf) -> Self {
        Self {
            log_file: work_dir.join(format!("node{}.log", config.index)),
            config,
            state: NodeState::Pending,
            process: None,
        }
    }

    pub async fn start(
        &mut self,
        paths: &Paths,
        staged: &StagedModules,
        config_account: &str,
        logoscore_path: &str,
        work_dir: &PathBuf,
    ) -> Result<(), String> {
        self.start_with_path(paths, staged.path(), config_account, logoscore_path, work_dir).await
    }

    pub async fn start_with_path(
        &mut self,
        paths: &Paths,
        staged_path: &std::path::Path,
        config_account: &str,
        logoscore_path: &str,
        work_dir: &PathBuf,
    ) -> Result<(), String> {
        self.state = NodeState::Starting;

        let node_config = self.generate_node_config();
        let config_path = work_dir.join(format!("node{}_config.json", self.config.index));
        fs::write(&config_path, &node_config).map_err(|e| e.to_string())?;

        let load_order =
            "liblogos_execution_zone_wallet_module,liblogos_rln_module,delivery_module,mix_simulation_module";
        let wallet_call = format!(
            "liblogos_execution_zone_wallet_module.open({},{})",
            paths.wallet_config.display(),
            paths.wallet_storage.display()
        );

        let mut cmd = Command::new(logoscore_path);
        cmd.current_dir(work_dir);
        cmd.env("TMPDIR", "/tmp");
        cmd.arg("-m").arg(staged_path);
        cmd.arg("-l").arg(load_order);
        cmd.arg("-c").arg(&wallet_call);

        if self.config.mode == NodeMode::Core {
            // Core nodes: 7 -c calls
            cmd.arg("-c")
                .arg(format!("delivery_module.createNode(@{})", config_path.display()));
            cmd.arg("-c").arg("delivery_module.start()");
            cmd.arg("-c")
                .arg(format!("delivery_module.subscribe({})", CONTENT_TOPIC));
            cmd.arg("-c").arg(format!(
                "delivery_module.setRlnConfig({},{})",
                config_account, self.config.leaf_index
            ));
            cmd.arg("-c").arg(format!(
                "liblogos_rln_module.start_root_broadcast({})",
                config_account
            ));
            cmd.arg("-c").arg(format!(
                "liblogos_rln_module.start_merkle_proof_broadcast({},{})",
                config_account, self.config.leaf_index
            ));
        } else {
            // Edge nodes: use mix_simulation_module
            let runner_config = self.generate_runner_config(config_account, work_dir)?;
            cmd.arg("-c")
                .arg(format!("mix_simulation_module.start(@{})", runner_config.display()));
        }

        let process = ManagedProcess::spawn(cmd)
            .await
            .map_err(|e| format!("Failed to start node {}: {}", self.config.index, e))?;

        self.state = NodeState::Initializing {
            completed: 0,
            expected: self.config.expected_calls,
        };
        self.process = Some(process);

        Ok(())
    }

    pub fn update(&mut self) {
        if let Some(ref mut process) = self.process {
            process.drain_logs();
            process.check_status();

            let completed = process.count_pattern("Method call successful");

            match &self.state {
                NodeState::Initializing { expected, .. } => {
                    if completed >= *expected {
                        self.state = NodeState::Ready;
                    } else {
                        self.state = NodeState::Initializing {
                            completed,
                            expected: *expected,
                        };
                    }
                }
                _ => {}
            }

            if !process.is_running() {
                if let NodeState::Ready = self.state {
                    self.state = NodeState::Stopped;
                } else {
                    self.state = NodeState::Failed("Process exited unexpectedly".to_string());
                }
            }
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(ref mut p) = self.process {
            p.kill();
        }
        self.state = NodeState::Stopped;
    }

    fn generate_node_config(&self) -> String {
        let entry_nodes = if self.config.index == 0 {
            vec![]
        } else {
            vec![format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                BASE_TCP_PORT, PEER_IDS[0]
            )]
        };

        let mix_nodes: Vec<String> = (0..NUM_CORE_NODES)
            .filter(|&j| j != self.config.index)
            .map(|j| {
                format!(
                    "/ip4/127.0.0.1/tcp/{}/p2p/{}:{}",
                    BASE_TCP_PORT + j as u16,
                    PEER_IDS[j],
                    MIX_PUBKEYS[j]
                )
            })
            .collect();

        let config = json!({
            "mode": self.config.mode.to_string(),
            "clusterId": 42,
            "numShardsInNetwork": 8,
            "entryNodes": entry_nodes,
            "maxMessageSize": "150 KiB",
            "listenAddress": "127.0.0.1",
            "tcpPort": self.config.tcp_port,
            "discv5UdpPort": self.config.disc_port,
            "nodekey": self.config.nodekey,
            "mixkey": self.config.mixkey,
            "mixnodes": mix_nodes,
            "mix": true,
            "enableSpamProtection": true,
            "ipColocationLimit": 0,
            "logLevel": "TRACE"
        });

        serde_json::to_string_pretty(&config).unwrap()
    }

    fn generate_runner_config(
        &self,
        config_account: &str,
        work_dir: &PathBuf,
    ) -> Result<PathBuf, String> {
        let node_config: serde_json::Value =
            serde_json::from_str(&self.generate_node_config()).unwrap();

        let runner_config = json!({
            "delivery": node_config,
            "contentTopic": CONTENT_TOPIC,
            "rln": {
                "configAccountId": config_account,
                "leafIndex": self.config.leaf_index
            },
            "simulation": {
                "peerDiscoveryDelayMs": 15000,
                "messageCount": 3,
                "messageDelayMs": 2000,
                "payload": "e2e_mix_test"
            }
        });

        let path = work_dir.join(format!("runner{}_config.json", self.config.index));
        fs::write(&path, serde_json::to_string_pretty(&runner_config).unwrap())
            .map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn last_log(&self) -> Option<&str> {
        self.process.as_ref().and_then(|p| p.last_log())
    }

    pub fn logs(&self) -> impl Iterator<Item = &str> {
        self.process
            .as_ref()
            .map(|p| p.logs.iter().map(|s| s.as_str()))
            .into_iter()
            .flatten()
    }
}
