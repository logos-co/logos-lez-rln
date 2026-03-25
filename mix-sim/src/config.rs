use std::path::PathBuf;

pub const NODEKEYS: [&str; 7] = [
    "f98e3fba96c32e8d1967d460f1b79457380e1a895f7971cecc8528abe733781a",
    "09e9d134331953357bd38bbfce8edb377f4b6308b4f3bfbe85c610497053d684",
    "ed54db994682e857d77cd6fb81be697382dc43aa5cd78e16b0ec8098549f860e",
    "42f96f29f2d6670938b0864aced65a332dcf5774103b4c44ec4d0ea4ef3c47d6",
    "3ce887b3c34b7a92dd2868af33941ed1dbec4893b054572cd5078da09dd923d4",
    "cb6fe589db0e5d5b48f7e82d33093e4d9d35456f4aaffc2322c473a173b2ac49",
    "35eace7ccb246f20c487e05015ca77273d8ecaed0ed683de3d39bf4f69336feb",
];

pub const MIXKEYS: [&str; 7] = [
    "a87db88246ec0eedda347b9b643864bee3d6933eb15ba41e6d58cb678d813258",
    "c86029e02c05a7e25182974b519d0d52fcbafeca6fe191fbb64857fb05be1a53",
    "b858ac16bbb551c4b2973313b1c8c8f7ea469fca03f1608d200bbf58d388ec7f",
    "d8bd379bb394b0f22dd236d63af9f1a9bc45266beffc3fbbe19e8b6575f2535b",
    "780fff09e51e98df574e266bf3266ec6a3a1ddfcf7da826a349a29c137009d49",
    "fe68e1ff4a6aa7115cfcff33f68a0c1767d6865a1fd56ec05b40dffba9653fe5",
    "88f02c1bcd8eedb697e8fd818e6f1617752488e048b37730fa18e3fb3460f57e",
];

pub const PEER_IDS: [&str; 7] = [
    "16Uiu2HAmPiEs2ozjjJF2iN2Pe2FYeMC9w4caRHKYdLdAfjgbWM6o",
    "16Uiu2HAmLtKaFaSWDohToWhWUZFLtqzYZGPFuXwKrojFVF6az5UF",
    "16Uiu2HAmTEDHwAziWUSz6ZE23h5vxG2o4Nn7GazhMor4bVuMXTrA",
    "16Uiu2HAmPwRKZajXtfb1Qsv45VVfRZgK3ENdfmnqzSrVm3BczF6f",
    "16Uiu2HAmRhxmCHBYdXt1RibXrjAUNJbduAhzaTHwFCZT4qWnqZAu",
    "16Uiu2HAm1QxSjNvNbsT2xtLjRGAsBLVztsJiTHr9a3EK96717hpj",
    "16Uiu2HAmC9h26U1C83FJ5xpE32ghqya8CaZHX1Y7qpfHNnRABscN",
];

pub const MIX_PUBKEYS: [&str; 5] = [
    "9d09ce624f76e8f606265edb9cca2b7de9b41772a6d784bddaf92ffa8fba7d2c",
    "9231e86da6432502900a84f867004ce78632ab52cd8e30b1ec322cd795710c2a",
    "275cd6889e1f29ca48e5b9edb800d1a94f49f13d393a0ecf1a07af753506de6c",
    "e0ed594a8d506681be075e8e23723478388fb182477f7a469309a25e7076fc18",
    "8fd7a1a7c19b403d231452a9b1ea40eb1cc76f455d918ef8980e7685f9eeeb1f",
];

pub const BASE_TCP_PORT: u16 = 60001;
pub const BASE_DISC_PORT: u16 = 9001;
pub const NUM_CORE_NODES: usize = 5;
pub const NUM_EDGE_NODES: usize = 2;
pub const SEQUENCER_PORT: u16 = 3040;
pub const CONTENT_TOPIC: &str = "/toy-chat/2/baixa-chiado/proto";

#[derive(Debug, Clone)]
pub struct Platform {
    pub name: &'static str,
    pub lib_ext: &'static str,
}

impl Platform {
    pub fn detect() -> Self {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return Platform {
            name: "darwin-arm64-dev",
            lib_ext: "dylib",
        };

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        return Platform {
            name: "linux-x86_64-dev",
            lib_ext: "so",
        };

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        return Platform {
            name: "linux-aarch64-dev",
            lib_ext: "so",
        };

        #[cfg(not(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64")
        )))]
        panic!("Unsupported platform");
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub rln_project: PathBuf,
    pub delivery: PathBuf,
    pub lez_rln: PathBuf,
    pub lssa: PathBuf,
    pub wallet_config: PathBuf,
    pub wallet_storage: PathBuf,
    pub simulation_dir: PathBuf,
}

impl Paths {
    pub fn new(rln_project: PathBuf) -> Self {
        let delivery = rln_project.join("logos-delivery");
        let dev_dir = rln_project.join("dev");
        Self {
            lez_rln: rln_project.join("lez-rln"),
            lssa: rln_project.join("lssa"),
            wallet_config: dev_dir.join("wallet_config.json"),
            wallet_storage: dev_dir.join("storage.json"),
            simulation_dir: delivery.join("simulations/mixnet"),
            delivery,
            rln_project,
        }
    }

    pub fn rln_module_result(&self) -> PathBuf {
        self.rln_project.join("logos-rln-module/result-rln")
    }

    pub fn wallet_module_result(&self) -> PathBuf {
        self.rln_project.join("logos-rln-module/result-wallet")
    }

    pub fn delivery_module_result(&self) -> PathBuf {
        self.rln_project.join("logos-delivery-module/result")
    }

    pub fn mix_sim_module_result(&self) -> PathBuf {
        self.rln_project.join("mix-simulation-module/result")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    Core,
    Edge,
}

impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeMode::Core => write!(f, "Core"),
            NodeMode::Edge => write!(f, "Edge"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub index: usize,
    pub mode: NodeMode,
    pub tcp_port: u16,
    pub disc_port: u16,
    pub nodekey: &'static str,
    pub mixkey: &'static str,
    pub peer_id: &'static str,
    pub leaf_index: u64,
    pub expected_calls: usize,
}

impl NodeConfig {
    pub fn new(index: usize, leaf_index: u64) -> Self {
        let mode = if index < NUM_CORE_NODES {
            NodeMode::Core
        } else {
            NodeMode::Edge
        };
        let expected_calls = if mode == NodeMode::Core { 7 } else { 2 };

        Self {
            index,
            mode,
            tcp_port: BASE_TCP_PORT + index as u16,
            disc_port: BASE_DISC_PORT + index as u16,
            nodekey: NODEKEYS[index],
            mixkey: MIXKEYS[index],
            peer_id: PEER_IDS[index],
            leaf_index,
            expected_calls,
        }
    }
}
