use crate::config::{Paths, Platform, NUM_CORE_NODES, NUM_EDGE_NODES};
use crate::modules::StagedModules;
use crate::phases::{
    nodes::{NodeInstance, NodeState},
    register::MemberInfo,
    sequencer::SequencerPhase,
};
use std::collections::VecDeque;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Initializing,
    Sequencer(SequencerState),
    Deploy(DeployState),
    Register { current: usize, total: usize },
    Build { current: usize, total: usize, name: String },
    Stage { current: usize, total: usize },
    StartingNodes { started: usize, total: usize },
    Running,
    ShuttingDown,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequencerState {
    Building,
    Starting,
    WaitingForPort,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployState {
    BuildingGuests,
    RunningSetup,
    Done,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Initializing => write!(f, "Initializing"),
            Phase::Sequencer(s) => write!(f, "Sequencer: {:?}", s),
            Phase::Deploy(s) => write!(f, "Deploy: {:?}", s),
            Phase::Register { current, total } => write!(f, "Register ({}/{})", current, total),
            Phase::Build { current, total, name } => {
                write!(f, "Build {} ({}/{})", name, current, total)
            }
            Phase::Stage { current, total } => write!(f, "Stage ({}/{})", current, total),
            Phase::StartingNodes { started, total } => {
                write!(f, "Starting Nodes ({}/{})", started, total)
            }
            Phase::Running => write!(f, "Running"),
            Phase::ShuttingDown => write!(f, "Shutting Down"),
            Phase::Failed(msg) => write!(f, "Failed: {}", msg),
        }
    }
}

pub enum LogPanel {
    Node(usize),
    Sequencer,
    Global,
}

pub struct App {
    pub phase: Phase,
    pub paths: Paths,
    pub platform: Platform,
    pub sequencer: SequencerPhase,
    pub nodes: Vec<NodeInstance>,
    pub staged_modules: Vec<StagedModules>,
    pub members: Vec<MemberInfo>,
    pub config_account: String,
    pub work_dir: PathBuf,
    pub logoscore_path: String,
    pub selected_node: usize,
    pub log_panel: LogPanel,
    pub log_scroll: usize,
    pub global_log: VecDeque<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new(paths: Paths) -> Self {
        let platform = Platform::detect();
        let total_nodes = NUM_CORE_NODES + NUM_EDGE_NODES;

        Self {
            phase: Phase::Initializing,
            paths,
            platform,
            sequencer: SequencerPhase::new(),
            nodes: Vec::with_capacity(total_nodes),
            staged_modules: Vec::new(),
            members: Vec::new(),
            config_account: String::new(),
            work_dir: PathBuf::new(),
            logoscore_path: String::new(),
            selected_node: 0,
            log_panel: LogPanel::Global,
            log_scroll: 0,
            global_log: VecDeque::with_capacity(1000),
            should_quit: false,
        }
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.global_log.len() >= 1000 {
            self.global_log.pop_front();
        }
        self.global_log.push_back(msg);
    }

    pub fn phase_number(&self) -> usize {
        match &self.phase {
            Phase::Initializing => 0,
            Phase::Sequencer(_) => 1,
            Phase::Deploy(_) => 2,
            Phase::Register { .. } => 3,
            Phase::Build { .. } => 4,
            Phase::Stage { .. } => 5,
            Phase::StartingNodes { .. } => 6,
            Phase::Running => 7,
            Phase::ShuttingDown => 7,
            Phase::Failed(_) => 0,
        }
    }

    pub fn total_nodes(&self) -> usize {
        NUM_CORE_NODES + NUM_EDGE_NODES
    }

    pub fn ready_nodes(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| matches!(n.state, NodeState::Ready))
            .count()
    }

    pub fn select_next_node(&mut self) {
        if !self.nodes.is_empty() {
            self.selected_node = (self.selected_node + 1) % self.nodes.len();
            self.log_panel = LogPanel::Node(self.selected_node);
            self.log_scroll = 0;
        }
    }

    pub fn select_prev_node(&mut self) {
        if !self.nodes.is_empty() {
            self.selected_node = if self.selected_node == 0 {
                self.nodes.len() - 1
            } else {
                self.selected_node - 1
            };
            self.log_panel = LogPanel::Node(self.selected_node);
            self.log_scroll = 0;
        }
    }

    pub fn toggle_log_panel(&mut self) {
        self.log_panel = match self.log_panel {
            LogPanel::Node(_) => LogPanel::Sequencer,
            LogPanel::Sequencer => LogPanel::Global,
            LogPanel::Global => LogPanel::Node(self.selected_node),
        };
        self.log_scroll = 0;
    }

    pub fn scroll_log_up(&mut self) {
        if self.log_scroll > 0 {
            self.log_scroll -= 1;
        }
    }

    pub fn scroll_log_down(&mut self) {
        self.log_scroll += 1;
    }

    pub fn tick(&mut self) {
        // Update sequencer
        if let Some(ref mut p) = self.sequencer.process {
            p.drain_logs();
            p.check_status();
        }

        // Update nodes
        for node in &mut self.nodes {
            node.update();
        }
    }

    pub fn shutdown(&mut self) {
        self.phase = Phase::ShuttingDown;
        for node in &mut self.nodes {
            node.shutdown();
        }
        self.sequencer.shutdown();
        self.should_quit = true;
    }
}
