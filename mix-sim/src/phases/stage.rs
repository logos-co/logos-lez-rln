use crate::config::{Paths, Platform, NUM_CORE_NODES, NUM_EDGE_NODES};
use crate::modules::{stage_modules, StagedModules};

pub struct StageResult {
    pub modules: Vec<StagedModules>,
}

pub fn run_stage(
    paths: &Paths,
    platform: &Platform,
    progress_callback: impl Fn(usize, usize),
) -> Result<StageResult, String> {
    let total_nodes = NUM_CORE_NODES + NUM_EDGE_NODES;
    let mut modules = Vec::with_capacity(total_nodes);

    for i in 0..total_nodes {
        progress_callback(i + 1, total_nodes);
        let staged = stage_modules(paths, platform)?;
        modules.push(staged);
    }

    Ok(StageResult { modules })
}
