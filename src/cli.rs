use bitcoin::network::Network;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct CliArgs {
    /// Build a flat, memory-mapped forest through the stop height encoded by this hintsfile, then
    /// exit. This phase currently supports Linux only.
    #[clap(long, value_name = "HINTS_FILE", conflicts_with = "steady_state")]
    pub build_forest: Option<std::path::PathBuf>,

    /// Continue sequentially from a completed flat forest at this hintsfile's stop height.
    #[clap(long, value_name = "HINTS_FILE", conflicts_with = "build_forest")]
    pub steady_state: Option<std::path::PathBuf>,

    /// Flat-forest path for bootstrap output or steady-state input.
    /// Defaults to `$DATA_DIR/forest.dat`.
    #[clap(long, value_name = "FOREST_FILE")]
    pub forest_file: Option<std::path::PathBuf>,

    /// Outpoint-to-bottom-position map for bootstrap output or steady-state input.
    /// Defaults to `$DATA_DIR/leaf-map`.
    #[clap(long, value_name = "LEAF_MAP_DIR")]
    pub leaf_map_path: Option<std::path::PathBuf>,

    /// Position-addressed 80-byte block-header file.
    /// Defaults to `$DATA_DIR/headers.dat`.
    #[clap(long, value_name = "HEADER_FILE")]
    pub header_file: Option<std::path::PathBuf>,

    /// Persistent block-hash-to-height index directory.
    /// Defaults to `$DATA_DIR/header-index`.
    #[clap(long, value_name = "HEADER_INDEX_DIR")]
    pub header_index_path: Option<std::path::PathBuf>,

    /// Number of concurrent block-fetching leaf workers.
    #[clap(long, requires = "build_forest")]
    pub forest_leaf_workers: Option<usize>,

    /// Number of concurrent parent-hashing chaser workers.
    #[clap(long, requires = "build_forest")]
    pub forest_chaser_workers: Option<usize>,

    /// Number of readiness checks a chaser spins through before sleeping.
    #[clap(long, requires = "build_forest")]
    pub forest_spin_iterations: Option<usize>,
    /// Minimum number of bottom-row leaf positions to preallocate.
    #[clap(long, requires = "build_forest")]
    pub forest_leaf_capacity: Option<u64>,
    /// Maximum Pollard cache size in MiB.
    #[clap(long, requires = "steady_state", default_value_t = 250)]
    pub pollard_memory_mib: usize,

    /// Do not attempt to lock touched forest pages in RAM.
    #[clap(long)]
    pub forest_no_mlock: bool,

    /// The network we are operating on
    #[clap(long, short = 'n', default_value = "bitcoin")]
    pub network: Network,
}
