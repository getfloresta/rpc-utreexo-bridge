use bitcoin::network::Network;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct CliArgs {
    /// If you want to run the bridge from a specific height, you can specify it here.
    ///
    /// Notice that this requires passing the initial state path, that should point to a valid
    /// accumulator state at the specified height.
    #[clap(long, requires("initial_state_path"))]
    pub start_height: Option<u32>,
    /// The path to the initial state file. This file should contain the accumulator state at the
    /// specified height.
    #[clap(long, requires("start_height"))]
    pub initial_state_path: Option<String>,
    /// Creates a snapshot of the accumulator every n blocks
    ///
    /// The file will be named <height>.acc
    #[clap(long)]
    pub acc_snapshot_every_n_blocks: Option<u32>,

    /// In shinigami mode, we save blocks individually in a json file. We also place those json
    /// inside a directory that has a range of blocks (e.g. 0-1000). This parameter specifies the
    /// range of blocks that will be saved in each directory. The default value is 10_000.
    #[clap(long, short = 'g', default_value_t = 10_000)]
    pub block_files_granularity: u32,

    /// If you don't want to save proofs for very old blocks, you can set this options with
    /// the number of blocks you want to keep, and we'll only keep proofs for blocks that are
    /// newer than that.
    #[clap(long)]
    pub save_proofs_after: Option<u32>,

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

    /// Number of concurrent block-fetching leaf workers.
    #[clap(long, requires = "build_forest")]
    pub forest_leaf_workers: Option<usize>,

    /// Number of concurrent parent-hashing chaser workers.
    #[clap(long, requires = "build_forest")]
    pub forest_chaser_workers: Option<usize>,

    /// Number of readiness checks a chaser spins through before sleeping.
    #[clap(long, requires = "build_forest")]
    pub forest_spin_iterations: Option<usize>,

    /// Do not attempt to lock touched forest pages in RAM.
    #[clap(long)]
    pub forest_no_mlock: bool,

    /// The network we are operating on
    #[clap(long, short = 'n', default_value = "bitcoin")]
    pub network: Network,
}
