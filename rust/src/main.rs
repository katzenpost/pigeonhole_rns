//! replica_rns-rs: a Pigeonhole storage replica for Reticulum, on berlinmesh/reticulum. The
//! store, query modes and command line of the Python `replica_rns replica`.

mod bridge;
mod channel;
mod config;
mod engine;
mod net;
mod push;
mod replica;
mod store;
mod wire;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "replica_rns-rs", about = "A Pigeonhole storage replica for Reticulum")]
struct Cli {
    /// Reticulum config directory
    #[arg(long)]
    config: Option<PathBuf>,
    /// Box plaintext sizes taken besides the mesh's (256 bytes) and the mixnet's (1549), which
    /// are always taken: comma separated, each a profile (mesh, mixnet) or a size in bytes, at
    /// most 8 and none over 1549; 0 alone for any size
    #[arg(long, default_value = "mesh")]
    box_size: String,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a storage replica
    Replica {
        /// Directory for identity and boxes
        #[arg(long)]
        storage: PathBuf,
        /// Unix socket of a Katzenpost replica on this host
        #[arg(long)]
        bridge_socket: Option<PathBuf>,
        /// With --bridge-socket: a name for the mixnet bridged, such as its PKI identity;
        /// bridges giving the same name serve one mixnet
        #[arg(long, default_value = "")]
        mixnet: String,
        /// With --bridge-socket: write every box into the mixnet, or only those clients write
        /// to this replica
        #[arg(long, default_value = "all", value_parser = ["all", "on-request"])]
        forward: String,
        #[arg(long, default_value_t = 600.0)]
        announce_interval: f64,
        /// Seconds in an epoch, Katzenpost's 20 minutes by default
        #[arg(long, default_value_t = engine::EPOCH_PERIOD)]
        epoch_period: f64,
        /// Epochs in a replica epoch, a week by default; boxes are kept for the current and
        /// previous replica epoch
        #[arg(long, default_value_t = engine::REPLICA_EPOCH_EPOCHS)]
        replica_epoch_epochs: u32,
        /// Most MiB the box store may take on disk; 0 for no limit
        #[arg(long, default_value_t = 0)]
        max_storage_mib: u64,
        /// MiB to leave free on the storage filesystem; 0 for none
        #[arg(long, default_value_t = 500)]
        min_free_storage_mib: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let filter = match cli.verbose {
        0 => "replica_rns_rs=info",
        1 => "replica_rns_rs=debug",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter)).init();
    let Cmd::Replica { storage, bridge_socket, mixnet, forward, announce_interval, epoch_period, replica_epoch_epochs, max_storage_mib, min_free_storage_mib } = cli.cmd;
    let config_dir = cli
        .config
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".reticulum"));
    let o = replica::Options {
        config_dir,
        storage,
        box_sizes: wire::box_ciphertext_sizes(&cli.box_size).unwrap_or_else(|e| {
            eprintln!("replica_rns-rs: --box-size: {e}");
            std::process::exit(2)
        }),
        bridge_socket,
        mixnet,
        forward_all: forward == "all",
        announce_interval: Duration::from_secs_f64(announce_interval),
        epoch_seconds: epoch_period * replica_epoch_epochs as f64,
        max_storage_bytes: max_storage_mib << 20,
        min_free_storage_bytes: min_free_storage_mib << 20,
    };
    if let Err(e) = replica::run(o).await {
        eprintln!("replica_rns-rs: {e}");
        std::process::exit(1);
    }
}
