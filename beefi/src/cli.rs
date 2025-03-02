use beefi_lib::FileType;
use clap::{ArgGroup, Parser, Subcommand};
use simplelog::LevelFilter;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
pub struct Cli {
    /// Log level for output (error, warn, info, debug, trace)
    #[arg(global = true, long, default_value = "info", value_enum)]
    pub loglevel: LevelFilter,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Capture live data from an interface
    Capture(OnlineCaptureArgs),

    /// Process an existing pcap file
    FromPcap(OfflineCaptureArgs),

    /// Put interface into monitor mode. Must be executed as sudo.
    MonitorMode(MonitorArgs),
}

#[derive(Parser)]
#[command(group = ArgGroup::new("output").required(true).multiple(true).args(&["pcap_out", "bfa_out", "bfm_out", "print"]))]
pub struct OnlineCaptureArgs {
    /// Network interface to capture from
    #[arg(long)]
    pub interface: String,

    /// Output file of raw captured packets
    #[arg(long)]
    pub pcap_out: Option<PathBuf>,

    /// Output file for extracted angles
    #[arg(short, long)]
    pub bfa_out: Option<PathBuf>,

    /// Output file for converted beamforming matrices
    #[arg(long)]
    pub bfm_out: Option<PathBuf>,

    /// Specify output format, e.g., 'parquet'
    #[arg(long, default_value = "parquet")]
    pub format: FileType,

    /// Whether to print processed data
    #[arg(long, default_value = "false")]
    pub print: bool,

    /// PCap snapshot size for internal buffer
    #[arg(long, default_value = "4096")]
    pub pcap_snaplen: i32,

    /// Whether pcap should buffer or process every packet immediately
    #[arg(long, default_value = "false")]
    pub pcap_buffered: bool,

    #[arg(long, default_value = "1000000")]
    pub pcap_bufsize: i32,
}

#[derive(Parser)]
#[command(group = ArgGroup::new("output").required(true).multiple(true).args(&["bfa_out", "bfm_out", "print"]))]
pub struct OfflineCaptureArgs {
    /// Read data from existing pcap file
    #[arg(long)]
    pub pcap_in: PathBuf,

    /// Output file for extracted feedback angles
    #[arg(short, long)]
    pub bfa_out: Option<PathBuf>,

    /// Output file for extracted feedback matrices
    #[arg(long)]
    pub bfm_out: Option<PathBuf>,

    /// Specify output format, e.g., 'parquet'
    #[arg(long, default_value = "parquet")]
    pub format: FileType,

    /// Whether to print processed data
    #[arg(long, default_value = "false")]
    pub print: bool,
}

#[derive(Parser)]
pub struct MonitorArgs {
    #[arg(long)]
    pub interface: String,

    #[arg(long, default_value = "1")]
    pub channel: u8,

    #[arg(long, default_value = "20")]
    pub bandwidth: u16,
}
