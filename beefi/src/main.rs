use beefi_lib::{
    create_live_capture, extract_from_pcap, BfiFile, FileType, HoneySink, PollenSink, StreamBee,
    Writer,
};
use clap::{ArgGroup, Parser, Subcommand};
use simplelog::{LevelFilter, SimpleLogger};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

mod monitor_mode;

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    /// Log level for output (error, warn, info, debug, trace)
    #[arg(global = true, long, default_value = "info", value_enum)]
    loglevel: LevelFilter,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture data from an interface or process an existing pcap file
    Capture(CaptureArgs),

    /// Put interface into monitor mode. Must be executed as sudo.
    MonitorMode(MonitorArgs),
}

#[derive(Parser)]
#[command(group = ArgGroup::new("output").required(true).args(&["pcap_out", "bfi_out", "print"]))]
struct CaptureArgs {
    /// Network interface to capture from
    #[arg(long, conflicts_with = "pcap_in")]
    interface: Option<String>,

    /// Read data from existing pcap file instead of interface
    #[arg(long, conflicts_with = "interface")]
    pcap_in: Option<PathBuf>,

    /// Output file of raw captured packets
    #[arg(long, conflicts_with = "pcap_in")]
    pcap_out: Option<PathBuf>,

    /// Output file for processed data
    #[arg(short, long, requires("format"))]
    bfi_out: Option<PathBuf>,

    /// Specify output format, e.g., 'parquet'
    #[arg(long, default_value = "parquet")]
    format: FileType,

    /// Whether to print processed data
    #[arg(long, default_value = "false")]
    print: bool,
}

#[derive(Parser)]
struct MonitorArgs {
    #[arg(long)]
    interface: String,

    #[arg(long, default_value = "1")]
    channel: u8,
}

fn main() {
    let cli = Cli::parse();

    SimpleLogger::init(
        cli.loglevel,
        simplelog::ConfigBuilder::new()
            .add_filter_allow("beefi".into())
            .build(),
    )
    .expect("Failed to initialize logger");

    match cli.command {
        Commands::Capture(args) => capture(args),
        Commands::MonitorMode(MonitorArgs { interface, channel }) => {
            monitor_mode::setup_monitor_mode(&interface, channel).unwrap()
        }
    }
}

fn capture(args: CaptureArgs) {
    if args.interface.is_some() {
        run_capture(args);
    } else {
        run_offline(args);
    }
}

fn run_capture(args: CaptureArgs) {
    let CaptureArgs {
        interface,
        pcap_in,
        pcap_out,
        bfi_out,
        format,
        print,
    } = args;

    // Set up the `running` flag for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);

    // Set up CTRL+C handler for graceful shutdown
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Initialize CaptureBee and set sinks
    let mut bee = create_bee(interface, pcap_in, pcap_out);

    if let Some(bfi_out_path) = bfi_out {
        let processed_sink = HoneySink::File(BfiFile {
            file_path: bfi_out_path,
            file_type: format,
        });
        bee.subscribe_for_honey(processed_sink);
    }

    // Start capturing
    bee.start_harvesting(print);
}

fn run_offline(args: CaptureArgs) {
    let data = extract_from_pcap(args.pcap_in.expect("Need a pcap file to extract from"));

    if args.print {
        println!("Data read: {:?}", data);
    }

    if let Some(file) = args.bfi_out {
        let file = BfiFile {
            file_path: file,
            file_type: args.format,
        };
        let mut writer = Writer::new(file).unwrap();
        writer.add_batch(&data).unwrap();
        writer.finalize().unwrap();
    }
}

/// Creates a `CaptureBee` object based on the specified interface or input file.
/// If `pcap_out` is provided, sets the capture to write raw packets to the given file.
fn create_bee(
    interface: Option<String>,
    input_file: Option<PathBuf>,
    pcap_out: Option<PathBuf>,
) -> StreamBee {
    match (interface, input_file) {
        (Some(interface), None) => {
            // Live capture from a network interface
            let cap = create_live_capture(&interface);

            let out_file = pcap_out.map(|out_file| {
                cap.savefile(out_file)
                    .expect("Failed to create pcap output file.")
            });

            let mut bee = StreamBee::from_live_capture(cap);

            // If `pcap_out` is specified, set it as the output file for raw packets
            if let Some(out_file) = out_file {
                let raw_sink = PollenSink::File(out_file);
                bee.subscribe_for_pollen(raw_sink);
            }

            bee
        }
        _ => unreachable!("CLI argument validation should prevent this case."),
    }
}
