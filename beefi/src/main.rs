use beefi_lib::{
    create_live_capture, extract_from_pcap, save, BfaFile, CaptureBee, FileType, ProcessedSink,
    RawSink,
};
use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture data from an interface or process an existing pcap file
    Capture(CaptureArgs),
}

#[derive(Parser)]
#[command(group = ArgGroup::new("output").required(true).args(&["pcap_out", "bfa_out", "print"]))]
struct CaptureArgs {
    /// Network interface to capture from
    #[arg(short, long, conflicts_with = "input")]
    interface: Option<String>,

    /// Read data from existing pcap file instead of interface
    #[arg(long, conflicts_with = "interface")]
    input_file: Option<PathBuf>,

    /// Output file for processed data
    #[arg(short, long, requires("format"))]
    bfa_out: Option<PathBuf>,

    /// Specify output format, e.g., 'parquet'
    #[arg(long, default_value = "parquet")]
    format: FileType,

    /// Output file of raw captured packets
    #[arg(long, conflicts_with = "input")]
    pcap_out: Option<PathBuf>,

    /// Whether to print processed data
    #[arg(long, default_value = "false")]
    print: bool,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture(args) => handle(args),
    }
}

fn handle(args: CaptureArgs) {
    if args.interface.is_some() {
        run_capture(args);
    } else {
        run_offline(args);
    }
}

fn run_capture(args: CaptureArgs) {
    let CaptureArgs {
        interface,
        input_file,
        bfa_out,
        format,
        pcap_out,
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
    let mut bee = create_capture_bee(interface, input_file, pcap_out);

    if let Some(bfa_out_path) = bfa_out {
        let processed_sink = ProcessedSink::File(BfaFile {
            file_path: bfa_out_path,
            file_type: format,
        });
        bee.set_proc_sink(processed_sink);
    }

    // Start capturing
    bee.start(print);
}

fn run_offline(args: CaptureArgs) {
    let data = extract_from_pcap(args.input_file.expect("Need a pcap file to extract from"));

    if args.print {
        println!("Data read: {:?}", data);
    }

    if let Some(file) = args.bfa_out {
        save(
            BfaFile {
                file_path: file,
                file_type: args.format,
            },
            &data,
        )
        .unwrap();
    }
}

/// Creates a `CaptureBee` object based on the specified interface or input file.
/// If `pcap_out` is provided, sets the capture to write raw packets to the given file.
fn create_capture_bee(
    interface: Option<String>,
    input_file: Option<PathBuf>,
    pcap_out: Option<PathBuf>,
) -> CaptureBee {
    match (interface, input_file) {
        (Some(interface), None) => {
            // Live capture from a network interface
            let cap = create_live_capture(&interface);

            let out_file = pcap_out.map(|out_file| {
                cap.savefile(out_file)
                    .expect("Failed to create pcap output file.")
            });

            let mut bee = CaptureBee::from_live_capture(cap);

            // If `pcap_out` is specified, set it as the output file for raw packets
            if let Some(out_file) = out_file {
                let raw_sink = RawSink::File(out_file);
                bee.set_raw_sink(raw_sink);
            }

            bee
        }
        _ => unreachable!("CLI argument validation should prevent this case."),
    }
}
