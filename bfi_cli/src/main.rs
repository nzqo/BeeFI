mod live_capture;

use crate::live_capture::live_capture;
use bfi_lib::extract_from_capture;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/**
 * Available CLI commands
 */
#[derive(Subcommand)]
enum Commands {
    /// Extract BFA angles and other data from a pcap capture
    Extract {
        /// pcap input file
        #[arg(short = 'f', long, value_name = "FILE")]
        pcap_file: PathBuf,

        /// parquet output file
        #[arg(short, long, value_name = "OUTFILE")]
        out_file: PathBuf,

        /// Whether to print extracted variables
        #[arg(short, long)]
        print: bool,
    },
    // starts live capture of bfa
    Capture {
        /// Chose interface to be used
        #[arg(short = 'i', long, value_name = "INTERFACE")]
        interface: String,

        /// parquet output file
        #[arg(short, long, value_name = "OUTFILE")]
        out_file: PathBuf,

        /// Whether to print extracted variables
        #[arg(short, long)]
        print: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Extract {
            pcap_file,
            out_file,
            print,
        }) => {
            handle_extract_command(pcap_file, out_file, print);
        }
        Some(Commands::Capture {
            interface,
            out_file,
            print,
        }) => {
            live_capture(interface, out_file, print);
        }
        None => {}
    }
}

fn handle_extract_command(pcap_file: PathBuf, out_file: PathBuf, print: bool) {
    let extracted_data = extract_from_capture(pcap_file);

    if print {
        println!("Extracted data: {:?}\n", extracted_data);
    }

    if let Err(e) = extracted_data.to_parquet(out_file) {
        eprintln!("Writing to parquet failed with error: {}", e);
    }

    println!("Data extraction completed!\n");
}
