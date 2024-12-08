use beefi_lib::{
    create_live_capture, extract_from_pcap, BfiFile, HoneySink, PollenSink, StreamBee, Writer,
};

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::cli::{OfflineCaptureArgs, OnlineCaptureArgs};

pub fn run_online_capture(args: OnlineCaptureArgs) {
    let OnlineCaptureArgs {
        interface,
        pcap_out,
        bfi_out,
        format,
        print,
        pcap_snaplen,
        pcap_buffered,
        pcap_bufsize,
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
    let mut bee = create_bee(
        Some(interface),
        None,
        pcap_out,
        pcap_buffered,
        pcap_snaplen,
        pcap_bufsize,
    );

    if let Some(bfi_out_path) = bfi_out {
        let processed_sink = HoneySink::File(BfiFile {
            file_path: bfi_out_path,
            file_type: format,
        });
        bee.subscribe_for_honey(processed_sink);
    }

    // Start capturing
    bee.start_harvesting(print);

    // Wait for CTRL+C
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Cleanup if necessary
    println!("Shutting down gracefully...");
    bee.stop();
}

pub fn run_offline_capture(args: OfflineCaptureArgs) {
    let data = extract_from_pcap(args.pcap_in);

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
    buffered: bool,
    snaplen: i32,
    bufsize: i32,
) -> StreamBee {
    match (interface, input_file) {
        (Some(interface), None) => {
            // Live capture from a network interface
            let cap = create_live_capture(&interface, buffered, Some(snaplen), Some(bufsize));

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