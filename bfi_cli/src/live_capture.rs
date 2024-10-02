use bfi_lib::{extract_from_packet, SinglePacketBfiData};
use pcap::{Active, Capture, Device};
use std::path::PathBuf;

pub fn live_capture(interface_name: String, out_file: PathBuf, print: bool) {
    println!("Starting live capture...");

    // Get the desired device and start a PCAP capture on it
    let devices = Device::list().unwrap_or_else(|e| {
        panic!("Error listing devices: {}", e);
    });

    let device = devices
        .into_iter()
        .find(|d| d.name == interface_name)
        .expect("Failed to find the specified interface");

    let cap = start_packet_capture(device, false);

    capture_packets(cap, out_file, print);

    println!("Live capture and data processing completed!\n");
}

/**
 * Start a packet capture for BFI packets
 */
fn start_packet_capture(device: Device, buffered: bool) -> Capture<Active> {
    let filter = "ether[0] == 0xe0";
    let mut cap = Capture::from_device(device)
        .expect("Couldn't create PCAP capture")
        .rfmon(true)
        .immediate_mode(!buffered) // If buffering is off, immediately receive packets
        .snaplen(65535)
        .open()
        .expect("Couldn't open PCAP capture");
    cap.filter(filter, true).expect("Failed to apply filter!");

    println!("PCAP capture successfully started");
    cap
}

/**
 * Capture BFI packets from the interface
 */
fn capture_packets(mut cap: Capture<Active>, out_file: PathBuf, print: bool) {
    let mut packet_buffer = Vec::new();
    let batch_size = 10;

    while let Ok(packet) = cap.next_packet() {
        let result = extract_from_packet(&packet);

        if print {
            println!(
                "Captured packet -- timestamp: {}, token: {}, length: {}",
                result.timestamp,
                result.token_number,
                result.bfa_angles.len()
            );
        }

        packet_buffer.push(result);

        if packet_buffer.len() >= batch_size {
            write_packets_to_parquet(&packet_buffer, &out_file);
            packet_buffer.clear();
        }
    }
}

/**
 * Write a slice of single packets to a dataframe
 */
fn write_packets_to_parquet(packet_buffer: &[SinglePacketBfiData], out_file: &PathBuf) {
    for packet_data in packet_buffer {
        if let Err(e) = packet_data.to_parquet(out_file.clone()) {
            eprintln!("Failed to write to Parquet: {}", e);
        }
    }
}
