#![allow(dead_code)]

/** ------------------------------------------------------------
 * Public library API
 * ------------------------------------------------------------- */
mod errors;
mod extract_bfa;
mod he_mimo_ctrl;
mod persistence;
mod util;

use extract_bfa::{extract_bfa, ExtractionConfig};
use he_mimo_ctrl::HeMimoControl;
use pcap::{Capture, Packet};
use std::path::PathBuf;

// Public re-export
pub mod bfi_data;
pub use crate::bfi_data::{ExtractedBfiData, SinglePacketBfiData};

/**
 * Extract data from a single packet
 */
pub fn extract_from_packet(packet: &Packet) -> SinglePacketBfiData {
    const MIMO_CTRL_HEADER_OFFSET: usize = 26;
    const BFA_HEADER_OFFSET: usize = 7;
    const FCS_LENGTH: usize = 4;

    // Extract the timestamp from the pcap packet
    let timestamp = packet.header.ts;
    println!("time, ");
    let timestamp_secs = timestamp.tv_sec as f64 + timestamp.tv_usec as f64 * 1e-6;

    let header_length = u16::from_le_bytes([packet.data[2], packet.data[3]]) as usize;
    let mimo_ctrl_start = header_length + MIMO_CTRL_HEADER_OFFSET;

    let mimo_control = HeMimoControl::from_buf(&packet[mimo_ctrl_start..]);

    let mut meta_data = Vec::new();
    meta_data.push(mimo_control.bandwidth().to_mhz());
    meta_data.push(mimo_control.nr_index().into());
    meta_data.push(mimo_control.nc_index().into());
    meta_data.push(mimo_control.codebook_info().into());
    meta_data.push(mimo_control.feedback_type().into());

    let extraction_config = ExtractionConfig::from_he_mimo_ctrl(&mimo_control);
    meta_data.push(extraction_config.num_subcarrier.try_into().unwrap());

    // NOTE: BFA data starts after mimo_control (5 bytes) and SNR (2 bytes)
    // They last until before the last four bytes (Frame Check Sequence)
    let bfa_start = mimo_ctrl_start + BFA_HEADER_OFFSET;
    let bfa_end = packet.len() - FCS_LENGTH;

    // Extract the binary data of the BFA angles
    let bfa_data = &packet[bfa_start..bfa_end];
    let bfa_angles = extract_bfa(bfa_data, extraction_config).expect("BFA extraction failed");

    SinglePacketBfiData {
        timestamp: timestamp_secs,
        token_number: u8::from(mimo_control.dialog_token_number()),
        bfa_angles: bfa_angles,
        meta_data,
    }
}

/**
 * Extract data from a pcap file
 *
 * \param capture_path Path to pcap capture file
 *
 */
pub fn extract_from_capture(capture_path: PathBuf) -> ExtractedBfiData {
    let mut capture = Capture::from_file(capture_path).expect("Couldn't open pcap file");
    let mut extracted_data = ExtractedBfiData::new();

    while let Ok(packet) = capture.next_packet() {
        let SinglePacketBfiData {
            timestamp,
            token_number,
            bfa_angles,
            meta_data,
        } = extract_from_packet(&packet);

        extracted_data.timestamps.push(timestamp);
        extracted_data.token_nums.push(token_number);
        extracted_data.bfa_angles.push(bfa_angles);
        extracted_data.meta_data.push(meta_data);
    }

    extracted_data
}
