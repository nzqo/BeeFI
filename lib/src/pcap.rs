//! Some pcap handling helpers

use crate::extraction::{extract_bfa, ExtractionConfig};
use crate::he_mimo_ctrl::HeMimoControl;
use crate::BfiData;
use pcap::{Capture, Packet};
use std::path::PathBuf;

/// Extract BFI data from a single WiFi packet captured with pcap
pub fn extract_from_packet(packet: &Packet) -> BfiData {
    const MIMO_CTRL_HEADER_OFFSET: usize = 26;
    const BFA_HEADER_OFFSET: usize = 7;
    const FCS_LENGTH: usize = 4;

    // Extract the timestamp from the pcap packet
    let timestamp = packet.header.ts;
    let timestamp_secs = timestamp.tv_sec as f64 + timestamp.tv_usec as f64 * 1e-6;

    let header_length = u16::from_le_bytes([packet.data[2], packet.data[3]]) as usize;
    let mimo_ctrl_start = header_length + MIMO_CTRL_HEADER_OFFSET;

    let mimo_control = HeMimoControl::from_buf(&packet[mimo_ctrl_start..]);
    let extraction_config = ExtractionConfig::from_he_mimo_ctrl(&mimo_control);

    // NOTE: BFA data starts after mimo_control (5 bytes) and SNR (2 bytes)
    // They last until before the last four bytes (Frame Check Sequence)
    let bfa_start = mimo_ctrl_start + BFA_HEADER_OFFSET;
    let bfa_end = packet.len() - FCS_LENGTH;

    // Extract the binary data of the BFA angles
    let bfa_data = &packet[bfa_start..bfa_end];
    let bfa_angles = extract_bfa(bfa_data, extraction_config).expect("BFA extraction failed");

    BfiData {
        #[cfg(feature = "bfi_metadata")]
        metadata: crate::BfiMetadata::from_mimo_ctrl_header(&mimo_control),
        timestamp: timestamp_secs,
        token_number: u8::from(mimo_control.dialog_token_number()),
        bfa_angles,
    }
}

/// Extract all BFI data from a pcap file
///
/// # Parameters
/// * `file_path` - Path to the pcap file
pub fn extract_from_pcap(pcap_file: PathBuf) -> Vec<BfiData> {
    log::trace!(
        "Extracting BFI data from pcap file: {}",
        pcap_file.display(),
    );

    let mut capture = Capture::from_file(pcap_file).expect("Couldn't open pcap file");
    let mut extracted_data = Vec::new();

    while let Ok(packet) = capture.next_packet() {
        let packet = extract_from_packet(&packet);
        extracted_data.push(packet);
    }

    log::trace!(
        "Extracted {} BFI data points from pcap file.",
        extracted_data.len()
    );
    extracted_data
}
