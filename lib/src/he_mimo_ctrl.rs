//! High Efficiency (HE) MIMO Control header
//!
//! This module defines types and handles extraction of the HE MIMO Control
//! header from the bytestream of a captured WiFi packet.
use bilge::prelude::*;

/// Bandwidth enum corresponding to index in HE MIMO Control field
#[bitsize(2)]
#[derive(FromBits, Debug, Eq, PartialEq, Copy, Clone)]
pub enum Bandwidth {
    Bw20,
    Bw40,
    Bw80,
    Bw160,
}

/// Bandwidth conversion functions
impl Bandwidth {
    /// Get bandwidth value in Megahertz
    pub fn to_mhz(self) -> u16 {
        // Left shift is equal to taking power of 2
        (2 << (self as u16)) * 10
    }

    /// Get bandwidth value in Hertz
    pub fn to_hz(self) -> u32 {
        self.to_mhz() as u32 * 1_000_000
    }
}

/// HE Mimo Control header
#[bitsize(40)]
#[derive(FromBits, DebugBits)]
pub struct HeMimoControl {
    pub nc_index: u3,                    // Index for number of "columns" (streams)
    pub nr_index: u3,                    // Index for number of receive antennas
    pub bandwidth: Bandwidth,            // channel bandwidth
    pub grouping: u1,                    // Indicates subcarrier grouping (Ng=4 or 16)
    pub codebook_info: u1,               // Codebook size (depends on grouping and feedback)
    pub feedback_type: u2,               // Feedback type (0=Single User, 1= Multi User, 2= CQI)
    pub remaining_feedback_segments: u3, // Indicate number of remaining feedback segments
    pub first_feedback_segments: u1,     // Whether this is the first (or only) feedback segment
    pub ru_start_index: u7,              // first RU26 for which beamformer requests feedback
    pub ru_end_index: u7,                // Last RU26 for which beamformer requests feedback
    pub dialog_token_number: u6,         // To identify VHT NDP announcement frame
    pub reserved_padding: u4,            // Reserved padding
}

impl HeMimoControl {
    /// Extract HeMimoControl header from the packet bytestream (requires first 5 bytes.)
    pub fn from_buf(buf: &[u8]) -> Self {
        let value: UInt<u64, 40> = UInt::<u64, 40>::new(
            (buf[0] as u64)
                | ((buf[1] as u64) << 8)
                | ((buf[2] as u64) << 16)
                | ((buf[3] as u64) << 24)
                | ((buf[4] as u64) << 32),
        );
        HeMimoControl::from(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn he_mimo_ctrl_extraction() {
        // 0000 1101 1100 0100 0000 0000 1000 0010 0001 1001 = 0x0dc4008219
        // HE MIMO Control:
        // .... .... .... .... .... .... .... .... .... .001 = Nc Index: 2 Columns (1)
        // .... .... .... .... .... .... .... .... ..01 1... = Nr Index: 4 Rows (3)
        // .... .... .... .... .... .... .... .... 00.. .... = BW: 0
        // .... .... .... .... .... .... .... ...0 .... .... = Grouping: Carrier Groups of 4 (0)
        // .... .... .... .... .... .... .... ..1. .... .... = Codebook Information: 1
        // .... .... .... .... .... .... .... 00.. .... .... = Feedback Type: SU (0)
        // .... .... .... .... .... .... .000 .... .... .... = Remaining Feedback Segments: 0
        // .... .... .... .... .... .... 1... .... .... .... = First Feedback Segment: 1
        // .... .... .... .... .000 0000 .... .... .... .... = RU Start Index: 0x00
        // .... .... ..00 0100 0... .... .... .... .... .... = RU End Index: 0x08
        // .... 1101 11.. .... .... .... .... .... .... .... = Sounding Dialog Token Number: 55
        // 0000 .... .... .... .... .... .... .... .... .... = Reserved: 0x0

        // bytestream (little endian)
        let byte_stream: &[u8] = &[0b00011001, 0b10000010, 0b00000000, 0b11000100, 0b00001101];

        let result = HeMimoControl::from_buf(byte_stream);
        assert_eq!(result.nc_index(), UInt::<u8, 3>::new(1));
        assert_eq!(result.nr_index(), UInt::<u8, 3>::new(3));
        assert_eq!(result.bandwidth(), Bandwidth::Bw20);
        assert_eq!(result.grouping(), UInt::<u8, 1>::new(0));
        assert_eq!(result.codebook_info(), UInt::<u8, 1>::new(1));
        assert_eq!(result.feedback_type(), UInt::<u8, 2>::new(0));
        assert_eq!(result.remaining_feedback_segments(), UInt::<u8, 3>::new(0));
        assert_eq!(result.first_feedback_segments(), UInt::<u8, 1>::new(1));
        assert_eq!(result.ru_start_index(), UInt::<u8, 7>::new(0));
        assert_eq!(result.ru_end_index(), UInt::<u8, 7>::new(0x08));
        assert_eq!(result.dialog_token_number(), UInt::<u8, 6>::new(55));
        assert_eq!(result.reserved_padding(), UInt::<u8, 4>::new(0));
    }

    #[test]
    fn bandwidth_to_hz() {
        assert_eq!(Bandwidth::Bw20.to_hz(), 20_000_000);
        assert_eq!(Bandwidth::Bw40.to_hz(), 40_000_000);
        assert_eq!(Bandwidth::Bw80.to_hz(), 80_000_000);
        assert_eq!(Bandwidth::Bw160.to_hz(), 160_000_000);
    }

    #[test]
    fn bandwidth_to_mhz() {
        assert_eq!(Bandwidth::Bw20.to_mhz(), 20);
        assert_eq!(Bandwidth::Bw40.to_mhz(), 40);
        assert_eq!(Bandwidth::Bw80.to_mhz(), 80);
        assert_eq!(Bandwidth::Bw160.to_mhz(), 160);
    }
}
