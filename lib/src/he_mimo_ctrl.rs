/** ------------------------------------------------------------
 * HE Mimo Control Header extraction.
 * ------------------------------------------------------------- */
use bilge::prelude::*;

/**
 * Bandwidth enum corresponding to index order in HE MIMO Control field
 */
#[bitsize(2)]
#[derive(FromBits, Debug, Eq, PartialEq, Copy, Clone)]
pub enum Bandwidth {
    Bw20,
    Bw40,
    Bw80,
    Bw160,
}

/**
 * Bandwidth conversion functions
 */
impl Bandwidth {
    pub fn to_mhz(self) -> u16 {
        // Left shift is equal to taking power of 2
        (2 << (self as u16)) * 10
    }

    pub fn to_hz(self) -> u32 {
        self.to_mhz() as u32 * 1_000_000
    }
}

/**
 * Full HE Mimo Control fields
 */
#[bitsize(40)]
#[derive(FromBits, DebugBits)]
pub struct HeMimoControl {
    pub nc_index: u3,
    pub nr_index: u3,
    pub bandwidth: Bandwidth,
    pub grouping: u1,
    pub codebook_info: u1,
    pub feedback_type: u2,
    pub remaining_feedback_segments: u3,
    pub first_feedback_segments: u1,
    pub ru_start_index: u7,
    pub ru_end_index: u7,
    pub dialog_token_number: u6,
    pub reserved_padding: u4,
}

/**
 * Extract HeMimoControl from 5 bytes in buffer
 */
impl HeMimoControl {
    pub fn from_buf(buf: &[u8]) -> Self {
        let test: UInt<u64, 40> = UInt::<u64, 40>::new(
            (buf[0] as u64)
                | ((buf[1] as u64) << 8)
                | ((buf[2] as u64) << 16)
                | ((buf[3] as u64) << 24)
                | ((buf[4] as u64) << 32),
        );
        HeMimoControl::from(test)
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
