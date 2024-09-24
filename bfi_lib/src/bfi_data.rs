/** ------------------------------------------------------------
 * BFI/BFA data structs used throughout the library.
 * ------------------------------------------------------------- */
/**
 * Accumulated data from the packets from the pcap file
 */
#[derive(Debug)]
pub struct ExtractedBfiData {
    pub timestamps: Vec<f64>,
    pub token_nums: Vec<u8>,
    pub bfa_angles: Vec<Vec<Vec<u16>>>,
    pub meta_data: Vec<Vec<u32>>,
}

/**
 * Constructor
 */
impl ExtractedBfiData {
    pub fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            token_nums: Vec::new(),
            bfa_angles: Vec::new(),
            meta_data: Vec::new(),
        }
    }
}

/**
 * Data extracted from a single packet in the pcap
 */
pub struct SinglePacketBfiData {
    pub timestamp: f64,
    pub token_number: u8,
    pub bfa_angles: Vec<Vec<u16>>,
    pub meta_data: Vec<u32>,
}
