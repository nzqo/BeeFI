//! BFI/BFA data structs used throughout the library.

use crate::he_mimo_ctrl::HeMimoControl;

/**
 * Metadata extracted from packets
 */
#[derive(Debug, Clone)]
pub struct BfiMetadata {
    pub bandwidth: u16,
    pub nr_index: u8,
    pub nc_index: u8,
    pub codebook_info: u8,
    pub feedback_type: u8,
}

impl BfiMetadata {
    pub fn from_mimo_ctrl_header(header: &HeMimoControl) -> Self {
        Self {
            bandwidth: header.bandwidth().to_mhz(),
            nr_index: header.nr_index().into(),
            nc_index: header.nc_index().into(),
            codebook_info: header.codebook_info().into(),
            feedback_type: header.feedback_type().into(),
        }
    }
}

/**
 * Data extracted from a single packet in the pcap
 */
#[derive(Debug, Clone)]
pub struct BfiData {
    #[cfg(feature = "bfi_metadata")]
    pub metadata: BfiMetadata,
    pub timestamp: f64,
    pub token_number: u8,
    pub bfa_angles: Vec<Vec<u16>>,
}

/**
 * A batch of data
 */
#[derive(Debug, Clone)]
pub struct BfiDataBatch {
    #[cfg(feature = "bfi_metadata")]
    pub metadata: Vec<BfiMetadata>,
    pub timestamps: Vec<f64>,
    pub token_numbers: Vec<u8>,
    pub bfa_angles: Vec<Vec<Vec<u16>>>,
}

pub fn split_bfi_data(input: Vec<BfiData>) -> BfiDataBatch {
    // Initialize vectors for each field
    #[cfg(feature = "bfi_metadata")]
    let mut metadata = Vec::with_capacity(input.len());
    let mut timestamps = Vec::with_capacity(input.len());
    let mut token_numbers = Vec::with_capacity(input.len());
    let mut bfa_angles = Vec::with_capacity(input.len());

    // Populate each vector by iterating over the input data
    for data in input {
        #[cfg(feature = "bfi_metadata")]
        metadata.push(data.metadata);
        timestamps.push(data.timestamp);
        token_numbers.push(data.token_number);
        bfa_angles.push(data.bfa_angles);
    }

    // Return a BfiDataBatch with the collected data
    BfiDataBatch {
        #[cfg(feature = "bfi_metadata")]
        metadata,
        timestamps,
        token_numbers,
        bfa_angles,
    }
}
