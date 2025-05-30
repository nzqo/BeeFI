//! BFI/BFA data structs used throughout the library.

use crate::he_mimo_ctrl::HeMimoControl;

/// Metadata extracted from a single WiFi packet.
#[derive(Debug, Clone)]
pub struct BfiMetadata {
    pub bandwidth: u16,
    pub nr_index: u8,
    pub nc_index: u8,
    pub codebook_info: u8,
    pub feedback_type: u8,
}

impl BfiMetadata {
    /// Extract metadata from a HE Mimo Control packet header
    ///
    /// # Arguments
    ///
    /// * `header` - The he mimo control header
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

/// Beamforming Feedback Angle data extracted from a single packet.
#[derive(Debug, Clone)]
pub struct BfaData {
    #[cfg(feature = "bfi_metadata")]
    pub metadata: BfiMetadata,
    pub timestamp: f64,
    pub token_number: u8,
    pub bfa_angles: Vec<Vec<u16>>,
}

/// Batch type for the above data.
///
/// This is just a helper type mostly for the python binding, since it
/// allows for simpler conversion to numpy arrays.
#[derive(Debug, Clone)]
pub struct BfaDataBatch {
    #[cfg(feature = "bfi_metadata")]
    pub metadata: Vec<BfiMetadata>,
    pub timestamps: Vec<f64>,
    pub token_numbers: Vec<u8>,
    pub bfa_angles: Vec<Vec<Vec<u16>>>,
}

/// Split a vector of BFI data into the BFI batch type
pub fn split_bfi_data(input: Vec<BfaData>) -> BfaDataBatch {
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

    // Return a BfaDataBatch with the collected data
    BfaDataBatch {
        #[cfg(feature = "bfi_metadata")]
        metadata,
        timestamps,
        token_numbers,
        bfa_angles,
    }
}
