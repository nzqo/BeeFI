//! BFM data structs used throughout the library.

use ndarray::Array3;
use num_complex::Complex64;

use crate::BfiMetadata;

pub type FeedbackMatrix = Array3<Complex64>;

/// Beamforming Feedback Matrix Data extracted from a single packet.
#[derive(Debug, Clone)]
pub struct BfmData {
    #[cfg(feature = "bfi_metadata")]
    pub metadata: BfiMetadata,
    pub timestamp: f64,
    pub token_number: u8,
    pub feedback_matrix: FeedbackMatrix,
}
