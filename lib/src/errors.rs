//! Error types used by this lib.
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum BfaExtractionError {
    #[error("Received buffer of insufficient bit number: {available} (required: {required})")]
    InsufficientBitsize { required: usize, available: usize },
    #[error("Bitsize {given} exceeds maximum handled bitsize of {allowed}")]
    InvalidBitfieldSize { given: u8, allowed: u8 },
    #[error("Encountered invalid/unhandled antenna config: nr: {nr_index}, nc: {nc_index}")]
    InvalidAntennaConfig { nr_index: u8, nc_index: u8 },
    #[error("Encountered invalid feedback type: {fb}")]
    InvalidFeedbackType { fb: u8 },
}

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("IO error in file persistence: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "parquet")]
    #[error("Error in writing parquet file: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    #[cfg(feature = "parquet")]
    #[error("Error in writing parquet file: {0}")]
    Parquet(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum BfmConversionError {
    #[error("Encountered invalid/unhandled antenna config: nr: {nr_index}, nc: {nc_index}")]
    InvalidAntennaConfig { nr_index: u8, nc_index: u8 },
    #[error("Information extraction failed: {0}")]
    Extraction(#[from] BfaExtractionError),
}
