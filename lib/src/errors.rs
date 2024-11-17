//! Error types used by this lib.
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum BfaExtractionError {
    #[error("Received buffer of insufficient bit number: {available} (required: {required})")]
    InsufficientBitsize { required: usize, available: usize },
    #[error("Bitsize {given} exceeds maximum handled bitsize of {allowed}")]
    InvalidBitfieldSize { given: u8, allowed: u8 },
}

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[cfg(feature = "parquet")]
    #[error("Error in writing parquet file: {0}")]
    Parquet(#[from] polars::error::PolarsError),
    #[error("IO error in file persistence: {0}")]
    Io(#[from] std::io::Error),
}
