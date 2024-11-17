use crate::{errors::PersistenceError, BfiData};
use std::path::PathBuf;

#[cfg(feature = "parquet")]
mod parquet;

/// File formats supported for writing
#[derive(Debug, Clone, Copy)]
pub enum FileType {
    /// Apache Parquet file
    #[cfg(feature = "parquet")]
    Parquet,
    /// Dummy type to satisfy clippy in case parquet is disabled.
    _Dummy,
}

/// Struct specifying a file to write BFI data to
#[derive(Debug, Clone)]
pub struct BfiFile {
    /// Path to file
    pub file_path: PathBuf,
    /// Type of file
    pub file_type: FileType,
}

/// A writer to handle file writes
#[allow(clippy::large_enum_variant)]
pub enum Writer {
    #[cfg(feature = "parquet")]
    Parquet(parquet::BatchWriter),
    _Dummy,
}

impl Writer {
    /// Create a new file writer.
    ///
    /// # Arguments
    ///
    /// * `file` - The file to write to
    pub fn new(file: BfiFile) -> Result<Self, PersistenceError> {
        let writer = match file.file_type {
            #[cfg(feature = "parquet")]
            FileType::Parquet => Self::Parquet(parquet::BatchWriter::new(file.file_path)?),
            FileType::_Dummy => Self::_Dummy,
        };

        Ok(writer)
    }

    /// Add a batch of data to the writer
    ///
    /// # Arguments
    ///
    /// * `data` A batch (slice) of data to write to the file
    pub fn add_batch(&mut self, data: &[BfiData]) -> Result<(), PersistenceError> {
        match self {
            #[cfg(feature = "parquet")]
            Writer::Parquet(writer) => writer.add_batch(data),
            Writer::_Dummy => {
                log::warn!("Tried to write to dummy file; Ignoring. Specify a proper file type.");
                Ok(())
            }
        }
    }

    /// Finalize the file writes, i.e. clear all buffers and make sure
    /// the data is actually written to file.
    ///
    /// Returns the number of bytes written or an error if any occured.
    pub fn finalize(&mut self) -> Result<u64, PersistenceError> {
        match self {
            #[cfg(feature = "parquet")]
            Writer::Parquet(writer) => writer.finalize(),
            Writer::_Dummy => Ok(0),
        }
    }
}

impl std::str::FromStr for FileType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "parquet")]
            "parquet" => Ok(FileType::Parquet),
            _ => Err(format!("Invalid file type: {}", s)),
        }
    }
}
