use crate::{errors::PersistenceError, BfiData};
use std::path::PathBuf;

#[cfg(feature = "parquet")]
mod parquet;

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    #[cfg(feature = "parquet")]
    Parquet,
    Dummy,
}

#[derive(Debug, Clone)]
pub struct BfiFile {
    pub file_path: PathBuf,
    pub file_type: FileType,
}

#[allow(clippy::large_enum_variant)]
pub enum Writer {
    #[cfg(feature = "parquet")]
    Parquet(parquet::BatchWriter),
    Dummy(),
}

impl Writer {
    pub fn new(file: BfiFile) -> Result<Self, PersistenceError> {
        let writer = match file.file_type {
            #[cfg(feature = "parquet")]
            FileType::Parquet => Self::Parquet(parquet::BatchWriter::new(file.file_path)?),
            FileType::Dummy => Self::Dummy(),
        };

        Ok(writer)
    }

    pub fn add_batch(&mut self, data: &[BfiData]) -> Result<(), PersistenceError> {
        match self {
            #[cfg(feature = "parquet")]
            Writer::Parquet(writer) => writer.add_batch(data),
            Writer::Dummy() => {
                log::warn!("Tried to write to dummy file; Ignoring. Specify a proper file type.");
                Ok(())
            }
        }
    }

    pub fn finalize(&mut self) -> Result<u64, PersistenceError> {
        match self {
            #[cfg(feature = "parquet")]
            Writer::Parquet(writer) => writer.finalize(),
            Writer::Dummy() => Ok(0),
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
