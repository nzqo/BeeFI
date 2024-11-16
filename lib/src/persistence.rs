use crate::errors::PersistenceError;
/** ------------------------------------------------------------
 * Persistence (saving extracted data to parquet files)
 * ------------------------------------------------------------- */
use crate::BfiData;
use std::fs::File;
use std::path::PathBuf;

use polars::prelude::*;
use polars::{datatypes::ListChunked, frame::DataFrame, series::Series};

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Parquet,
}

#[derive(Debug, Clone)]
pub struct BfaFile {
    pub file_path: PathBuf,
    pub file_type: FileType,
}

pub fn save(file: BfaFile, data: &[BfiData]) -> Result<(), PersistenceError> {
    match file.file_type {
        FileType::Parquet => save_parquet(file.file_path, data),
    }
}

pub fn save_parquet(file_path: PathBuf, data: &[BfiData]) -> Result<(), PersistenceError> {
    let timestamps_series = Series::new(
        "timestamps",
        data.iter().map(|d| d.timestamp).collect::<Vec<_>>(),
    );

    let token_nums_series = Series::new(
        "token_nums",
        data.iter()
            .map(|d| d.token_number as u32)
            .collect::<Vec<_>>(),
    );

    let bfa_angles_series = ListChunked::from_iter(data.iter().map(|d| {
        Series::new(
            "",
            d.bfa_angles
                .iter()
                .map(|inner| Series::new("", inner.iter().map(|&e| e as u32).collect::<Vec<_>>()))
                .collect::<Vec<_>>(),
        )
    }))
    .into_series();

    #[rustfmt::skip]
    #[cfg(feature = "bfi_metadata")]
    let mut metadata_columns = vec![
        Series::new("bandwidth", data.iter().map(|d| d.metadata.bandwidth as u32).collect::<Vec<_>>()),
        Series::new("nr_index", data.iter().map(|d| d.metadata.nr_index as u32).collect::<Vec<_>>()),
        Series::new("nc_index", data.iter().map(|d| d.metadata.nc_index as u32).collect::<Vec<_>>()),
        Series::new("codebook_info", data.iter().map(|d| d.metadata.codebook_info as u32).collect::<Vec<_>>()),
        Series::new("feedback_type", data.iter().map(|d| d.metadata.feedback_type as u32).collect::<Vec<_>>()),
    ];

    let mut columns = vec![timestamps_series, token_nums_series, bfa_angles_series];

    #[cfg(feature = "bfi_metadata")]
    columns.append(&mut metadata_columns);

    let mut df = DataFrame::new(columns)?;

    let file = File::create(file_path)?;
    ParquetWriter::new(file).finish(&mut df)?;

    Ok(())
}

impl std::str::FromStr for FileType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "parquet" => Ok(FileType::Parquet),
            _ => Err(format!("Invalid file type: {}", s)),
        }
    }
}
