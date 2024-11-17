//! Persistence module
//!
//! Handles saving extracted BFI data to files. Currently supported file types are:
//! - [x] Parquet
use crate::errors::PersistenceError;
use crate::BfiData;

use polars::prelude::*;
use polars::{datatypes::ListChunked, frame::DataFrame, series::Series};
use std::fs::File;
use std::path::PathBuf;

#[cfg(feature = "bfi_metadata")]
const NUM_COLUMNS: usize = 8; // 3 base fields + 5 metadata fields

#[cfg(not(feature = "bfi_metadata"))]
const NUM_COLUMNS: usize = 3; // Only 3 base fields

pub struct BatchWriter {
    file: PathBuf,
    writer: polars::io::parquet::write::BatchedWriter<File>,
}

impl BatchWriter {
    pub fn new(file_path: PathBuf) -> Result<Self, PersistenceError> {
        let file = std::fs::File::create(&file_path)?;
        let schema = create_bfi_schema();
        Ok(Self {
            file: file_path,
            writer: ParquetWriter::new(file)
                .with_compression(ParquetCompression::Snappy)
                .set_parallel(true)
                .batched(&schema)?,
        })
    }

    pub fn finalize(&mut self) -> Result<u64, PersistenceError> {
        self.writer.finish().map_err(PersistenceError::Parquet)
    }

    pub fn add_batch(&mut self, data: &[BfiData]) -> Result<(), PersistenceError> {
        log::trace!(
            "Saving {} data points to parquet file {}",
            data.len(),
            self.file.display(),
        );

        let timestamps_series =
            Series::from_iter(data.iter().map(|d| d.timestamp)).with_name("timestamps");

        let token_nums_series =
            Series::from_iter(data.iter().map(|d| d.token_number as u32)).with_name("token_nums");

        let bfa_angles_series = ListChunked::from_iter(data.iter().map(|d| {
            let mut inner_series = Vec::with_capacity(d.bfa_angles.len());
            for inner in &d.bfa_angles {
                let converted_inner = inner.iter().map(|&e| e as u32).collect::<Vec<_>>();
                inner_series.push(Series::new("", converted_inner));
            }
            Series::new("", inner_series)
        }))
        .into_series()
        .with_name("bfa_angles");

        let mut columns = vec![timestamps_series, token_nums_series, bfa_angles_series];

        #[cfg(feature = "bfi_metadata")]
        {
            let mut bandwidth = Vec::with_capacity(data.len());
            let mut nr_index = Vec::with_capacity(data.len());
            let mut nc_index = Vec::with_capacity(data.len());
            let mut codebook_info = Vec::with_capacity(data.len());
            let mut feedback_type = Vec::with_capacity(data.len());

            for d in data.iter() {
                bandwidth.push(d.metadata.bandwidth as u32);
                nr_index.push(d.metadata.nr_index as u32);
                nc_index.push(d.metadata.nc_index as u32);
                codebook_info.push(d.metadata.codebook_info as u32);
                feedback_type.push(d.metadata.feedback_type as u32);
            }

            columns.push(Series::new("bandwidth", bandwidth));
            columns.push(Series::new("nr_index", nr_index));
            columns.push(Series::new("nc_index", nc_index));
            columns.push(Series::new("codebook_info", codebook_info));
            columns.push(Series::new("feedback_type", feedback_type));
        }

        let df = DataFrame::new(columns)?;
        log::trace!("Created dataframe {}", df);
        self.write(df)
    }

    fn write(&mut self, df: DataFrame) -> Result<(), PersistenceError> {
        self.writer.write_batch(&df)?;
        Ok(())
    }
}

fn create_bfi_schema() -> Schema {
    // Initialize an empty Schema with a predefined capacity (optional)
    let mut schema = Schema::with_capacity(NUM_COLUMNS);

    // Add fields directly to the schema
    schema.with_column("timestamps".into(), DataType::Float64);
    schema.with_column("token_nums".into(), DataType::UInt32);
    schema.with_column(
        "bfa_angles".into(),
        DataType::List(Box::new(DataType::List(Box::new(DataType::UInt32)))),
    );

    #[cfg(feature = "bfi_metadata")]
    {
        schema.with_column("bandwidth".into(), DataType::UInt32);
        schema.with_column("nr_index".into(), DataType::UInt32);
        schema.with_column("nc_index".into(), DataType::UInt32);
        schema.with_column("codebook_info".into(), DataType::UInt32);
        schema.with_column("feedback_type".into(), DataType::UInt32);
    }

    schema
}

// fn write_or_append(mut df: DataFrame, file_path: PathBuf) -> Result<(), PersistenceError> {
//     if !file_path.exists() {
//         log::trace!("Creating new parquet file {}", file_path.display());
//         // No file exists, so just write the new data
//         let file = std::fs::File::create(&file_path)?;
//         ParquetWriter::new(file)
//             .with_compression(ParquetCompression::Snappy)
//             .set_parallel(true)
//             .finish(&mut df)?;
//     } else {
//         log::trace!("Lazily appending to parquet file {}", file_path.display());

//         // If file exists, load it lazily
//         let existing_lazy_df = LazyFrame::scan_parquet(&file_path, Default::default())?;

//         // Append new data without loading the whole file into memory
//         let merged_lazy_df = concat(&[df.lazy(), existing_lazy_df], UnionArgs::default())?;

//         // Write to a temporary file. This is required since we scan from `file_path`,
//         // so we cannot directly write back to it without conflicts.
//         let temp_file_path = file_path.with_extension("tmp.parquet");
//         let _file = std::fs::File::create(&temp_file_path)?;

//         let options = ParquetWriteOptions {
//             compression: ParquetCompression::Snappy,
//             maintain_order: true,
//             ..Default::default()
//         };
//         merged_lazy_df.sink_parquet(&temp_file_path, options)?;

//         // Replace the original file with the new file
//         std::fs::rename(temp_file_path, file_path)?;
//     }

//     log::trace!("Finished writing to file.");
//     Ok(())
// }
