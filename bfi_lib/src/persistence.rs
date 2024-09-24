/** ------------------------------------------------------------
 * Persistence (saving extracted data to parquet files)
 * ------------------------------------------------------------- */
use crate::bfi_data::{ExtractedBfiData, SinglePacketBfiData};
use crate::PathBuf;
use std::fs::{File, OpenOptions};

use polars::prelude::*;
use polars::{datatypes::ListChunked, error::PolarsError, frame::DataFrame, series::Series};

/**
 * Parquet conversion of extracted BFI data from capture
 */
impl ExtractedBfiData {
    pub fn to_parquet(&self, file_path: PathBuf) -> Result<(), PolarsError> {
        // Convert timestamps and token_nums to Polars Series
        let timestamps_series = Series::new("timestamps", &self.timestamps);

        // Convert Vec<u8> to Vec<u32> for token_nums
        // Required because polars doesnt support u8
        let token_nums_series = Series::new(
            "token_nums",
            &self
                .token_nums
                .iter()
                .map(|&num| num as u32)
                .collect::<Vec<u32>>(),
        );

        // Convert Vec<Vec<u8>> to a List Series of Vec<i32>
        let bfa_angles_series = ListChunked::from_iter(self.bfa_angles.iter().map(|outer| {
            ListChunked::from_iter(outer.iter().map(|inner| {
                UInt32Chunked::from_vec(
                    "bfa_angles_inner",
                    inner.iter().map(|&e| e as u32).collect::<Vec<u32>>(),
                )
                .into_series()
            }))
            .into_series()
        }))
        .into_series();

        // Construct DataFrame from the series
        let mut df = DataFrame::new(vec![
            timestamps_series,
            token_nums_series,
            bfa_angles_series,
        ])?;

        // Write DataFrame to a Parquet file
        let file = File::create(file_path)?;
        ParquetWriter::new(file).finish(&mut df)?;

        Ok(())
    }
}

/**
 * Parquet conversion of extracted BFI data from live capture
 */
impl SinglePacketBfiData {
    pub fn to_parquet(&self, file_path: PathBuf) -> Result<(), PolarsError> {
        // Convert timestamp and token_number to Polars Series with a single element
        let timestamp_series = Series::new("timestamp", &[self.timestamp]);
        let token_number_series = Series::new(
            "token_number",
            &[self.token_number as u32], // Convert u8 to u32 since Polars doesn't support u8
        );

        // Convert Vec<Vec<u16>> to a List Series of Vec<Vec<Vec<u32>>>  with a single row
        let bfa_angles_series = ListChunked::from_iter(vec![ListChunked::from_iter(
            self.bfa_angles.iter().map(|inner| {
                UInt32Chunked::from_vec(
                    "bfa_angles_inner",
                    inner.iter().map(|&e| e as u32).collect::<Vec<u32>>(),
                )
                .into_series()
            }),
        )
        .into_series()])
        .into_series();

        // TODO: add meta info also to parquet file, currently commented out because it create
        // a second "collected" column causinf erreors with polars
        // Convert Vec<u32> to a List Series with a single element as Vec<Vec<u32>>
        // let meta_data_series = ListChunked::from_iter(vec![
        //     Series::new("meta_data", self.meta_data.as_slice())
        //     ]).into_series().rename("meta_data");

        // Create a DataFrame with a single row
        let mut df = DataFrame::new(vec![
            timestamp_series,
            token_number_series,
            bfa_angles_series,
            // meta_data_series,
        ])?;

        if file_path.exists() {
            // If the file exists, read the existing data
            let mut file = File::open(&file_path)?;
            let existing_df = ParquetReader::new(&mut file).finish()?;

            // Concatenate the new DataFrame with the existing DataFrame
            df = concatenate_dataframes(&existing_df, &df)?;
        }

        // Write (or overwrite) the DataFrame to the Parquet file
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)?;
        ParquetWriter::new(file).finish(&mut df)?;

        Ok(())
    }
}

fn concatenate_dataframes(df1: &DataFrame, df2: &DataFrame) -> Result<DataFrame, PolarsError> {
    let concatenated = df1.vstack(df2)?;
    Ok(concatenated)
}
