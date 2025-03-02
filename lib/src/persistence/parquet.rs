//! Parquet file writer
use crate::errors::PersistenceError;
use crate::BfaData;
use crate::BfmData;
use arrow::array::{
    ArrayRef, Float64Builder, ListBuilder, UInt16Array, UInt16Builder, UInt8Array, UInt8Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

// ---------- Schema Creation ----------
#[cfg(feature = "bfi_metadata")]
const NUM_META_COLUMNS: usize = 7; // 2 base + 5 extra metadata
#[cfg(not(feature = "bfi_metadata"))]
const NUM_META_COLUMNS: usize = 2;

/// Create base schema (metadata)
fn create_base_schema(num_data_fields: usize) -> Schema {
    let mut fields = Vec::with_capacity(NUM_META_COLUMNS + num_data_fields);
    fields.push(Field::new("timestamps", DataType::Float64, false));
    fields.push(Field::new("token_nums", DataType::UInt8, false));
    #[cfg(feature = "bfi_metadata")]
    {
        fields.push(Field::new("bandwidth", DataType::UInt16, false));
        fields.push(Field::new("nr_index", DataType::UInt8, false));
        fields.push(Field::new("nc_index", DataType::UInt8, false));
        fields.push(Field::new("codebook_info", DataType::UInt8, false));
        fields.push(Field::new("feedback_type", DataType::UInt8, false));
    }
    Schema::new(fields)
}

/// Create BFA schema
fn create_bfa_schema() -> Schema {
    let mut fields = create_base_schema(1).fields().to_vec();
    // bfa_angles is defined as List(List(UInt32))
    let inner = DataType::List(Arc::new(Field::new("item", DataType::UInt16, true)));
    let outer = DataType::List(Arc::new(Field::new("item", inner, true)));
    fields.push(Arc::new(Field::new("bfa_angles", outer, true)));
    Schema::new(fields)
}

/// Create BFM schema
fn create_bfm_schema() -> Schema {
    // Start with base schema (timestamps, token_nums, and optional metadata)
    let mut fields = create_base_schema(2).fields().to_vec();

    // Create triply nested list: List<List<List(Float64)>>
    let inner = DataType::List(Arc::new(Field::new("item", DataType::Float64, true)));
    let mid = DataType::List(Arc::new(Field::new("item", inner, true)));
    let outer = DataType::List(Arc::new(Field::new("item", mid, true)));

    fields.push(Arc::new(Field::new("bfm_abs", outer.clone(), false)));
    fields.push(Arc::new(Field::new("bfm_phase", outer, false)));
    Schema::new(fields)
}

/// A batch writer to write batches of BFA/BFM data to a Parquet file.
pub struct BatchWriter {
    writer: Option<ArrowWriter<File>>,
}

impl BatchWriter {
    fn new_with_schema(file_path: PathBuf, schema: Schema) -> Result<Self, PersistenceError> {
        let file = File::create(&file_path)?;
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();
        let writer = ArrowWriter::try_new(file, Arc::new(schema), Some(props))
            .map_err(|e| PersistenceError::Parquet(e.to_string()))?;
        Ok(Self {
            writer: Some(writer),
        })
    }

    /// Create a writer for BFA data
    pub fn new_bfa(file_path: PathBuf) -> Result<Self, PersistenceError> {
        Self::new_with_schema(file_path, create_bfa_schema())
    }

    /// Create a writer for BFM data
    pub fn new_bfm(file_path: PathBuf) -> Result<Self, PersistenceError> {
        Self::new_with_schema(file_path, create_bfm_schema())
    }

    /// Write a record batch
    fn write(&mut self, batch: RecordBatch) -> Result<(), PersistenceError> {
        // Access writer from Option
        if let Some(writer) = &mut self.writer {
            writer
                .write(&batch)
                .map_err(|e| PersistenceError::Parquet(e.to_string()))
        } else {
            Err(PersistenceError::Parquet(
                "Writer has been finalized".into(),
            ))
        }
    }

    /// Finalize the writer by taking ownership and closing it.
    /// Returns 0 (as per your original API) on success.
    pub fn finalize(&mut self) -> Result<u64, PersistenceError> {
        // Take the writer out of the Option so we can call close() (which takes self)
        let writer = self
            .writer
            .take()
            .ok_or_else(|| PersistenceError::Parquet("Writer already finalized".into()))?;
        // Call close(), ignore the metadata, and return 0.
        let _metadata = writer
            .close()
            .map_err(|e| PersistenceError::Parquet(e.to_string()))?;

        // TODO try to figure out if we can find the number of bytes written at this point..
        Ok(0)
    }

    /// Add a batch of BFA data.
    pub fn add_bfa_batch(&mut self, data: &[BfaData]) -> Result<(), PersistenceError> {
        // Build timestamps and token_nums.
        let mut ts_builder = Float64Builder::new();
        let mut token_builder = UInt8Builder::new();
        #[cfg(feature = "bfi_metadata")]
        let (
            mut bandwidth_vec,
            mut nr_index_vec,
            mut nc_index_vec,
            mut codebook_vec,
            mut feedback_type_vec,
        ) = (
            Vec::with_capacity(data.len()),
            Vec::with_capacity(data.len()),
            Vec::with_capacity(data.len()),
            Vec::with_capacity(data.len()),
            Vec::with_capacity(data.len()),
        );
        // Build bfa_angles as nested lists.
        let mut outer_builder = ListBuilder::new(ListBuilder::new(UInt16Builder::new()));

        for d in data {
            ts_builder.append_value(d.timestamp);
            token_builder.append_value(d.token_number);
            #[cfg(feature = "bfi_metadata")]
            {
                bandwidth_vec.push(d.metadata.bandwidth);
                nr_index_vec.push(d.metadata.nr_index);
                nc_index_vec.push(d.metadata.nc_index);
                codebook_vec.push(d.metadata.codebook_info);
                feedback_type_vec.push(d.metadata.feedback_type);
            }
            let inner_builder = outer_builder.values();
            for inner in &d.bfa_angles {
                for &angle in inner {
                    inner_builder.values().append_value(angle);
                }
                inner_builder.append(true);
            }
            outer_builder.append(true);
        }
        let ts_array = Arc::new(ts_builder.finish()) as ArrayRef;
        let token_array = Arc::new(token_builder.finish()) as ArrayRef;
        let bfa_angles_array = Arc::new(outer_builder.finish()) as ArrayRef;
        let mut arrays = vec![ts_array, token_array];

        #[cfg(feature = "bfi_metadata")]
        {
            let bandwidth_array = Arc::new(UInt16Array::from(bandwidth_vec)) as ArrayRef;
            let nr_index_array = Arc::new(UInt8Array::from(nr_index_vec)) as ArrayRef;
            let nc_index_array = Arc::new(UInt8Array::from(nc_index_vec)) as ArrayRef;
            let codebook_array = Arc::new(UInt8Array::from(codebook_vec)) as ArrayRef;
            let feedback_type_array = Arc::new(UInt8Array::from(feedback_type_vec)) as ArrayRef;
            arrays.push(bandwidth_array);
            arrays.push(nr_index_array);
            arrays.push(nc_index_array);
            arrays.push(codebook_array);
            arrays.push(feedback_type_array);
        }
        arrays.push(bfa_angles_array);

        let schema = Arc::new(create_bfa_schema());
        let batch = RecordBatch::try_new(schema, arrays)?;
        self.write(batch)
    }

    /// Add a batch of BFM data.
    /// For each BfmData record, the feedback_matrix (ndarray of Complex64 with shape (m,n,k))
    /// is converted into two columns:
    /// - "bfm_abs": triple nested lists of Float64 containing the absolute values (flattened row‑major per subcarrier)
    /// - "bfm_phase": triple nested lists of Float64 containing the phase (argument) values.
    pub fn add_bfm_batch(&mut self, data: &[BfmData]) -> Result<(), PersistenceError> {
        let num_records = data.len();
        let mut ts_builder = Float64Builder::new();
        let mut token_builder = UInt8Builder::new();

        #[cfg(feature = "bfi_metadata")]
        let (
            mut bandwidth_vec,
            mut nr_index_vec,
            mut nc_index_vec,
            mut codebook_vec,
            mut feedback_type_vec,
        ) = (
            Vec::with_capacity(num_records),
            Vec::with_capacity(num_records),
            Vec::with_capacity(num_records),
            Vec::with_capacity(num_records),
            Vec::with_capacity(num_records),
        );

        // Create triple-nested ListBuilders for bfm_abs and bfm_phase.
        // Each will build a List<List<List<Float64>>>
        let mut abs_outer =
            ListBuilder::new(ListBuilder::new(ListBuilder::new(Float64Builder::new())));
        let mut phase_outer =
            ListBuilder::new(ListBuilder::new(ListBuilder::new(Float64Builder::new())));

        for d in data {
            ts_builder.append_value(d.timestamp);
            token_builder.append_value(d.token_number);
            #[cfg(feature = "bfi_metadata")]
            {
                bandwidth_vec.push(d.metadata.bandwidth);
                nr_index_vec.push(d.metadata.nr_index);
                nc_index_vec.push(d.metadata.nc_index);
                codebook_vec.push(d.metadata.codebook_info);
                feedback_type_vec.push(d.metadata.feedback_type);
            }

            // Build triple-nested list for absolute values.

            // abs_outer: ListBuilder<ListBuilder<ListBuilder<Float64>>>
            // Get mutable reference to the middle builder for the current record.
            let (m, n, k) = d.feedback_matrix.dim();
            let abs_middle = abs_outer.values();
            let phase_middle = phase_outer.values();

            for antenna in 0..m {
                // For each row, get the inner builder.
                let abs_inner = abs_middle.values();
                let phase_inner = phase_middle.values();

                for core in 0..n {
                    // For each column, get the Float64Builder.
                    let abs_builder = abs_inner.values();
                    let phase_builder = phase_inner.values();

                    for subcarrier in 0..k {
                        abs_builder
                            .append_value(d.feedback_matrix[(antenna, core, subcarrier)].norm());
                        phase_builder
                            .append_value(d.feedback_matrix[(antenna, core, subcarrier)].arg());
                    }
                    abs_inner.append(true);
                    phase_inner.append(true);
                }
                abs_middle.append(true);
                phase_middle.append(true);
            }
            abs_outer.append(true);
            phase_outer.append(true);
        }

        let ts_array = Arc::new(ts_builder.finish()) as ArrayRef;
        let token_array = Arc::new(token_builder.finish()) as ArrayRef;
        let bfm_abs_array = Arc::new(abs_outer.finish()) as ArrayRef;
        let bfm_phase_array = Arc::new(phase_outer.finish()) as ArrayRef;

        let mut arrays = vec![ts_array, token_array];

        #[cfg(feature = "bfi_metadata")]
        {
            let bandwidth_array = Arc::new(UInt16Array::from(bandwidth_vec)) as ArrayRef;
            let nr_index_array = Arc::new(UInt8Array::from(nr_index_vec)) as ArrayRef;
            let nc_index_array = Arc::new(UInt8Array::from(nc_index_vec)) as ArrayRef;
            let codebook_array = Arc::new(UInt8Array::from(codebook_vec)) as ArrayRef;
            let feedback_type_array = Arc::new(UInt8Array::from(feedback_type_vec)) as ArrayRef;
            arrays.push(bandwidth_array);
            arrays.push(nr_index_array);
            arrays.push(nc_index_array);
            arrays.push(codebook_array);
            arrays.push(feedback_type_array);
        }
        arrays.push(bfm_abs_array);
        arrays.push(bfm_phase_array);

        let schema = Arc::new(create_bfm_schema());
        let batch = RecordBatch::try_new(schema, arrays)?;
        self.write(batch)
    }
}
