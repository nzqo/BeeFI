use beefi_lib::{
    create_live_capture, create_offline_capture, split_bfi_data, BfaData, BfiMetadata,
    FeedbackMatrix, NectarSink, StreamBee,
};
use crossbeam_channel::{bounded, Receiver};
use numpy::{Complex64, PyArray1, PyArray2, PyArray3, PyArray4};
use pyo3::{prelude::*, types::PyList};

/**************************************************************************
 * STRUCT TYPEDEFS
 *************************************************************************/

/// BFI metadata
#[pyclass(get_all)]
#[derive(Clone, Copy)]
pub struct PyBfiMeta {
    /// Channel bandwidth
    pub bandwidth: u16,
    /// Index of the receive antennas used in the sounding procedure
    pub nr_index: u8,
    /// Index of columns (streams) used in the sounding procedure
    pub nc_index: u8,
    /// Codebook size
    pub codebook_info: u8,
    /// Feedback type (SU/MU/CQI)
    pub feedback_type: u8,
}

/// BFA data (angles) extracted from a single packet
#[pyclass(get_all)]
pub struct PyBfaData {
    /// Metadata of the extracted BFI data
    pub metadata: Py<PyBfiMeta>,
    /// Timestamp of the associated pcap capture
    pub timestamp: f64,
    /// Token number to identify the NDP packet used in the procedure
    pub token_number: u8,
    /// Extracted BFA angles from the compressed beamforming feedback information
    pub bfa_angles: Vec<Vec<u16>>,
}

#[pymethods]
impl PyBfaData {
    /// When Python accesses `bfa_angles`, convert the native data to a NumPy array.
    #[getter]
    pub fn bfa_angles(&self, py: Python) -> PyResult<Py<PyArray2<u16>>> {
        PyArray2::from_vec2(py, &self.bfa_angles)
            .map(|bound| bound.unbind())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

/// BFM data (feedback matrices) extracted from a single packet
#[pyclass()]
pub struct PyBfmData {
    /// Metadata of the extracted BFI data
    #[pyo3(get)]
    pub metadata: Py<PyBfiMeta>,
    /// Timestamp of the associated pcap capture
    #[pyo3(get)]
    pub timestamp: f64,
    /// Token number to identify the NDP packet used in the procedure
    #[pyo3(get)]
    pub token_number: u8,
    /// Extracted Beamforming Feedback Matrices stored as an ndarray of 3 dimensions
    pub bfm: FeedbackMatrix,
}

#[pymethods]
impl PyBfmData {
    /// Custom getter for `bfm` that converts the inner ndarray into a NumPy array.
    #[getter]
    pub fn bfm(&self, py: Python<'_>) -> PyResult<Py<PyArray3<Complex64>>> {
        let array = numpy::PyArray3::from_array(py, &self.bfm);
        Ok(array.to_owned().into())
    }
}

/// BFA batch data extracted from a pcap file.
#[pyclass()]
pub struct PyBfaBatch {
    /// A vector of metadata objects.
    pub metadata: Vec<PyBfiMeta>,
    /// A vector of timestamps.
    pub timestamps: Vec<f64>,
    /// A vector of token numbers.
    pub token_numbers: Vec<u8>,
    /// 3D vector representing the extracted BFA angles.
    pub bfa_angles: Vec<Vec<Vec<u16>>>,
}

#[pymethods]
impl PyBfaBatch {
    /// Getter for metadata as a Python list.
    #[getter]
    pub fn metadata(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let list = PyList::empty(py);
        for meta in &self.metadata {
            list.append(Py::new(py, *meta)?)?;
        }
        Ok(list.into())
    }

    /// Getter for timestamps as a NumPy array.
    #[getter]
    pub fn timestamps(&self, py: Python<'_>) -> Py<PyArray1<f64>> {
        // from_vec returns a &PyArray1, so we convert it to an owned PyArray
        numpy::PyArray1::from_vec(py, self.timestamps.clone())
            .to_owned()
            .into()
    }

    /// Getter for token_numbers as a NumPy array.
    #[getter]
    pub fn token_numbers(&self, py: Python<'_>) -> Py<PyArray1<u8>> {
        numpy::PyArray1::from_vec(py, self.token_numbers.clone())
            .to_owned()
            .into()
    }

    /// Getter for bfa_angles as a 3D NumPy array.
    #[getter]
    pub fn bfa_angles(&self, py: Python<'_>) -> PyResult<Py<PyArray3<u16>>> {
        numpy::PyArray3::from_vec3(py, &self.bfa_angles)
            .map(|arr| arr.to_owned().into())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

/// BFM batch data extracted from a pcap file.
#[pyclass()]
pub struct PyBfmBatch {
    /// A vector of metadata objects.
    pub metadata: Vec<PyBfiMeta>,
    /// A vector of timestamps.
    pub timestamps: Vec<f64>,
    /// A vector of token numbers.
    pub token_numbers: Vec<u8>,
    /// Vector of Beamforming Feedback Matrices
    pub bfm: Vec<FeedbackMatrix>,
}

/// Batch of BFM data
#[pymethods]
impl PyBfmBatch {
    /// Getter for metadata as a Python list.
    #[getter]
    pub fn metadata(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let list = PyList::empty(py);
        for meta in &self.metadata {
            list.append(Py::new(py, *meta)?)?;
        }
        Ok(list.into())
    }

    /// Getter for timestamps as a NumPy array.
    #[getter]
    pub fn timestamps(&self, py: Python<'_>) -> Py<PyArray1<f64>> {
        // from_vec returns a &PyArray1, so we convert it to an owned PyArray
        numpy::PyArray1::from_vec(py, self.timestamps.clone())
            .to_owned()
            .into()
    }

    /// Getter for token_numbers as a NumPy array.
    #[getter]
    pub fn token_numbers(&self, py: Python<'_>) -> Py<PyArray1<u8>> {
        numpy::PyArray1::from_vec(py, self.token_numbers.clone())
            .to_owned()
            .into()
    }

    /// Custom getter that converts the inner bfm Vec into a NumPy array.
    #[getter]
    pub fn bfm(&self, py: Python<'_>) -> PyResult<Py<PyArray4<Complex64>>> {
        use ndarray::Axis;
        // Each element in self.bfm is an Array3<Complex64>.
        // We stack them along a new axis (axis 0) to get an Array4.
        let views: Vec<_> = self.bfm.iter().map(|m| m.view()).collect();
        let stacked = ndarray::stack(Axis(0), &views)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(numpy::PyArray4::from_array(py, &stacked).to_owned().into())
    }
}

/**************************************************************************
 * CORE CLASS
 *************************************************************************/

/// Capture bee
///
/// A little worker to read and process packets in a streaming fashion.
#[pyclass(unsendable)]
pub struct Bee {
    bee: StreamBee,              // Internal CaptureBee instance
    receiver: Receiver<BfaData>, // Receiver for BfaData messages from CaptureBee
}

/// Specifies the source of packet data
#[pyclass]
#[derive(Debug, Clone)]
pub enum DataSource {
    /// Get packets live from an interface
    Live {
        /// Name of the network interface to capture packets on
        interface: String,
    },
    /// Get packets from an offline pcap file
    File {
        /// Path to the pcap file on disk.
        file_path: String,
    },
}

#[pymethods]
impl Bee {
    /// Create a new streaming Bee
    ///
    /// A streaming bee is used to read packets from a pcap source, either an
    /// interface of a captured pcap file. Packets are processed to extract
    /// the BFI, which is exposed via a polling API.
    ///
    /// # Arguments
    /// * `source` - The pcap source to read packets from
    /// * `queue_size` - Size of internal queue to buffer collected data
    /// * `pcap_buffer` - Whether to buffer pcap packets internally for batch processing
    /// * `pcap_snaplen` - Snapshot length of pcap packets. Must exceed BFI packet length.
    /// * `pcap_bufsize` - Size of internal pcap packet buffer.
    #[new]
    #[pyo3(signature = (source, queue_size=1000, pcap_buffer=false, pcap_snaplen=4096, pcap_bufsize=1_000_000))]
    pub fn new(
        source: DataSource,
        queue_size: Option<usize>,
        pcap_buffer: Option<bool>,
        pcap_snaplen: Option<i32>,
        pcap_bufsize: Option<i32>,
    ) -> PyResult<Self> {
        // Set up the capture bee and queue
        let queue_size = queue_size.unwrap_or(1000);
        let (sender, receiver) = bounded(queue_size);

        // Initialize CaptureBee based on the capture source
        let mut bee = match source {
            DataSource::File { file_path } => {
                let cap = create_offline_capture(file_path.into());
                StreamBee::from_file_capture(cap)
            }
            DataSource::Live { interface } => {
                let buffered = pcap_buffer.unwrap_or(false);
                let cap = create_live_capture(&interface, buffered, pcap_snaplen, pcap_bufsize);
                StreamBee::from_live_capture(cap)
            }
        };

        // Attach the queue to CaptureBee to receive processed data and start receiving
        bee.subscribe_for_nectar(NectarSink::Queue(sender));
        bee.start_harvesting(false);

        Ok(Bee { bee, receiver })
    }

    /// Polls the queue for new  and returns it if available, else None.
    ///
    /// This function is nonblocking and will immediately return None if no data
    /// is available.
    ///
    /// Note that if the internal queue is full, the writer thread collecting and
    /// processing data is blocked. If not polled sufficiently often, the writer
    /// will be dropping messages. Callers must make sure to poll frequently
    /// enough.
    pub fn poll(&self, py: Python) -> PyResult<Option<Py<PyBfaData>>> {
        match self.receiver.try_recv() {
            Ok(bfi_data) => {
                let py_bfi_data = Py::new(
                    py,
                    PyBfaData {
                        metadata: Py::new(py, PyBfiMeta::from(bfi_data.metadata))?,
                        timestamp: bfi_data.timestamp,
                        token_number: bfi_data.token_number,
                        bfa_angles: bfi_data.bfa_angles,
                    },
                )?;

                Ok(Some(py_bfi_data))
            }
            Err(_) => Ok(None), // No data available in the queue
        }
    }

    /// Stops the capture process
    ///
    /// This will exit all background threads and wrap up file usage.
    /// Note that this is alternatively also done on destruction, but
    /// doing it manually is just cleaner.
    pub fn stop(&mut self) {
        self.bee.stop();
    }
}

impl Drop for Bee {
    fn drop(&mut self) {
        self.bee.stop()
    }
}

/**************************************************************************
 * MODULE AND SINGLE FUNCTIONS
 *************************************************************************/
#[pymodule]
fn beefi<'py>(_py: Python<'py>, m: &Bound<'py, PyModule>) -> PyResult<()> {
    /**
     * Extract all data from a pcap file in a single batch.
     *
     * Since the data is returned as a single batch, this function might pad
     * the BFA angles in case different dimensions are founds to homogenize
     * the data.
     *
     * # Parameters
     * * `path` - Path to pcap file to extract data from
     */
    #[allow(dead_code)]
    #[allow(clippy::type_complexity)] // Don't want to wrap and create owned struct
    #[pyfn(m)]
    fn extract_from_pcap(_py: Python<'_>, path: &str) -> PyResult<PyBfaBatch> {
        let data = beefi_lib::extract_from_pcap(path.into());
        let data_batch = split_bfi_data(data);

        // Since we are facing different bandwidth causing number of subcarrier
        // to have different length we need to pad the extracted bfi data:
        let padded_bfa_angles = pad_bfa_angles(&data_batch.bfa_angles);

        // We put the metadata in a list instead of arrays, since its non-primitive.

        let meta_list: Vec<PyBfiMeta> = data_batch
            .metadata
            .into_iter()
            .map(PyBfiMeta::from)
            .collect::<Vec<PyBfiMeta>>();

        Ok(PyBfaBatch {
            timestamps: data_batch.timestamps,
            token_numbers: data_batch.token_numbers,
            bfa_angles: padded_bfa_angles,
            metadata: meta_list,
        })
    }

    /**
     * Convert BFA to BFM.
     *
     * # Parameters
     * * `bfa` - Beamforming Feedback Angle Data
     *
     * # Returns
     * Beamforming feedback matrix data
     */
    #[allow(dead_code)]
    #[allow(clippy::type_complexity)] // Don't want to wrap and create owned struct
    #[pyfn(m)]
    fn bfa_to_bfm(py: Python<'_>, bfa: &PyBfaData) -> PyResult<PyBfmData> {
        // --- Step 1. Convert PyBfaData (Python side) to internal BfaData ---
        // Borrow the inner metadata from the Py<> wrapper.
        let meta_py: &PyBfiMeta = &bfa.metadata.borrow(py);
        let internal_metadata = BfiMetadata {
            bandwidth: meta_py.bandwidth,
            nr_index: meta_py.nr_index,
            nc_index: meta_py.nc_index,
            codebook_info: meta_py.codebook_info,
            feedback_type: meta_py.feedback_type,
        };

        // Construct the internal BfaData
        let bfa_internal = beefi_lib::BfaData {
            metadata: internal_metadata,
            timestamp: bfa.timestamp,
            token_number: bfa.token_number,
            bfa_angles: bfa.bfa_angles.clone(),
        };

        // --- Step 2. Convert BfaData to BfmData using your conversion function ---
        let bfm_internal = beefi_lib::to_bfm(&bfa_internal).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Conversion failed: {:?}", e))
        })?;

        // --- Step 3. Convert internal BfmData to PyBfmData for Python ---
        // Convert the metadata back into a PyBfiMeta.
        let py_meta = Py::new(py, PyBfiMeta::from(bfm_internal.metadata))?;

        // Create and return the PyBfmData instance.
        Ok(PyBfmData {
            metadata: py_meta,
            timestamp: bfm_internal.timestamp,
            token_number: bfm_internal.token_number,
            bfm: bfm_internal.feedback_matrix,
        })
    }

    /**
     * Convert a batch of Feedback Angles to a batch of Feedback matrices.
     *
     * # Parameters
     * * `bfa_batch` - Batch to process
     *
     * # Returns
     * Batch of BFM data
     */
    #[pyfn(m)]
    fn bfa_to_bfm_batch(_py: Python<'_>, bfa_batch: &PyBfaBatch) -> PyResult<PyBfmBatch> {
        let n = bfa_batch.metadata.len();
        if n != bfa_batch.timestamps.len()
            || n != bfa_batch.token_numbers.len()
            || n != bfa_batch.bfa_angles.len()
        {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Input batch fields have mismatched lengths",
            ));
        }

        let mut out_metadata = Vec::with_capacity(n);
        let mut out_timestamps = Vec::with_capacity(n);
        let mut out_token_numbers = Vec::with_capacity(n);
        let mut out_bfm = Vec::with_capacity(n);

        for i in 0..n {
            // Step 1: Convert PyBfiMeta (from PyBfaBatch) into internal BfiMetadata.
            let meta_py: &PyBfiMeta = &bfa_batch.metadata[i];
            let internal_metadata = beefi_lib::BfiMetadata {
                bandwidth: meta_py.bandwidth,
                nr_index: meta_py.nr_index,
                nc_index: meta_py.nc_index,
                codebook_info: meta_py.codebook_info,
                feedback_type: meta_py.feedback_type,
            };

            // Construct internal BfaData from the batch fields.
            let bfa_internal = beefi_lib::BfaData {
                metadata: internal_metadata,
                timestamp: bfa_batch.timestamps[i],
                token_number: bfa_batch.token_numbers[i],
                bfa_angles: bfa_batch.bfa_angles[i].clone(),
            };

            // Step 2: Convert internal BfaData to internal BfmData.
            let bfm_internal = beefi_lib::to_bfm(&bfa_internal).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Conversion failed: {:?}",
                    e
                ))
            })?;

            // Step 3: Convert internal BfmData back to PyBfmBatch fields.
            // Create a new Python object for the metadata.
            let py_meta: PyBfiMeta = PyBfiMeta::from(bfm_internal.metadata);
            out_metadata.push(py_meta);
            out_timestamps.push(bfm_internal.timestamp);
            out_token_numbers.push(bfm_internal.token_number);
            out_bfm.push(bfm_internal.feedback_matrix);
        }

        Ok(PyBfmBatch {
            metadata: out_metadata,
            timestamps: out_timestamps,
            token_numbers: out_token_numbers,
            bfm: out_bfm,
        })
    }

    m.add_class::<Bee>()?;
    m.add_class::<DataSource>()?;
    m.add_class::<PyBfaData>()?;
    m.add_class::<PyBfiMeta>()?;

    Ok(())
}

/// Helper function to pad the bfi data according to the longest number of subcarrier
fn pad_bfa_angles(bfa_angles: &[Vec<Vec<u16>>]) -> Vec<Vec<Vec<u16>>> {
    // Get the maximum length in both the second and third dimensions
    // (determining the number of subcarrier and number of angels respectively)
    let max_len_subcarrier = bfa_angles
        .iter()
        .map(|outer| outer.len())
        .max()
        .unwrap_or(0);

    // Find the maximum length in the third dimension (inner vector lengths)
    let max_len_angles = bfa_angles
        .iter()
        .flat_map(|outer| outer.iter().map(|inner| inner.len()))
        .max()
        .unwrap_or(0);

    // Create a zero-filled template for inner padding
    let zero_padded_inner = vec![0; max_len_angles];

    // Pad each outer vector
    bfa_angles
        .iter()
        .map(|outer| {
            // Create a vector with padded inner vectors
            let mut padded_outer: Vec<Vec<u16>> = outer
                .iter()
                .map(|inner| {
                    // Create a new inner vector, padded if necessary
                    let mut padded_inner = inner.clone();
                    padded_inner.resize(max_len_angles, 0);
                    padded_inner
                })
                .collect();

            // Add zero-filled vectors if needed to reach `max_len_subcarrier`
            padded_outer.resize_with(max_len_subcarrier, || zero_padded_inner.clone());

            padded_outer
        })
        .collect()
}

impl From<BfiMetadata> for PyBfiMeta {
    fn from(metadata: BfiMetadata) -> Self {
        PyBfiMeta {
            bandwidth: metadata.bandwidth,
            nr_index: metadata.nr_index,
            nc_index: metadata.nc_index,
            codebook_info: metadata.codebook_info,
            feedback_type: metadata.feedback_type,
        }
    }
}
