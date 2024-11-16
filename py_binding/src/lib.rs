use beefi_lib::{
    create_live_capture, create_offline_capture, split_bfi_data, BfiData, BfiMetadata, CaptureBee,
    ProcessedSink,
};
use crossbeam_channel::{bounded, Receiver};
use numpy::{PyArray1, PyArray2, PyArray3};
use pyo3::{prelude::*, types::PyList};

#[pyclass]
pub struct PyBfiMeta {
    #[pyo3(get)]
    pub bandwidth: u16,
    #[pyo3(get)]
    pub nr_index: u8,
    #[pyo3(get)]
    pub nc_index: u8,
    #[pyo3(get)]
    pub codebook_info: u8,
    #[pyo3(get)]
    pub feedback_type: u8,
}

#[pyclass]
pub struct PyBfiData {
    #[pyo3(get)]
    pub timestamp: f64,
    #[pyo3(get)]
    pub token_number: u8,
    #[pyo3(get)]
    pub bfa_angles: Py<PyArray2<u16>>, // No lifetimes, allows direct access from Python
}

#[pyclass]
pub struct PyBfiDataBatch {}

#[pyclass]
pub struct Bee {
    bee: CaptureBee,             // Internal CaptureBee instance
    receiver: Receiver<BfiData>, // Receiver for BfiData messages from CaptureBee
}

#[pyclass]
#[derive(Debug, Clone)]
pub enum DataSource {
    Live(String),
    File(String),
}

#[pymethods]
impl Bee {
    #[new]
    pub fn new(source: DataSource, queue_size: usize) -> PyResult<Self> {
        // Set up the capture bee and queue
        let (sender, receiver) = bounded(queue_size);

        // Initialize CaptureBee based on the capture source
        let mut bee = match source {
            DataSource::File(file) => {
                let cap = create_offline_capture(file.into());
                CaptureBee::from_file_capture(cap)
            }
            DataSource::Live(interface) => {
                let cap = create_live_capture(&interface);
                CaptureBee::from_live_capture(cap)
            }
        };

        // Attach the queue to CaptureBee to receive processed data
        bee.set_proc_sink(ProcessedSink::Queue(sender));

        // Start a background thread to run CaptureBee
        bee.start(false);

        Ok(Bee { bee, receiver })
    }

    /// Polls the queue for new BfiData and returns it as a `PyBfiData` if available.
    pub fn poll(&self, py: Python) -> PyResult<Option<Py<PyBfiData>>> {
        match self.receiver.try_recv() {
            Ok(bfi_data) => {
                // Convert BfiData to PyBfiData
                let bfa_angles = PyArray2::from_vec2_bound(py, &bfi_data.bfa_angles)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?
                    .unbind(); // Ensures PyArray is safely managed

                let py_bfi_data = Py::new(
                    py,
                    PyBfiData {
                        timestamp: bfi_data.timestamp,
                        token_number: bfi_data.token_number,
                        bfa_angles,
                    },
                )?;

                Ok(Some(py_bfi_data))
            }
            Err(_) => Ok(None), // No data available in the queue
        }
    }

    /// Stops the `Bee` capture process.
    pub fn stop(&self) {
        self.bee.stop();
    }
}

impl Drop for Bee {
    fn drop(&mut self) {
        self.stop()
    }
}

#[pymodule]
fn beefi<'py>(_py: Python<'py>, m: &Bound<'py, PyModule>) -> PyResult<()> {
    /**
     * Extract data from a pcap file
     *
     * \param path: Path to pcap file
     *
     * \returns A tuple of extracted values, each a numpy array
     *          with length equal to the number of packets.
     */
    #[allow(dead_code)]
    #[pyfn(m)]
    fn extract_from_pcap<'py>(
        py: Python<'py>,
        path: &str,
    ) -> (
        Bound<'py, PyArray1<f64>>,
        Bound<'py, PyArray1<u8>>,
        Bound<'py, PyArray3<u16>>,
        Bound<'py, PyList>,
    ) {
        let data = beefi_lib::extract_from_pcap(path.into());
        let data_batch = split_bfi_data(data);

        // Since we are facing different bandwidth causing number of subcarrier
        // to have different length we need to pad the extracted bfi data:
        let padded_bfa_angles = pad_bfa_angles(&data_batch.bfa_angles);
        let py_objects: Vec<Py<PyBfiMeta>> = data_batch
            .metadata
            .into_iter()
            .map(|metadata| Py::new(py, PyBfiMeta::from(metadata)))
            .collect::<Result<_, _>>()
            .unwrap();

        (
            PyArray1::from_vec_bound(py, data_batch.timestamps),
            PyArray1::from_vec_bound(py, data_batch.token_numbers),
            PyArray3::from_vec3_bound(py, &padded_bfa_angles).unwrap(),
            PyList::new_bound(py, py_objects),
        )
    }

    m.add_class::<Bee>()?;
    m.add_class::<PyBfiData>()?;
    m.add_class::<PyBfiDataBatch>()?;
    m.add_class::<PyBfiMeta>()?;
    m.add_class::<DataSource>()?;

    Ok(())
}

// Helper function to pad the bfi data according to the longest number of subcarrier
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

    // Pad the second dimension and inner vectors
    bfa_angles
        .iter()
        .map(|outer| {
            let mut padded_outer = Vec::with_capacity(max_len_subcarrier);

            // Pad inner vectors to max_len_angles
            for inner in outer {
                let mut padded_inner = inner.clone();
                padded_inner.resize(max_len_angles, 0);
                padded_outer.push(padded_inner);
            }

            // Pad the outer vector to max_len_subcarrier with zero-filled vectors
            padded_outer.resize_with(max_len_subcarrier, || vec![0; max_len_angles]);

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
