use beefi_lib::{
    create_live_capture, create_offline_capture, split_bfi_data, BfiData, BfiMetadata, HoneySink,
    StreamBee,
};
use crossbeam_channel::{bounded, Receiver};
use numpy::{PyArray1, PyArray2, PyArray3};
use pyo3::{prelude::*, types::PyList};

#[pyclass(get_all)]
pub struct PyBfiMeta {
    pub bandwidth: u16,
    pub nr_index: u8,
    pub nc_index: u8,
    pub codebook_info: u8,
    pub feedback_type: u8,
}

#[pyclass(get_all)]
pub struct PyBfiData {
    pub timestamp: f64,
    pub token_number: u8,
    pub bfa_angles: Py<PyArray2<u16>>, // No lifetimes, allows direct access from Python
}

#[pyclass]
pub struct Bee {
    bee: StreamBee,              // Internal CaptureBee instance
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
    #[pyo3(signature = (source, queue_size=1000))]
    pub fn new(source: DataSource, queue_size: Option<usize>) -> PyResult<Self> {
        // Set up the capture bee and queue
        let queue_size = queue_size.unwrap_or(1000);
        let (sender, receiver) = bounded(queue_size);

        // Initialize CaptureBee based on the capture source
        let mut bee = match source {
            DataSource::File(file) => {
                let cap = create_offline_capture(file.into());
                StreamBee::from_file_capture(cap)
            }
            DataSource::Live(interface) => {
                let cap = create_live_capture(&interface);
                StreamBee::from_live_capture(cap)
            }
        };

        // Attach the queue to CaptureBee to receive processed data and start receiving
        bee.subscribe_for_honey(HoneySink::Queue(sender));
        bee.start_harvesting(false);

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

    /// Stops the capture process
    pub fn stop(&mut self) {
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
    #[allow(clippy::type_complexity)] // Don't want to wrap and create owned struct
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

        // We put the metadata in a list instead of arrays, since its non-primitive.
        let meta_list: Vec<Py<PyBfiMeta>> = data_batch
            .metadata
            .into_iter()
            .map(|metadata| Py::new(py, PyBfiMeta::from(metadata)))
            .collect::<Result<_, _>>()
            .unwrap();

        (
            PyArray1::from_vec_bound(py, data_batch.timestamps),
            PyArray1::from_vec_bound(py, data_batch.token_numbers),
            PyArray3::from_vec3_bound(py, &padded_bfa_angles).unwrap(),
            PyList::new_bound(py, meta_list),
        )
    }

    m.add_class::<Bee>()?;
    m.add_class::<DataSource>()?;
    m.add_class::<PyBfiData>()?;
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
