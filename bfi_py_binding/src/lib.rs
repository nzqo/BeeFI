use bfi_lib::{extract_from_capture, ExtractedBfiData};
use numpy::{PyArray1, PyArray3};
use pyo3::prelude::*;
use pyo3::types::PyList;

#[pymodule]
fn bfi_extract<'py>(_py: Python<'py>, m: &Bound<'py, PyModule>) -> PyResult<()> {
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
        let ExtractedBfiData {
            timestamps,
            token_nums,
            bfa_angles,
            meta_data,
        } = extract_from_capture(path.into());

        // Since we are facing different bandwidth causing number of subcarrier
        // to have different length we need to pad the extracted bfi data:
        let padded_bfa_angles = pad_bfa_angles(&bfa_angles);

        (
            PyArray1::from_vec_bound(py, timestamps),
            PyArray1::from_vec_bound(py, token_nums),
            PyArray3::from_vec3_bound(py, &padded_bfa_angles).unwrap(),
            PyList::new_bound(py, meta_data).into(),
        )
    }

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
