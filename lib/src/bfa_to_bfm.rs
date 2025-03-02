//! Beamforming Feedback Angles (BFA) to Beamforming Feedback Matrix (BFM) conversion.
//!
//! TODO: More references to equations in the standard.
use crate::bfm_data::{BfmData, FeedbackMatrix};
use crate::extraction::{get_angle_bit_sizes, Angles, ExtractionConfig};
use crate::{errors::BfmConversionError, BfaData};

use ndarray::Array2;
use num_complex::Complex64;

/// Transform BFI angles to Beamforming Feedback Matrix (BFM).
///
/// Metadata is maintained, this just receovers the matrices from the angles.
pub fn to_bfm(bfa: &BfaData) -> Result<BfmData, BfmConversionError> {
    // Retrieve pattern and bit-size parameters.
    let pattern = ExtractionConfig::get_pattern(bfa.metadata.nr_index, bfa.metadata.nc_index)?;

    // Compute the bit-size constants once.
    let bitsizes = get_angle_bit_sizes(bfa.metadata.codebook_info, bfa.metadata.feedback_type)?;
    let const1_phi = std::f64::consts::PI / ((1u64 << (bitsizes.phi_bit - 1)) as f64);
    let const2_phi = std::f64::consts::PI / ((1u64 << bitsizes.phi_bit) as f64);
    let const1_psi = std::f64::consts::PI / ((1u64 << (bitsizes.psi_bit + 1)) as f64);
    let const2_psi = std::f64::consts::PI / ((1u64 << (bitsizes.psi_bit + 2)) as f64);

    let num_receive = bfa.metadata.nr_index as usize + 1;
    let num_spatial = bfa.metadata.nc_index as usize + 1;
    let n_subcarriers = bfa.bfa_angles.len();

    // Preallocate final matrix.
    let mut final_result = FeedbackMatrix::zeros((num_receive, num_spatial, n_subcarriers));

    // Process each subcarrier.
    for (sub_idx, inner_angles) in bfa.bfa_angles.iter().enumerate() {
        let acc = pattern.iter().enumerate().fold(
            Array2::<Complex64>::eye(num_receive),
            |mut acc, (i, &(ref kind, nr, nc))| {
                // 1. Compute quantized value on the fly.
                let angle = inner_angles[i] as f64;
                let quantized = match kind {
                    Angles::Phi => angle * const1_phi + const2_phi,
                    Angles::Psi => angle * const1_psi + const2_psi,
                };

                // 2. Figure out which angle is next in the multiplication
                let row = nr - 1;
                let col = nc - 1;
                match kind {
                    // 3. Multiply by either (part of) D or givens rotation
                    Angles::Phi => apply_d_inplace(&mut acc, row, quantized),
                    Angles::Psi => apply_givens_inplace(&mut acc, row, col, quantized),
                };
                acc
            },
        );

        // Slice last num_spatial rows (application of non-square identity) and
        // put the matrix into the subcarrier dimension it belongs to.
        final_result
            .slice_mut(ndarray::s![.., .., sub_idx])
            .assign(&acc.slice(ndarray::s![.., 0..num_spatial]));
    }

    Ok(BfmData {
        metadata: bfa.metadata.clone(),
        timestamp: bfa.timestamp,
        token_number: bfa.token_number,
        feedback_matrix: final_result,
    })
}

/// In-place right-multiplication by the n-dimensional D_i(phi) matrix.
///
/// This function performs the equivalent of multiplying an input matrix `acc` on the right by a
/// D-matrix that is identity except that its diagonal element at the given position `pos`
/// is replaced by exp(i * phase).
///
/// # Parameters
/// * `acc` - A mutable reference to the matrix (of dimension n x n) to be updated.
/// * `pos` - The subindex `i` corresponding to the column to scale.
/// * `phase` - The Phi value used to compute exp(i * phase).
///
/// The matrix `acc` is updated in place.
fn apply_d_inplace(acc: &mut Array2<Complex64>, pos: usize, phase: f64) {
    let scale = (Complex64::new(0.0, 1.0) * phase).exp();
    for r in 0..acc.nrows() {
        acc[(r, pos)] *= scale;
    }
}

/// In-place right-multiplication by the TRANSPOSED Givens rotation G_{r,c}(psi) matrix.
///
/// This function applies a rotation to the matrix `acc` that only affects the two columns
/// corresponding to `row_idx` and `col_idx`. It is equivalent to multiplying by a matrix where:
///   - The entries at (row_idx, row_idx) and (col_idx, col_idx) are replaced by cos(phase),
///   - The entry at (row_idx, col_idx) is set to sin(phase),
///   - The entry at (col_idx, row_idx) is set to -sin(phase),
///
/// while all other entries remain identical to the identity matrix.
///
/// # Parameters
/// * `acc` - A mutable reference to the matrix (of dimension n x n) to be updated.
/// * `row_idx` - Row index used to specify the rotation axis.
/// * `col_idx` - Column index used to specify the rotation axis.
/// * `phase` - The Psi value used to evaluate the rotation.
///
/// The matrix `acc` is modified in place.
fn apply_givens_inplace(acc: &mut Array2<Complex64>, row_idx: usize, col_idx: usize, phase: f64) {
    let cos_val = phase.cos();
    let sin_val = phase.sin();
    for r in 0..acc.nrows() {
        let temp_i = acc[(r, row_idx)];
        let temp_j = acc[(r, col_idx)];
        acc[(r, row_idx)] = cos_val * temp_i - sin_val * temp_j;
        acc[(r, col_idx)] = sin_val * temp_i + cos_val * temp_j;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::{array, stack, Array2, Array3};
    use num_complex::Complex64;
    use std::f64::consts::PI;

    /// Compares two Complex64 numbers within a given tolerance.
    /// This helper is used to assert that two complex numbers are approximately equal.
    fn approx_eq_complex(a: Complex64, b: Complex64, epsilon: f64) {
        assert!(
            (a.re - b.re).abs() < epsilon,
            "Real parts differ: {} vs {}",
            a.re,
            b.re
        );
        assert!(
            (a.im - b.im).abs() < epsilon,
            "Imaginary parts differ: {} vs {}",
            a.im,
            b.im
        );
    }

    /// Asserts that two 3D arrays of Complex64 are approximately equal.
    /// Iterates over each element and uses `approx_eq_complex` for comparison.
    fn assert_array3_approx_eq(
        expected: &Array3<Complex64>,
        actual: &Array3<Complex64>,
        epsilon: f64,
    ) {
        assert_eq!(
            expected.dim(),
            actual.dim(),
            "Dimension mismatch: expected {:?}, got {:?}",
            expected.dim(),
            actual.dim()
        );
        for ((r, c, s), &val) in actual.indexed_iter() {
            approx_eq_complex(val, expected[(r, c, s)], epsilon);
        }
    }

    /// Test for `apply_d_inplace`:
    ///
    /// Verifies that applying `apply_d_inplace` to an identity matrix multiplies the specified
    /// diagonal element by exp(i * phase). For example, with phase = PI/2, exp(i * PI/2) should equal i.
    #[test]
    fn test_apply_d_inplace() {
        let n = 3;
        let pos = 1;
        let phase = PI / 2.0; // Expected exp(i*PI/2) = i.
        let mut result = Array2::<Complex64>::eye(n);
        apply_d_inplace(&mut result, pos, phase);

        // Build the expected matrix: identity with expected scaling at index (pos, pos).
        let mut expected = Array2::<Complex64>::eye(n);
        expected[(pos, pos)] = (Complex64::new(0.0, 1.0) * phase).exp();

        for i in 0..n {
            for j in 0..n {
                approx_eq_complex(result[(i, j)], expected[(i, j)], 1e-6);
            }
        }
    }

    /// Test for `apply_givens_inplace`:
    ///
    /// Checks that applying `apply_givens_inplace` to an identity matrix rotates the two specified columns such that:
    ///   - The new column at `row_idx` becomes: cos(phase) * old_col[row_idx] - sin(phase) * old_col[col_idx],
    ///   - The new column at `col_idx` becomes: sin(phase) * old_col[row_idx] + cos(phase) * old_col[col_idx].
    #[test]
    fn test_apply_givens_inplace() {
        let n = 4;
        let row_idx = 1;
        let col_idx = 2;
        let phase = PI / 6.0; // cos(PI/6) ≈ 0.8660254, sin(PI/6) = 0.5.
        let mut result = Array2::<Complex64>::eye(n);
        apply_givens_inplace(&mut result, row_idx, col_idx, phase);

        let cos_val = phase.cos();
        let sin_val = phase.sin();

        // Build the expected matrix: starting from identity, only columns `row_idx` and `col_idx`
        // are rotated. For each row:
        // new value at (r, row_idx) = cos(phase) * orig(row_idx) - sin(phase) * orig(col_idx)
        // new value at (r, col_idx) = sin(phase) * orig(row_idx) + cos(phase) * orig(col_idx)
        // Since the original matrix is identity, orig(row_idx) is 1 if r == row_idx and 0 otherwise,
        // and similarly for orig(col_idx).
        let mut expected = Array2::<Complex64>::eye(n);
        for r in 0..n {
            let orig_i = if r == row_idx { 1.0 } else { 0.0 };
            let orig_j = if r == col_idx { 1.0 } else { 0.0 };
            expected[(r, row_idx)] = Complex64::new(cos_val * orig_i - sin_val * orig_j, 0.0);
            expected[(r, col_idx)] = Complex64::new(sin_val * orig_i + cos_val * orig_j, 0.0);
        }

        for i in 0..n {
            for j in 0..n {
                approx_eq_complex(result[(i, j)], expected[(i, j)], 1e-6);
            }
        }
    }

    /// Test for the full beamforming conversion (`to_bfm`) for Frame 1.
    ///
    /// This test verifies that for a configuration with 4 receive antennas and 2 spatial streams
    /// (indicated by nr_index=3 and nc_index=1) and 3 subcarriers, the computed beamforming feedback
    /// matrix matches the known hardcoded expected values.
    #[test]
    fn test_to_bfm_frame1() {
        let epsilon = 1e-6;
        let metadata = crate::BfiMetadata {
            bandwidth: 20,
            nr_index: 3, // 4 receive antennas.
            nc_index: 1, // 2 spatial streams.
            codebook_info: 1,
            feedback_type: 0,
        };
        let bfa_angles = vec![
            vec![18, 33, 43, 15, 12, 9, 31, 15, 12, 1],
            vec![19, 33, 43, 14, 12, 9, 31, 16, 11, 1],
            vec![26, 34, 43, 15, 12, 9, 25, 16, 12, 1],
        ];
        let bfi = BfaData {
            metadata,
            timestamp: 0.0,
            token_number: 0,
            bfa_angles,
        };
        let result = to_bfm(&bfi).expect("Conversion failed for frame1");

        // Hardcoded expected matrices for each subcarrier.
        let expected_sub0 = array![
            [
                Complex64::new(-0.0023926619729460947, 0.009552042034917656),
                Complex64::new(-0.022259733555152955, 0.332951183878653)
            ],
            [
                Complex64::new(-0.19827382117422365, -0.029411143066880127),
                Complex64::new(-0.03034882774477342, 0.8790579124979945)
            ],
            [
                Complex64::new(-0.23980588003868333, -0.5070269336374148),
                Complex64::new(0.3241586226783822, -0.047595272953470685)
            ],
            [
                Complex64::new(0.8032075314806448, 0.0),
                Complex64::new(0.08740724158090377, 0.0)
            ]
        ];
        let expected_sub1 = array![
            [
                Complex64::new(-0.009920265069631532, 0.02772528352309735),
                Complex64::new(-0.005344341128167007, 0.44212631275685693)
            ],
            [
                Complex64::new(-0.19636433588881996, -0.02912789768137983),
                Complex64::new(-0.061868399045409694, 0.8286636523397674)
            ],
            [
                Complex64::new(-0.23980588003868333, -0.5070269336374148),
                Complex64::new(0.32576134847561194, -0.014971039876228665)
            ],
            [
                Complex64::new(0.8032075314806448, 0.0),
                Complex64::new(0.08740724158090377, 0.0)
            ]
        ];
        let expected_sub2 = array![
            [
                Complex64::new(-0.008446181203226587, 0.005062446190911855),
                Complex64::new(-0.10541891583486544, 0.34445171127342417)
            ],
            [
                Complex64::new(-0.1944362823942826, -0.048703753327842075),
                Complex64::new(-0.2006722704845437, 0.8415181571491093)
            ],
            [
                Complex64::new(-0.23980588003868333, -0.5070269336374148),
                Complex64::new(0.3373235943827392, -0.01976027894245358)
            ],
            [
                Complex64::new(0.8032075314806448, 0.0),
                Complex64::new(0.08740724158090377, 0.0)
            ]
        ];
        let expected = stack!(
            ndarray::Axis(2),
            expected_sub0,
            expected_sub1,
            expected_sub2
        );
        assert_array3_approx_eq(&expected, &result.feedback_matrix, epsilon);
    }

    /// Test for the full beamforming conversion (`to_bfm`) for Frame 2.
    ///
    /// Similar to Frame 1, but for a frame with 2 subcarriers. This test checks that the output
    /// matches the hardcoded expected values for each subcarrier.
    #[test]
    fn test_to_bfm_frame2() {
        let epsilon = 1e-6;
        let metadata = crate::BfiMetadata {
            bandwidth: 20,
            nr_index: 3,
            nc_index: 1,
            codebook_info: 1,
            feedback_type: 0,
        };
        let bfa_angles = vec![
            vec![11, 33, 43, 13, 13, 9, 46, 23, 10, 2],
            vec![14, 34, 44, 14, 13, 9, 44, 23, 10, 1],
        ];
        let bfi = BfaData {
            metadata,
            timestamp: 0.0,
            token_number: 0,
            bfa_angles,
        };
        let result = to_bfm(&bfi).expect("Conversion failed for frame2");

        let expected_sub0 = array![
            [
                Complex64::new(0.015036988795258143, 0.031793041600022685),
                Complex64::new(-0.2194879133817079, 0.3152680229308265)
            ],
            [
                Complex64::new(-0.13888567818226813, -0.02060174422809983),
                Complex64::new(-0.5596891331514844, 0.6245901378093384)
            ],
            [
                Complex64::new(-0.24706140364458362, -0.5223674494130918),
                Complex64::new(0.27440253306071005, 0.22982393572983456)
            ],
            [
                Complex64::new(0.8032075314806448, 0.0),
                Complex64::new(0.14474312417382065, 0.0)
            ]
        ];
        let expected_sub1 = array![
            [
                Complex64::new(0.0031162951659979613, 0.02100835554280006),
                Complex64::new(-0.3438432894013426, 0.3000640069749745)
            ],
            [
                Complex64::new(-0.13888567818226813, -0.03478905134198425),
                Complex64::new(-0.6421164888100508, 0.5334369540853382)
            ],
            [
                Complex64::new(-0.1946707718645663, -0.5440683596376699),
                Complex64::new(0.22897695510627752, 0.18653241813601995)
            ],
            [
                Complex64::new(0.8032075314806448, 0.0),
                Complex64::new(0.08740724158090377, 0.0)
            ]
        ];
        let expected = stack!(ndarray::Axis(2), expected_sub0, expected_sub1);
        assert_array3_approx_eq(&expected, &result.feedback_matrix, epsilon);
    }
}
