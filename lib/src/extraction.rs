//! Extraction of BFA angles from WiFi packet bytestream payloads.
//!
//! At the end of a beamforming sensing procedure, the feedback matrix is sent
//! unencrypted but compressed in a WiFi packet. In this module, we handle the
//! decompression to obtain the original BFA angles, which parametrize the BFI.
use crate::errors::BfaExtractionError;
use crate::he_mimo_ctrl::Bandwidth;
use crate::he_mimo_ctrl::HeMimoControl;

/// Config containing all required parameters to extract the original Phi
/// and Psi angles from the compressed beamforming feedback information.
#[rustfmt::skip]
pub struct ExtractionConfig {
	pub bitfield_pattern : Vec<u8>, // Length of bitfields per subcarrier-chunk
	pub num_subcarrier   : usize,   // Number of subcarriers
}

/// Compressed Feedback contains two types of angles
enum Angles {
    Phi,
    Psi,
}

use Angles::{Phi, Psi};

/// Bit-sizes of the individual angles in the compression
///
/// Phi and Psi are encoded in a variable number of bits, depending on the
/// HE MIMO Control configuration. This struct contains these bit sizes.
struct CompressedAngleBitSizes {
    phi_bit: u8,
    psi_bit: u8,
}

/// Possible patterns of Phi and Psi angles
/// 
/// For different configurations, the exact parametrization differs, requiring
/// different numbers of Phi and Psi angles. This array lists all the patterns
/// of Phi/Psi that may occur.
#[rustfmt::skip]
const ANGLE_PATTERNS: &[&[Angles]] = &[                            // (nr_index, nc_index):
    &[Phi, Psi],                                                   // (1, 0) | (1, 2)
    &[Phi, Phi, Psi, Psi],                                         // (2, 0)
    &[Phi, Phi, Psi, Psi, Phi, Psi],                               // (2, 1) | (2, 2)
    &[Phi, Phi, Phi, Psi, Psi, Psi],                               // (3, 0)
    &[Phi, Phi, Phi, Psi, Psi, Psi, Phi, Phi, Psi, Psi],           // (3, 1)
    &[Phi, Phi, Phi, Psi, Psi, Psi, Phi, Phi, Psi, Psi, Phi, Psi]  // (3, 2) | (3, 3)
];

impl ExtractionConfig {
    /// Find the Phi/Psi angle pattern from a configuration.
    ///
    /// # Parameters
    /// * `nr_index` - Index for number of receive chains
    /// * `nc_index` - Index for number of columns (spatial streams)
    fn get_pattern(nr_index: u8, nc_index: u8) -> &'static [Angles] {
        match (nr_index, nc_index) {
            (1, 0) | (1, 2) => ANGLE_PATTERNS[0],
            (2, 0) => ANGLE_PATTERNS[1],
            (2, 1) | (2, 2) => ANGLE_PATTERNS[2],
            (3, 0) => ANGLE_PATTERNS[3],
            (3, 1) => ANGLE_PATTERNS[4],
            (3, 2) | (3, 3) => ANGLE_PATTERNS[5],
            _ => panic!("Invalid nr_index or nc_index"),
        }
    }

    /// Get an extraction configuration from the HeMimoControl header specification
    /// The extraction configuration specifies how to extract the compressed angles
    /// from the payload.
    ///
    /// # Parameters
    /// * `mimo_ctrl` - The MIMO control header
    pub fn from_he_mimo_ctrl(mimo_ctrl: &HeMimoControl) -> Self {
        #[rustfmt::skip]
        let phi_psi = match (
            mimo_ctrl.codebook_info().value(),
            mimo_ctrl.feedback_type().value(),
        ) {
            (0, 0) => CompressedAngleBitSizes { phi_bit: 4, psi_bit: 2 },
            (0, 1) => CompressedAngleBitSizes { phi_bit: 7, psi_bit: 5 },
            (1, 0) => CompressedAngleBitSizes { phi_bit: 6, psi_bit: 4 },
            (1, 1) => CompressedAngleBitSizes { phi_bit: 9, psi_bit: 7 },
            _ => panic!("Invalid codebook or feedback type, {}", mimo_ctrl.codebook_info()),
        };

        let nr_index = mimo_ctrl.nr_index().value();
        let nc_index = mimo_ctrl.nc_index().value();

        let bitfield_pattern: Vec<u8> = Self::get_pattern(nr_index, nc_index)
            .iter()
            .map(|pattern| match pattern {
                Angles::Phi => phi_psi.phi_bit,
                Angles::Psi => phi_psi.psi_bit,
            })
            .collect();

        // NOTE: based on grouping bit the number of subcarrier change
        // for more details see IEEE 802.11ax Table 9-91a and Table 9-91e
        let num_sub = match (mimo_ctrl.grouping().value(), mimo_ctrl.bandwidth()) {
            (0, Bandwidth::Bw20) => 64,
            (0, Bandwidth::Bw40) => 122,
            (0, Bandwidth::Bw80) => 250,
            (0, Bandwidth::Bw160) => 500,
            (1, Bandwidth::Bw20) => 50,
            (1, Bandwidth::Bw40) => 32,
            (1, Bandwidth::Bw80) => 64,
            (1, Bandwidth::Bw160) => 160,
            _ => panic!("Invalid grouping or BW"),
        };

        ExtractionConfig {
            bitfield_pattern,
            num_subcarrier: num_sub,
        }
    }
}

/// Some sanity checks for the BFA bitfield extraction
#[cfg(debug_assertions)]
fn sanity_check_extraction(
    bitfield_pattern: &[u8],
    num_chunks: usize,
    byte_stream_len: usize,
) -> Result<(), BfaExtractionError> {
    // Find the number of bits per chunk
    let total_bits_per_chunk: usize = bitfield_pattern
        .iter()
        .map(|&bitsize| bitsize as usize)
        .sum();

    // Find the number of bits we expect present in the byte stream
    let total_bits_needed = total_bits_per_chunk * num_chunks;

    // Ensure there are enough bits in the byte stream
    if byte_stream_len * 8 < total_bits_needed {
        return Err(BfaExtractionError::InsufficientBitsize {
            required: total_bits_needed,
            available: byte_stream_len * 8,
        });
    }

    // See `extract_bitfields` for an explanation of this part
    let max_allowed_bitsize = 9;
    if bitfield_pattern.iter().any(|&x| x > max_allowed_bitsize) {
        return Err(BfaExtractionError::InvalidBitfieldSize {
            given: *bitfield_pattern.iter().max().unwrap(),
            allowed: 9,
        });
    }

    Ok(())
}

/// Extract bitfields from a pattern description
///
/// This function runs through a stream of bytes and extracts bitfields.
/// To extract bits from LSB, we pre-shift new bytes' bitpattern to the
/// front and simply mask out the correct bits to extract.
///
/// Also assumes that bitfield_pattern never contains a value greater
/// than 16.
///
/// # Warning
///
/// This function assumes that bfa_payload is at least of size 2.
/// This requirement is not tested, so it will panic if violated.
///
/// # Parameters
/// * `byte_stream` - The bytestream (packet payload containing compressed BFI)
/// * `bitfield_pattern` - The Phi/Psi angle pattern present
/// * `num_chunks` - Number of BFI chunks (i.e. number of subcarriers)
fn extract_bitfields(
    byte_stream: &[u8],
    bitfield_pattern: Vec<u8>,
    num_chunks: usize,
) -> Result<Vec<Vec<u16>>, BfaExtractionError> {
    // Start with some sanity checks in debug mode. In release mode, we
    // leave them out for performance reasons. This will cause a crash in
    // API violations, but that's on you  ¯\_(ツ)_/¯
    #[cfg(debug_assertions)]
    sanity_check_extraction(bitfield_pattern.as_slice(), num_chunks, byte_stream.len())?;

    // --------------------------------------------------------------------------
    // Bit window processing:
    // We use a multi-byte integer as a sliding window over the byte stream to
    // extract bitfields. An index tracks the last processed bit. Since we shift
    // by 8 bits (1 byte) after processing, at most 7 bits can remain unprocessed
    // in the buffer. Therefore, to extract a bitfield of size N, the window must
    // be at least N+7 bits to handle the worst case. For BFI, the WiFi standard
    // specifies at most a bitsize of 9 for an angle, so a 16bit buffer suffices.
    let mut bit_window = u16::from_le_bytes([byte_stream[0], byte_stream[1]]);
    let mut window_offset = 0; // bit-offset pointing past last processed bit
    let mut curr_byte = 2; // stream offset past current window edge

    // Preallocate result vectors and bitmasks
    let mut result = Vec::with_capacity(num_chunks);
    let mut chunk = Vec::with_capacity(bitfield_pattern.len());
    let masks: Vec<u16> = bitfield_pattern.iter().map(|&l| (1 << l) - 1).collect();

    for _ in 0..num_chunks {
        chunk.clear();
        for (i, &bit_length) in bitfield_pattern.iter().enumerate() {
            // If the to-be-processed bitfield is not completely within the
            // 16 bit, we need to advance the window.
            while window_offset + bit_length > 16 {
                // Shift in new byte from the left into window and advance
                let next_byte = byte_stream[curr_byte] as u16;
                bit_window = (bit_window >> 8) | (next_byte << 8);
                window_offset -= 8;
                curr_byte += 1;
            }

            // Extract the requested number of bits from the window (MSB first)
            let mask = masks[i];
            let bitfield = (bit_window >> window_offset) & mask;

            // Add the extracted bitfield to the chunk and advance pointer to
            // next bits in window to be processed.
            chunk.push(bitfield);
            window_offset += bit_length;
        }

        // Collect the chunk
        result.push(chunk.clone());
    }

    Ok(result)
}

/// Extract BFA from payload using the corresponding extraction config
///
/// # Parameters
/// * `bfa_payload` - The bytestream (packet payload containing compressed BFI)
/// * `extraction_config` - Configuration for the extraction acquired from the MIMO control configuration
pub fn extract_bfa(
    bfa_payload: &[u8],
    extraction_config: ExtractionConfig,
) -> Result<Vec<Vec<u16>>, BfaExtractionError> {
    extract_bitfields(
        bfa_payload,
        extraction_config.bitfield_pattern,
        extraction_config.num_subcarrier,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extractioncfg_parsing_2by1() {
        let byte_stream: &[u8] = &[0b11001000, 0b10000100, 0b00000000, 0b11000100, 0b00001101];

        let result_he_mimo = HeMimoControl::from_buf(byte_stream);
        let result_he_ctrl = ExtractionConfig::from_he_mimo_ctrl(&result_he_mimo);
        let expected_bitfield_pattern = vec![7, 5]; // 7 phi, 5 psi

        assert_eq!(result_he_ctrl.bitfield_pattern, expected_bitfield_pattern);
        assert_eq!(result_he_ctrl.num_subcarrier, 500); //BW 160
    }

    #[test]
    fn extractioncfg_parsing_3by2() {
        let byte_stream: &[u8] = &[0b10010001, 0b10000000, 0b00000000, 0b11000100, 0b00001101];

        let result_he_mimo = HeMimoControl::from_buf(byte_stream);
        let result_he_ctrl = ExtractionConfig::from_he_mimo_ctrl(&result_he_mimo);
        let expected_bitfield_pattern = vec![4, 4, 2, 2, 4, 2]; // 4 phi, 2 psi

        assert_eq!(result_he_ctrl.bitfield_pattern, expected_bitfield_pattern);
        assert_eq!(result_he_ctrl.num_subcarrier, 250); //BW 80
    }

    #[test]
    fn extractioncfg_parsing_4by1() {
        let byte_stream: &[u8] = &[0b01011000, 0b10000010, 0b00000000, 0b11000100, 0b00001101];

        let result_he_mimo = HeMimoControl::from_buf(byte_stream);
        let result_he_ctrl = ExtractionConfig::from_he_mimo_ctrl(&result_he_mimo);
        let expected_bitfield_pattern = vec![6, 6, 6, 4, 4, 4]; // 6 phi, 4 psi

        assert_eq!(result_he_ctrl.bitfield_pattern, expected_bitfield_pattern);
        assert_eq!(result_he_ctrl.num_subcarrier, 122); //BW 40
    }

    #[test]
    fn extractioncfg_parsing_4by2() {
        let byte_stream: &[u8] = &[0b00011001, 0b10000010, 0b00000000, 0b11000100, 0b00001101];

        let result_he_mimo = HeMimoControl::from_buf(byte_stream);
        let result_he_ctrl = ExtractionConfig::from_he_mimo_ctrl(&result_he_mimo);
        let expected_bitfield_pattern = vec![6, 6, 6, 4, 4, 4, 6, 6, 4, 4]; // 6 phi, 4 psi

        assert_eq!(result_he_ctrl.bitfield_pattern, expected_bitfield_pattern);
        assert_eq!(result_he_ctrl.num_subcarrier, 64); //BW 20
    }

    #[test]
    fn extractioncfg_parsing_4by4() {
        let byte_stream: &[u8] = &[0b11011011, 0b10000111, 0b00000000, 0b11000100, 0b00001101];

        let result_he_mimo = HeMimoControl::from_buf(byte_stream);
        let result_he_ctrl = ExtractionConfig::from_he_mimo_ctrl(&result_he_mimo);
        let expected_bitfield_pattern = vec![9, 9, 9, 7, 7, 7, 9, 9, 7, 7, 9, 7]; // 9 phi, 7 psi

        assert_eq!(result_he_ctrl.bitfield_pattern, expected_bitfield_pattern);
        assert_eq!(result_he_ctrl.num_subcarrier, 160); //BW 160
    }

    #[test]
    fn bitfield_extraction_base() {
        // Example payload 11001010 11110000 01011100 00111110
        // Reverse:        01010011 00001111 00111010 01111100
        // Chunk:          010100 1100 0011 110011 1010 0111 (1100)
        // Reverse:        001010 0011 1100 110011 0101 1110
        let byte_stream: &[u8] = &[0b11001010, 0b11110000, 0b01011100, 0b00111110];
        let expected: Vec<Vec<u16>> = vec![
            vec![0b001010, 0b0011, 0b1100],
            vec![0b110011, 0b0101, 0b1110],
        ];

        // Example pattern (6 bits, 4 bits, 4 bits) x 2
        let bitfield_pattern = vec![6, 4, 4];
        let num_chunks = 2;

        let result = extract_bitfields(byte_stream, bitfield_pattern, num_chunks);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(
            result == expected,
            "Expected {:?}, but got: {:?}",
            expected,
            result
        );
    }

    #[test]
    fn extract_bitfields_long_bitsize() {
        // Example payload 11001010 11110000
        // Reverse:        01010011 00001111
        // Chunk:          010100110 00011 11
        // Reverse:        011001010 11000 11
        let byte_stream: &[u8] = &[0b11001010, 0b11110000];
        let expected: Vec<Vec<u16>> = vec![vec![0b011001010, 0b11000, 0b11]];

        // use longer bitsize of 9
        let bitfield_pattern = vec![9, 5, 2];
        let num_chunks = 1; // Example number of chunks

        let result = extract_bitfields(byte_stream, bitfield_pattern, num_chunks);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(
            result == expected,
            "Expected {:?}, but got: {:?}",
            expected,
            result
        );
    }

    #[test]
    fn extract_as_4by2() {
        // example: 10010111 10011111 01010011 11011101 00111001 00101110 01011110 01111110 01001110 01110101 11100111 10111000 01110111 11111001 00111001 11010101
        // reverse: 11101001 11111001 11001010 10111011 10011100 01110100 01111010 01111110 01110010 10101110 11100111 00011101 11101110 10011111 10011100 10101011
        // chunk  : 111010 011111 100111 0010 1010 1110 111001 110001 1101 0001 | 111010 011111 100111 0010 1010 1110 111001 110001 1101 1110 (1110 10011111)
        // reverse: 010111 111110 111001 0100 0101 0111 100111 100011 1011 1000 | 010111 111110 111001 0100 0101 0111 100111 100011 1011 0111
        let byte_stream_extract: &[u8] = &[
            0b10010111, 0b10011111, 0b01010011, 0b11011101, 0b00111001, 0b00101110, 0b01011110,
            0b01111110, 0b01001110, 0b01110101, 0b11100111, 0b10111000, 0b01110111, 0b11111001,
            0b00111001, 0b11010101,
        ];
        let bitfield_pattern = vec![6, 6, 6, 4, 4, 4, 6, 6, 4, 4];
        let num_chunks = 2;

        let result = extract_bitfields(byte_stream_extract, bitfield_pattern, num_chunks);
        assert!(result.is_ok());

        let result = result.unwrap();
        let expected: Vec<Vec<u16>> = vec![
            vec![
                0b010111, 0b111110, 0b111001, 0b0100, 0b0101, 0b0111, 0b100111, 0b100011, 0b1011,
                0b1000,
            ],
            vec![
                0b010111, 0b111110, 0b111001, 0b0100, 0b0101, 0b0111, 0b100111, 0b100011, 0b1011,
                0b0111,
            ],
        ];
        assert!(
            result == expected,
            "Expected {:?}, but got: {:?}",
            expected,
            result
        );
    }

    #[test]
    fn extract_as_4by2_large_bitfields() {
        // example: 10010111 10011111 01010011 11011101 00111001 00101110 01011110 01111110 01001110 01110101 11100111 10111000 01110111 11111001 00111001 11010101
        // reverse: 11101001 11111001 11001010 10111011 10011100 01110100 01111010 01111110 01110010 10101110 11100111 00011101 11101110 10011111 10011100 10101011
        // chunk  : 111010011 111100111 001010101 1101110 0111000 1110100 011110100 111111001 1100101 0101110  (11100111 00011101 11101110 10011111 10011100 10101011)
        // reverse: 110010111 111001111 101010100 0111011 0001110 0010111 001011110 100111111 1010011 0111010
        let byte_stream_extract: &[u8] = &[
            0b10010111, 0b10011111, 0b01010011, 0b11011101, 0b00111001, 0b00101110, 0b01011110,
            0b01111110, 0b01001110, 0b01110101, 0b11100111, 0b10111000, 0b01110111, 0b11111001,
            0b00111001, 0b11010101,
        ];
        let expected_bitfield_pattern = vec![9, 9, 9, 7, 7, 7, 9, 9, 7, 7];
        let num_chunks = 1;

        let result = extract_bitfields(byte_stream_extract, expected_bitfield_pattern, num_chunks);
        assert!(result.is_ok());
        let result = result.unwrap();
        let expected: Vec<Vec<u16>> = vec![vec![
            0b110010111,
            0b111001111,
            0b101010100,
            0b0111011,
            0b0001110,
            0b0010111,
            0b001011110,
            0b100111111,
            0b1010011,
            0b0111010,
        ]];
        assert_eq!(result, expected);
    }

    #[test]
    fn capacity_error() {
        // Example payload 11001010 11110000 01011100 00111110
        // Reverse:        01010011 00001111 00111010 01111100
        // Chunk:          010100 1100 0011 110011 1010 0111 (1100)
        // Reverse:        001010 0011 1100 110011 0101 1110
        let byte_stream: &[u8] = &[0b11001010, 0b11110000];
        let bitfield_pattern = vec![6, 4, 4];
        let num_chunks = 2;

        // 2 chunks, each of size 14 bit -> exceeds payload of 16 bits

        let result = extract_bitfields(byte_stream, bitfield_pattern, num_chunks);
        assert!(matches!(
            result,
            Err(BfaExtractionError::InsufficientBitsize {
                required: 28,
                available: 16
            })
        ));
    }
}
