use crossbeam_channel::{bounded, Receiver, Sender};
use pcap::{Active, Capture, Offline, Savefile};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::pcap::extract_from_packet;
use crate::{save, BfaFile, BfiData};

/// Manages packet capture and BFI processing from a `Capture object`.
///
/// Supports option to stream raw and/or processed packets to sinks for further handling.
pub struct CaptureBee {
    cap: CaptureWrapper,
    raw_sink: Option<RawSink>,
    proc_sink: Option<Sender<BfiData>>,
    running: Arc<AtomicBool>,
    extract_data: bool,
}

/// Wrapper enum for `Capture<Active>` and `Capture<Offline>` to avoid generics in CaptureBee.
pub enum CaptureWrapper {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl CaptureWrapper {
    /// Reads the next packet, returning `Ok(Packet)` if successful, or an error if not.
    pub fn next_packet(&mut self) -> Result<pcap::Packet, pcap::Error> {
        match self {
            CaptureWrapper::Live(cap) => cap.next_packet(),
            CaptureWrapper::File(cap) => cap.next_packet(),
        }
    }
}

/// Enum for processed data sinks (i.e., extracted BFI data).
pub enum ProcessedSink {
    File(BfaFile),
    Queue(Sender<BfiData>),
}

/// Enum for raw data sinks (i.e., unprocessed packets).
pub enum RawSink {
    File(Savefile),
}

impl CaptureBee {
    /// Creates a new `CaptureBee` from a live `Capture<Active>`.
    pub fn from_live_capture(cap: Capture<Active>) -> Self {
        Self::new(CaptureWrapper::Live(cap))
    }

    /// Creates a new `CaptureBee` from an offline `Capture<Offline>`.
    pub fn from_file_capture(cap: Capture<Offline>) -> Self {
        Self::new(CaptureWrapper::File(cap))
    }

    fn new(cap: CaptureWrapper) -> Self {
        Self {
            cap,
            raw_sink: None,
            proc_sink: None,
            running: Arc::new(AtomicBool::new(false)),
            extract_data: false,
        }
    }

    /// Registers a sink for packet processing, supporting multiple output options.
    ///
    /// - `ProcessedSink::File`: Captured packets are extracted, batched, and saved to a specified file.
    /// - `ProcessedSink::Queue`: Packets are extracted and sent to an in-process queue for real-time handling.
    ///
    /// # Parameters
    /// - `sink`: The `Sink` to stream to
    pub fn set_proc_sink(&mut self, sink: ProcessedSink) {
        if self.proc_sink.is_some() {
            panic!("Cant set two processed data sinks (currently)");
        }

        let sink = match sink {
            ProcessedSink::File(file) => {
                self.extract_data = true;
                let (tx, rx) = bounded(100);

                // Spawn a thread to handle file writing from the channel
                let file = file.clone();
                thread::spawn(|| write_packets_to_file(rx, file));
                tx
            }
            ProcessedSink::Queue(queue) => queue,
        };

        self.proc_sink = Some(sink);
    }

    /// Registers a sink for raw packets
    ///
    /// - `Sink::File`:
    ///
    /// # Parameters
    /// - `sink`: The `Sink` to stream to
    pub fn set_raw_sink(&mut self, sink: RawSink) {
        if self.raw_sink.is_some() {
            panic!("Cant set two raw sinks (currently)");
        }
        self.raw_sink = Some(sink);
    }

    /// Starts packet capture, processing packets based on registered sinks and options.
    ///
    /// Captures packets continuously until:
    /// - The capture ends (for offline captures),
    /// - An error occurs, or
    /// - The `stop()` method is called, which sets `running` to `false`.
    ///
    /// # Parameters
    /// - `print`: If `true`, logs each captured packet for debugging or inspection.
    pub fn start(&mut self, print: bool) {
        // If print is true, we extract data (to print)
        self.extract_data = self.extract_data || print;

        log::info!("Starting packet capture...");
        self.running.store(true, Ordering::SeqCst);

        // Loop while the running flag is true
        while self.running.load(Ordering::SeqCst) {
            // Capture the next packet first, holding the mutable borrow only for this step
            let packet = {
                match self.cap.next_packet() {
                    Ok(packet) => packet,
                    Err(e) => {
                        log::error!("Pcap capture error encountered: {}", e);
                        break;
                    }
                }
            };

            if self.proc_sink.is_some() || print {
                let data = extract_from_packet(&packet);

                if print {
                    log::info!(
                        "Captured packet -- timestamp: {}, token: {}, length: {}",
                        data.timestamp,
                        data.token_number,
                        data.bfa_angles.len()
                    );
                }

                if let Some(sink) = &self.proc_sink {
                    if let Err(e) = sink.send(data) {
                        log::error!(
                            "Failed to forward data to sink; Stopping collection. Error: {}",
                            e
                        );
                    }
                }
            }

            if let Some(raw_sink) = &mut self.raw_sink {
                match raw_sink {
                    RawSink::File(savefile) => savefile.write(&packet),
                }
            }
        }

        log::info!("Packet capture completed!\n");
    }

    /// Stops packet capture gracefully by setting `running` to `false`.
    ///
    /// The `start()` method will complete any remaining packet processing before exiting.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Writes captured packets to a file in batches, receiving data from a queue.
///
/// # Parameters
/// - `rx`: Receiver channel that receives `BfiData` packets to write.
/// - `out_file`: The file to which packets are saved in batches.
fn write_packets_to_file(rx: Receiver<BfiData>, out_file: BfaFile) {
    let mut packet_buffer = Vec::new();
    let batch_size = 10;

    while let Ok(bfi_data) = rx.recv() {
        packet_buffer.push(bfi_data);
        if packet_buffer.len() >= batch_size {
            save_batch(&packet_buffer, &out_file);
            packet_buffer.clear();
        }
    }

    // Write any remaining packets when the channel is closed
    if !packet_buffer.is_empty() {
        save_batch(&packet_buffer, &out_file);
    }
}

/// Saves a batch of packets to a specified file.
///
/// # Parameters
/// - `packet_buffer`: A slice of `BfiData` packets to save in a batch.
/// - `out_file`: The file to which packets are saved.
fn save_batch(packet_buffer: &[BfiData], out_file: &BfaFile) {
    if let Err(e) = save(out_file.clone(), packet_buffer) {
        log::error!("Failed to write to file: {}", e);
    }
}

/// Creates a live `Capture<Active>` object for a specified network interface.
pub fn create_live_capture(interface: &str) -> Capture<Active> {
    let devices = pcap::Device::list().unwrap_or_else(|e| {
        panic!("Error listing devices: {}", e);
    });

    let device = devices
        .into_iter()
        .find(|d| d.name == interface)
        .expect("Failed to find the specified interface");

    Capture::from_device(device)
        .expect("Failed to create capture")
        .open()
        .expect("Failed to open live capture")
}

/// Creates a live `Capture<Active>` object for a specified network interface.
pub fn create_offline_capture(pcap_file: PathBuf) -> Capture<Offline> {
    Capture::from_file(pcap_file).expect("Failed to open pcap file")
}

/// Function to extract not online but offline; In-process.
pub fn extract_from_pcap(capture_path: PathBuf) -> Vec<BfiData> {
    let mut capture = Capture::from_file(capture_path).expect("Couldn't open pcap file");
    let mut extracted_data = Vec::new();

    while let Ok(packet) = capture.next_packet() {
        let packet = extract_from_packet(&packet);
        extracted_data.push(packet);
    }

    extracted_data
}
