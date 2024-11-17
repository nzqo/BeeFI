//! Stream-based capturing
//!
//! This library supports extraction of BFI data from WiFi packets. There are two
//! main ways to work with these packets:
//!  - Load all of them from a file, then process as batch
//!  - Open a pcap stream (either online or from file) and process piece by piece
//!
//! This module implements

use crossbeam_channel::{bounded, Receiver, Sender};
use pcap::{Active, Capture, Offline, Savefile};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::pcap::extract_from_packet;
use crate::{BfiData, BfiFile, Writer};

const BATCH_SIZE: usize = 1000;

/// Manages packet capture and BFI processing from a `Capture object`.
///
/// Supports option to stream raw and/or processed packets to sinks for further handling.
pub struct StreamBee {
    cap: CaptureWrapper,
    pollen_sink: Option<PollenSink>,
    honey_sink: Option<Sender<BfiData>>,
    running: Arc<AtomicBool>,
}

/// Wrapper enum for `Capture<Active>` and `Capture<Offline>` to avoid generics in CaptureBee.
enum CaptureWrapper {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl CaptureWrapper {
    /// Reads the next packet, returning `Ok(Packet)` if successful, or an error if not.
    fn next_packet(&mut self) -> Result<pcap::Packet, pcap::Error> {
        match self {
            CaptureWrapper::Live(cap) => cap.next_packet(),
            CaptureWrapper::File(cap) => cap.next_packet(),
        }
    }
}

/// A sink to receive honey, i.e. processed BFI data
pub enum HoneySink {
    File(BfiFile),
    Queue(Sender<BfiData>),
}

/// A sink to receive pollen, i.e. raw data.
///
/// This is mainly used to store data captured live from an interface
/// to a pcap file as an intermediate optional processing step.
pub enum PollenSink {
    File(Savefile),
}

impl StreamBee {
    /// Creates a bee from a live `Capture<Active>`
    pub fn from_live_capture(cap: Capture<Active>) -> Self {
        log::trace!("Creating a streaming Bee from a pcap live capture");
        Self::new(CaptureWrapper::Live(cap))
    }

    /// Creates a bee from an offline `Capture<Offline>`.
    pub fn from_file_capture(cap: Capture<Offline>) -> Self {
        log::trace!("Creating a streaming Bee from a pcap file");
        Self::new(CaptureWrapper::File(cap))
    }

    fn new(cap: CaptureWrapper) -> Self {
        Self {
            cap,
            pollen_sink: None,
            honey_sink: None,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Registers a sink for packet processing, supporting multiple output options.
    ///
    /// - `HoneySink::File`: Captured packets are extracted, batched, and saved to a specified file.
    /// - `HoneySink::Queue`: Packets are extracted and sent to an in-process queue for real-time handling.
    ///
    /// # Parameters
    /// - `sink`: The `Sink` to stream to
    pub fn subscribe_for_honey(&mut self, sink: HoneySink) {
        if self.honey_sink.is_some() {
            panic!("Cant set two processed data sinks (currently)");
        }

        let sink = match sink {
            HoneySink::File(file) => {
                let (tx, rx) = bounded(100);

                // Spawn a thread to handle file writing from the channel
                let file = file.clone();
                log::trace!(
                    "Spawning background thread to write processed data to file {:?}",
                    file
                );
                thread::spawn(|| write_packets_to_file(rx, file));
                tx
            }
            HoneySink::Queue(queue) => queue,
        };

        self.honey_sink = Some(sink);
    }

    /// Registers a sink for pollen (raw packets)
    ///
    /// - `PollenSink::File`: Specifies a pcap file to write packets to
    ///
    /// # Parameters
    /// - `sink`: The sink to stream the raw packets to
    pub fn subscribe_for_pollen(&mut self, sink: PollenSink) {
        if self.pollen_sink.is_some() {
            panic!("Cant set two raw sinks (currently)");
        }
        self.pollen_sink = Some(sink);
    }

    /// Starts harvesting packets from the registered Capture
    ///
    /// Reads packets from the registered interface, then:
    ///
    /// 1. If a `PollenSink` is registered, first forwards the raw packets
    /// 2. If a `HoneySink` is registered, extracts BFI data and forwards it.
    ///
    /// Captures packets continuously until:
    /// - The capture ends (for offline captures),
    /// - An error occurs, or
    /// - The `stop()` method is called.
    ///
    /// # Parameters
    /// * `print` - Whether to print processed data to stdout.
    pub fn start_harvesting(&mut self, print: bool) {
        log::info!("Starting harvesting of packets! εწз");
        self.running.store(true, Ordering::SeqCst);

        // Loop while the running flag is true
        while self.running.load(Ordering::SeqCst) {
            // Capture the next packet first, holding the mutable borrow only for this step
            let packet = {
                match self.cap.next_packet() {
                    Ok(packet) => packet,
                    Err(e) => {
                        log::error!("Pcap capture error encountered: {}. Stopping harvest.", e);
                        break;
                    }
                }
            };

            if let Some(raw_sink) = &mut self.pollen_sink {
                match raw_sink {
                    PollenSink::File(savefile) => savefile.write(&packet),
                }
            }

            if self.honey_sink.is_some() || print {
                let data = extract_from_packet(&packet);

                if print {
                    println!(
                        "Captured data:\n - timestamp: {}\n - token number {}\n - {:?}\n - {:?}",
                        data.timestamp, data.token_number, data.metadata, data.bfa_angles
                    );
                }

                if let Some(sink) = &self.honey_sink {
                    if let Err(e) = sink.send(data) {
                        log::error!(
                            "Failed to forward data to sink; Stopping collection. Error: {}",
                            e
                        );
                    }
                }
            }
        }

        log::info!("Packet capture completed!\n");
    }

    /// Stops packet capture gracefully by setting `running` to `false`.
    ///
    /// # Note
    ///
    /// After invoking this function, registered sinks are destroyed. If you
    /// want to reuse this object for collection, you will have to subscribe
    /// with a new pair of sinks.
    pub fn stop(&mut self) {
        log::info!("Stopping harvesting of data; Resetting sinks as well.");
        self.running.store(false, Ordering::SeqCst);

        // Ensure pcap file is flushed
        if let Some(PollenSink::File(file)) = &mut self.pollen_sink {
            if let Err(e) = file.flush() {
                log::error!("Error flushing pcap stream file: {}", e);
            }
        }

        // Ensure the queues are destroyed so the file writer's are notified.
        self.honey_sink = None;
        self.pollen_sink = None;
    }
}

/// Writes captured packets to a file in batches, receiving data from a queue.
///
/// # Parameters
/// - `rx`: Receiver channel that receives `BfiData` packets to write.
/// - `out_file`: The file to which packets are saved in batches.
fn write_packets_to_file(rx: Receiver<BfiData>, out_file: BfiFile) {
    let mut packet_buffer = Vec::new();
    let mut writer = Writer::new(out_file).expect("Couldn't create a file writer!");

    while let Ok(bfi_data) = rx.recv() {
        packet_buffer.push(bfi_data);
        if packet_buffer.len() <= BATCH_SIZE {
            continue;
        }

        if let Err(e) = writer.add_batch(&packet_buffer) {
            log::error!("Error encountered on batch writing: {}. Exiting writer.", e);
            return;
        }
        packet_buffer.clear();
    }

    if packet_buffer.is_empty() {
        return;
    }

    // Write any remaining packets when the channel is closed
    if let Err(e) = writer.add_batch(&packet_buffer) {
        log::error!("Error encountered on batch writing: {}. Exiting writer.", e);
    }
}

/// Creates a live capture to read packets from a specified network interface.
pub fn create_live_capture(interface: &str) -> Capture<Active> {
    log::info!("Creating live capture on interface: {}", interface);
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

/// Creates an offline capture to read packets from a pcap file.
pub fn create_offline_capture(pcap_file: PathBuf) -> Capture<Offline> {
    log::info!(
        "Creating offline pcap capture from file: {}",
        pcap_file.display()
    );
    Capture::from_file(pcap_file).expect("Failed to open pcap file")
}
