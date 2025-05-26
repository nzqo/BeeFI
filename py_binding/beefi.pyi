from typing import List, Optional, Union

from numpy import ndarray

class PyBfiMeta:
    """
    BFI metadata structure.

    Attributes:
        bandwidth (int): Channel bandwidth.
        nr_index (int): Index of the receive antennas used in the sounding procedure.
        nc_index (int): Index of columns (streams) used in the sounding procedure.
        codebook_info (int): Codebook size.
        feedback_type (int): Feedback type (e.g., SU, MU, CQI).
    """

    bandwidth: int
    nr_index: int
    nc_index: int
    codebook_info: int
    feedback_type: int

class PyBfmData:
    """
    BFM data extracted from a single packet.

    Attributes:
        metadata (PyBfiMeta): Metadata associated with the BFI data.
        timestamp (float): Timestamp of the associated pcap capture.
        token_number (int): Token number identifying the NDP packet used in the procedure.
        bfa_angles (ndarray): 2D array of extracted BFA angles from the compressed beamforming feedback information.
    """

    metadata: PyBfiMeta
    timestamp: float
    token_number: int
    bfm: (
        ndarray  # 3D array of shape (num_rx_antennas, num_spatial_streams, subcarriers)
    )

class PyBfmBatch:
    """
    BFM data extracted from a single packet.

    Attributes:
        metadata (PyBfiMeta): Metadata associated with the BFI data.
        timestamp (float): Timestamp of the associated pcap capture.
        token_number (int): Token number identifying the NDP packet used in the procedure.
        bfa_angles (ndarray): 2D array of extracted BFA angles from the compressed beamforming feedback information.
    """

    metadata: List[PyBfiMeta]
    timestamps: ndarray  # 1D array of shape (num_packets,)
    token_numbers: ndarray  # 1D array of shape (num_packets,)
    bfa_angles: ndarray  # 4D array of shape (num_packets, num_rx_antenna, num_spatial_streams, subcarriers)

class PyBfaData:
    """
    BFI angle data extracted from a single packet.

    Attributes:
        metadata (PyBfiMeta): Metadata associated with the BFI data.
        timestamp (float): Timestamp of the associated pcap capture.
        token_number (int): Token number identifying the NDP packet used in the procedure.
        bfa_angles (ndarray): 2D array of extracted BFA angles from the compressed beamforming feedback information.
    """

    metadata: PyBfiMeta
    timestamp: float
    token_number: int
    bfa_angles: ndarray  # 2D array of shape (subcarriers, angles)

class PyBfaBatch:
    """
    Batch of BFI data, extracted from multiple packets.

    Attributes:
        metadata (List[PyBfiMeta]): List of metadata of shape (num_packets,).
        timestamps (ndarray): 1D array of timestamps of shape (num_packets,).
        token_numbers (ndarray): 1D array of token numbers of shape (num_packets,).
        bfa_angles (ndarray): 3D array of BFA angles with shape (num_packets, subcarriers, angles).
    """

    metadata: List[PyBfiMeta]
    timestamps: ndarray  # 1D array of shape (num_packets,)
    token_numbers: ndarray  # 1D array of shape (num_packets,)
    bfa_angles: ndarray  # 3D array of shape (num_packets, subcarriers, angles)

class DataSource:
    """
    Specifies the source of packet data for BFI capture.

    Variants:
        Live: Capture packets live from a network interface.
        File: Capture packets from an offline pcap file.
    """
    class Live:
        """
        Specifies a live capture source.

        Attributes:
            interface (str): Name of the network interface to capture packets on.
        """

        interface: str

    class File:
        """
        Specifies a file-based capture source.

        Attributes:
            file_path (str): Path to the pcap file on disk.
        """

        file_path: str

class Bee:
    """
    Capture bee for reading and processing packets in a streaming fashion.

    Methods:
        __init__: Initialize a streaming bee for packet capture.
        poll: Polls for new BFI data, returning it if available.
        stop: Stops the capture process.
    """

    def __init__(
        self,
        source: Union[DataSource.Live, DataSource.File],
        queue_size: int = 1000,
        pcap_buffer: bool = False,
        pcap_snaplen: int = 4096,
        pcap_bufsize: int = 1_000_000,
    ) -> None:
        """
        Initializes a new streaming Bee.

        Args:
            source (Union[DataSource.Live, DataSource.File]): The source of packets (live interface or pcap file).
            queue_size (int): Size of the internal queue to buffer collected data. Defaults to 1000.
            pcap_buffer (bool): Whether pcap should buffer packets before processing. Default is off (immediate processing).
            pcap_snaplen (int): Internal pcap snapshot length (defaults to 4k=4096)
            pcap_bufsize (int): Internal pcap buffer size to store snapshots (defaults to 1_000_000)
        """
        ...

    def poll(self) -> Optional[PyBfaData]:
        """
        Polls the queue for new BFI data. Non-blocking; returns None if no data is available.

        Returns:
            Optional[PyBfaData]: BFI data if available, or None if the queue is empty.
        """
        ...

    def stop(self) -> None:
        """
        Stops the capture process, exiting background threads and wrapping up file usage.
        """
        ...

def extract_from_pcap(path: str) -> PyBfaBatch:
    """
    Extract all BFA data from a pcap file in a single batch. Pads BFA angles as needed.

    Args:
        path (str): Path to the pcap file to extract data from.

    Returns:
        PyBfaBatch: Batch of BFA data, including metadata, timestamps, token numbers, and padded BFA angles.
    """
    ...

def bfa_to_bfm(bfa: PyBfaData) -> PyBfmData:
    """
    Convert Beamforming Feedback Angles to Beamforming Feedback Matrices.

    Args:
        bfa (PyBfaData): Beamforming feedback angle struct.

    Returns:
        PyBfmData: Converted BFM struct.
    """

def bfa_to_bfm_batch(bfa_batch: PyBfaBatch) -> PyBfmBatch:
    """
    Convert Beamforming Feedback Angles to Beamforming Feedback Matrices
    for a batch of data.

    Args:
        bfa (PyBfaBatch): Beamforming feedback angle batch

    Returns:
        PyBfmBatch: Converted BFM batch
    """
