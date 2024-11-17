from typing import Optional, List, Union
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

class PyBfiData:
    """
    BFI data extracted from a single packet.

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

class PyBfiBatch:
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

    def __init__(self, source: Union[DataSource.Live, DataSource.File], queue_size: Optional[int] = 1000) -> None:
        """
        Initializes a new streaming Bee.

        Args:
            source (Union[DataSource.Live, DataSource.File]): The source of packets (live interface or pcap file).
            queue_size (Optional[int]): Size of the internal queue to buffer collected data. Defaults to 1000.
        """
        ...

    def poll(self) -> Optional[PyBfiData]:
        """
        Polls the queue for new BFI data. Non-blocking; returns None if no data is available.

        Returns:
            Optional[PyBfiData]: BFI data if available, or None if the queue is empty.
        """
        ...

    def stop(self) -> None:
        """
        Stops the capture process, exiting background threads and wrapping up file usage.
        """
        ...

def extract_from_pcap(path: str) -> PyBfiBatch:
    """
    Extract all BFI data from a pcap file in a single batch. Pads BFA angles as needed.

    Args:
        path (str): Path to the pcap file to extract data from.

    Returns:
        PyBfiBatch: Batch of BFI data, including metadata, timestamps, token numbers, and padded BFA angles.
    """
    ...
