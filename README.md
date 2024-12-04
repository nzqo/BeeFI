<div align="center">
  <img src="assets/logo.png" alt="Project Logo" width="250">

# BeeFI
</div>

## Overview

**BeeFI** is a tool for capturing and processing Beamforming Feedback Information (BFI)
from WiFi communications, designed for users who need real-time or batched data extraction
for analysis. BeeFI provides flexible capture options for both live and pcap-based data,
with bindings for Python for seamless integration with data processing workflows.

The extraction is built with efficiency in mind. BeeFI can process tens of thousand of
packets per second easily.

This workspace includes:

- `lib` – The core library with BeeFI's primary capture and processing functions  
- `beefi` – A command-line tool to perform BFI data extraction  
- `py_binding` – A Python binding to import and extract information into numpy arrays  

## Getting Started

### Prerequisites

Make sure `libpcap` is installed on your system.

### Features

- **bfi_metadata**: Extract some metadata (e.g. bandwidth) together with the core data.
  Enabled per default.
- **parquet**: Support writing of extracted data to parquet files.
  Enabled per default.

### BeeFI CLI

#### Building the CLI

To build the CLI (which also builds the library as a dependency):

```bash
cargo build --package bfi_cli --release
```

Be aware that this takes a while, mainly because polars is a rather
heavyweight library and compiler optimizations take their time.

#### CLI Options

BeeFI's CLI supports various operations:

- **Capture frames directly to a pcap file**  
- **Extract BFA angles from a pcap file**  
- **Capture live data and directly process it to BFA angles**  

For a list of all options and flags, use:

```bash
./target/release/beefi --help
```

The CLI can either print data to the command line or save it to a file.
Currently, we only support the [parquet](https://parquet.apache.org/) file format.
For working with parquet, we suggest [python polars](https://pola.rs/):

```python
import polars as pl
df = pl.read_parquet("out.parquet")
print(df)
```

#### Running Live Captures

> **Note**: Ensure your NIC is set to monitor mode before capturing live data.

If you want to run BeeFI without `sudo`, grant the necessary permissions:

```bash
sudo setcap cap_net_admin,cap_net_raw=ep ./target/release/beefi
```

Afterwards, simply specify the interface. For example, to capture packets in a
pcap file:

```bash
./target/release/beefi capture --interface wlp1s0 --pcap_out capture.pcap
```

### Python Binding

#### Building the Python Binding

To build the Python binding, create a virtual environment and install BeeFI:

```bash
python3 -m venv .venv && source .venv/bin/activate
cd py_binding
pip install .
```

#### Using the Python Binding

After installation, import `beefi` in Python for data extraction.

```python
import beefi

batch = beefi.extract_from_pcap("file.pcap")
# see dir(batch) for extracted members
```

Live captures are also supported. Note however that the interface must
be set into monitor mode before running this.

```python
import beefi

source = beefi.DataSource.Live(interface="wlp1s0")
bee = beefi.Bee(source)
bee.start()

while True: # Handle Ctrl+C in production code
    if data := bee.poll():
        print(f"data: {data}")
    else:
        time.sleep(0.01) # Sleep 10 ms to avoid busy-waiting

bee.stop()
```

## Testing

To run unit tests for BeeFI, simply use:

```bash
cargo test
```

You can run a simple test with the CLI as well:

```bash
./target/release/beefi --loglevel trace capture --pcap-in data/test_data/bfi.pcap --print
```
