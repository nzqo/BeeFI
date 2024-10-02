# BfiExtract

A small library to extract information out of the compressed beamforming
feedback angles (BFAs) captured from channel sounding session.

This workspace contains:

- `bfi_lib` The library implementing the core functionality
- `bfi_cli` A mini application to perform extraction from the command line
- `bfi_py_binding` A python binding to directly extract information into numpy arrays

## Installing dependencies

Install pcap (todo link page)

```bash
pip install numpy maturin
```

## Build & Run

To build the CLI (which in turn builds the lib as dependency):

```bash
cargo build --package bfi_cli
cargo run --package bfi_cli 
```

## live capture

> make sure you have set NIC to monitor mode, somehow rust dont set it to monitor mode. 

Live capturing is supported via the `capture` command. However, you first need to set capture permissions for the application: 
 
```bash
sudo setcap cap_net_raw+ep ./target/debug/bfi_cli  # or release
```

Afterwards, you can capture using:

```bash 
cargo run --package bfi_cli capture -p
```

This will capture frames of type `Action NO ACK`, and extract the BFI from them.

## Python Binding

To build the python binding, install maturin and use it to install
the package in your virtual environment:

```bash
# Activate venv from whereever first, then:
cd bfi_py_binding
maturin develop
```

Afterwards, the python binding will be installed in the venv.

## Testing

To run some unit tests, just use cargo:

```bash
cargo test
```
