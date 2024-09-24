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
HINT: make sure you have set NIC to monitor mode, somehow rust dont set it to monitor mode. 


after building with `cargo build --package bfi_cli`
you need to give the script permission to do network sniffing stuff. Therfore, got to target/debug (or target/release  if you build in release mode) and do:  
 
```bash
cd target/debug
sudo setcap cap_net_raw+ep ./bfi_cli
```
then go back to main dir and now you can use 
```bash 
cargo run --package bfi_cli capture -p
```
to capture Acktion No ACK frames with rust. 

NOTE: if you want to sniff any frame just remove the filter in the main.rs file. 


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
