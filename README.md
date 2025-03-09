<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Diffuse zkTLS
[![Automata SGX SDK](https://img.shields.io/badge/Power%20By-Automata%20SGX%20SDK-orange.svg)](https://github.com/automata-network/automata-sgx-sdk)

This is a fork of the Automata SGX SDK, which is a Rust-based SDK for developing Intel SGX enclaves. This repository contains the implementation of the zkTLS enclave, which is used to provide privacy-preserving TLS connections.

## Project Structure
<pre>
├── <a href="bin/zktls-pairs/">app</a>: The main application
│ ├── <a href="bin/zktls-pairs/sgx">sgx</a>: Configurations for the enclave
│ │ ├── <a href="bin/zktls-pairs/sgx/config.xml">config.xml</a>: Developer defined parameters of the enclave
│ │ ├── <a href="bin/zktls-pairs/sgx/enclave.edl">enclave.edl</a>: Enclave Definition Language file defining the enclave interface
│ │ ├── <a href="bin/zktls-pairs/sgx/enclave.lds">enclave.lds</a>: Linker script for the enclave
│ │ └── <a href="bin/zktls-pairs/sgx/private.pem">private.pem</a>: Developer key used to sign the enclave, do not use this key to sign your enclave in production, please use your own key
│ ├── <a href="bin/zktls-pairs/src/main.rs">src/main.rs</a>: Main entrypoint for the application
│ └── <a href="bin/zktls-pairs/build.rs">build.rs</a>: Builder code used to build the application, you don't need change it
├── <a href="crates/enclave/">enclave</a>: The SGX enclave implementation
│   └── <a href="crates/enclave/src/lib.rs">src/lib.rs</a>: Main library file for the enclave
│       ├── <a href="crates/enclave/src/error.rs">error.rs</a>: Error types and result alias
│       ├── <a href="crates/enclave/src/tcp_stream_oc.rs">tcp_stream_oc.rs</a>: Untrusted TCP stream wrapper
│       └── <a href="crates/enclave/src/tls.rs">tls.rs</a>: TLS connection implementation
└── <a href="crates/untrusted-host/">mock-lib</a>: Mock library for OCALL implementations
</pre>

## Building the Enclave
### Prerequisites
In order to build the enclave, you need to have a sgx-supported machine.

If you have a machine with SGX support, please check the version of your SGX and DCAP SDK. The latest version supported by Automata SGX SDK can be found [here](https://github.com/automata-network/automata-sgx-sdk/tree/main).

If you don't have a machine with SGX support, we recommend you to create a [`DCsv3`](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcsv3-series?tabs=sizebasic) instance in Azure. Please refer to the [docker](./docker/) folder for the list of supported systems and create the instance using one of these systems. You can either install the SGX and DCAP SDK manually by following the steps outlined in the Dockerfile, or alternatively, you can use Docker to build and run the enclave directly.

### Build mannually
> You need to have a sgx-supported machine with SGX and DCAP SDK installed to build the enclave manually.
#### Clone the repository
```bash
git clone https://github.com/Diffuse-fi/zktls-enclave.git
cd zktls-enclave
```

#### Install cargo-sgx
```bash
cargo install cargo-sgx
```
Once you have installed `cargo-sgx`, you can check the help menu to see the available commands.
```bash
cargo sgx --help
```

#### Generate new signing key

```bash
cargo sgx gen-key app/sgx/private.pem
```

#### Build the Enclave

Export `SGX_SDK` environment variable first (default path here, change if you installed SGX SDK somewhere else)
```bash
export SGX_SDK=/opt/intel/sgxsdk
```
then you cah build the enclave
```bash
cargo sgx build
```
or you can run the enclave directly
```bash
cargo sgx run
```
You can find the executable file in `./target/debug` or `./target/release` directory.

Also, you can run/build the enclave with the `std` flag, which will disable the SGX feature and run the enclave as a normal Rust application.
```bash
cargo sgx run --std
```
