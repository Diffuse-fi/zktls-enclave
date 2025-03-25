<div align="center">
    <img src="./assets/Diffuse%20Logo%20L%20Orange.svg" width="30%">
</div>


# Diffuse zkTLS
[![Automata SGX SDK](https://img.shields.io/badge/Power%20By-Automata%20SGX%20SDK-orange.svg)](https://github.com/automata-network/automata-sgx-sdk)

This repository is a fork of [automata-network/sgx-scaffold](https://github.com/automata-network/sgx-scaffold), a Rust-based template for developing Intel SGX enclaves. This fork leverages the Intel SGX SDK to implement the zkTLS enclave, which provides privacy-preserving TLS connections.

## Project Structure
<pre>
zktls-enclave
├── bin/zktls-pairs/          # Main application
│   ├── build.rs              # Build script for the application
│   ├── Cargo.toml            # Application configuration
│   ├── sgx/                  # SGX enclave configurations and definitions
│   │   ├── config.xml        # Enclave configuration parameters
│   │   ├── enclave.edl       # Enclave Definition Language file
│   │   ├── enclave.lds       # Linker script for the enclave
│   │   └── private.pem       # Developer key (do not use in production)
│   └── src/main.rs           # Application entrypoint
├── crates/enclave/           # SGX enclave implementation
│   ├── Cargo.toml            # Enclave crate configuration
│   └── src/
│       ├── lib.rs            # Main library file for the enclave
│       ├── error.rs          # Error types and result alias
│       ├── parser.rs         # JSON parser for server responses
│       ├── tcp_stream_oc.rs  # Untrusted TCP stream wrapper
│       └── tls.rs            # TLS connection implementation
├── crates/untrusted-host/    # Mock library for OCALL implementations
│   ├── Cargo.toml
│   └── src/lib.rs
├── docker/                   # Docker configurations for Ubuntu 22.04 and 20.04
├── assets/                   # Logo and other assets
├── Cargo.toml                # Workspace configuration
├── Cargo.lock
└── README.md                 # This file
</pre>

## Prerequisites

- **SGX-Supported Machine**: A machine with SGX support is required.
- **SGX and DCAP SDK**: Ensure you have the Intel SGX SDK and DCAP SDK installed. Refer to the [Automata SGX SDK repository](https://github.com/automata-network/automata-sgx-sdk) for the latest supported versions.

## Building the Enclave

### Manual Build

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Diffuse-fi/zktls-enclave.git
    cd zktls-enclave
    ```

2. **Install `cargo-sgx`**:
    ```bash
    cargo install cargo-sgx
    ```
   To see all available commands, run:
    ```bash
    cargo sgx --help
    ```

3. **Generate a New Signing Key**:
    ```bash
    cargo sgx gen-key bin/zktls-pairs/sgx/private.pem
    ```

4. **Set the SGX SDK Environment Variable**:
   (Update the path if you installed the SGX SDK elsewhere)
    ```bash
    export SGX_SDK=/opt/intel/sgxsdk
    ```

5. **Build the Enclave**:
    ```bash
    cargo sgx build
    ```
   Or run the enclave directly:
    ```bash
    cargo sgx run
    ```
   The executable will be located in `./target/debug` or `./target/release`.
### Building as a Standard Rust Application

If you do not have SGX hardware or prefer to run the enclave as a normal Rust application, disable SGX-specific features:
```bash
cargo sgx run --std
```

## Usage

When you run the application (e.g., using cargo sgx run), the following steps occur:
- **File I/O**: Reads a list of currency pairs from pairs/list.txt.
- **TLS Communication**: Connects to Binance’s API via a privacy-preserving TLS request.
- **Data Processing**: Parses the API response, filters for specified currency pairs, and outputs details like pair name, price, and timestamp.
- **Cryptographic Hashing & Attestation**: Generates individual hashes for each data component, combines them, and produces a final attestation report using Intel SGX DCAP.
- **File Outputs**: Writes outputs to files (e.g., pairs.bin, prices.bin, timestamps.bin, sgx_quote.bin).

### Description of use:
```shell
./zktls-pairs --help

enclave v0
Diffuse labs

USAGE:
    zktls-pairs [OPTIONS]

OPTIONS:
    -h, --help                                 Print help information
        --pairs-file-path <PAIRS_FILE_PATH>    Path to the file with pairs [default: pairs/list.txt]
    -V, --version                              Print version information

```

## Community and Support

For any questions, discussions, or contributions, join our [Telegram Channel](https://t.me/zkdiffuse). We're active there and ready to help!