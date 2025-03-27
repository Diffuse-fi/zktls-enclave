extern crate core;

mod error;
mod ocalls;
mod parser;
mod tcp_stream_oc;
mod tls;

use std::{ffi::CString, fmt::Debug, string::String};

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;
use ethabi::{Token, Uint};
use serde_json::json;
use tiny_keccak::{Hasher, Keccak};
use tls_enclave::tls_request;

use crate::{
    ocalls::{ocall_read_from_file, ocall_write_to_file},
    parser::get_filtered_items,
    tcp_stream_oc::UntrustedTcpStreamPtr,
};

pub(crate) const BINANCE_API_HOST: &str = "data-api.binance.vision";
pub(crate) const HARDCODED_DECIMALS: u32 = 8;

#[derive(Parser)]
#[clap(author = "Diffuse", version = "v0", about)]
struct ZkTlsPairsCli {
    /// Path to the file with pairs
    #[clap(long, default_value = "pairs/list.txt")]
    pairs_file_path: String,
}

#[no_mangle]
pub unsafe extern "C" fn trusted_execution() -> SgxStatus {
    let cli = ZkTlsPairsCli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    tracing::debug!("=============== Trusted execution =================");
    tracing::info!("Form a request inside the TEE");

    // data can be passed betwen enclave and outer world only with byte arrays
    let mut pairs_list_buffer: [u8; 8192] = [0; 8192];
    let mut pairs_list_actual_len: usize = 0;
    let cstr = CString::new(cli.pairs_file_path).expect("CString::new failed");
    let path_bytes = cstr.as_ptr() as *const u8;

    ocall_read_from_file(
        path_bytes,
        pairs_list_buffer.as_mut_ptr(),
        pairs_list_buffer.len(),
        &mut pairs_list_actual_len as *mut usize,
    );

    let currency_pairs_raw_str =
        String::from_utf8_lossy(&pairs_list_buffer[..pairs_list_actual_len]);

    let currency_pairs: Vec<String> = currency_pairs_raw_str
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let currency_pairs_bytes = json!(currency_pairs).to_string();

    let zk_tls_pairs = tls::ZkTlsPairs::new(BINANCE_API_HOST.to_string(), currency_pairs_bytes);

    let response_str = match tls_request(BINANCE_API_HOST, zk_tls_pairs) {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Error encountered in TLS request: {e}");
            return SgxStatus::Unexpected;
        }
    };

    let filtered_items = match get_filtered_items(response_str, &currency_pairs) {
        Ok(items) => items,
        Err(e) => {
            tracing::error!("Error encountered in parsing response: {e}");
            return SgxStatus::Unexpected;
        }
    };

    // We don't need to output the data exactly as it came from the server.
    // The enclave content is trusted, so why not output JSON in a convenient form?

    tracing::info!("Filtered items:");
    for (pair, price, timestamp) in &filtered_items {
        tracing::info!(
            "Pair: {:<10} | Price: {:>15} | Timestamp: {}",
            pair,
            price,
            timestamp
        );
    }

    let pairs: Vec<String> = filtered_items
        .iter()
        .map(|(pair, _, _)| pair.clone())
        .collect();
    let prices: Vec<String> = filtered_items
        .iter()
        .map(|(_, price, _)| price.to_string())
        .collect();
    let timestamps: Vec<String> = filtered_items
        .iter()
        .map(|(_, _, timestamp)| timestamp.to_string())
        .collect();

    tracing::info!("pairs:\t{:?}", pairs);
    tracing::info!("Prices:\t{:?}", prices);
    tracing::info!("Close times:\t{:?}", timestamps);

    print_vec_of_strings(pairs, "pairs.bin");
    print_vec_of_strings(prices, "prices.bin");
    print_vec_of_strings(timestamps, "timestamps.bin");

    let mut all_hashes = Vec::new();

    for (pair, price, timestamp) in &filtered_items {
        let pair_hash = abi_encode_and_keccak(InputValue::Str(pair.clone()));
        let price_hash = abi_encode_and_keccak(InputValue::U64(*price));
        let timestamp_hash = abi_encode_and_keccak(InputValue::U64(*timestamp));

        // debug info
        tracing::debug!("pair_hash:     0x{}", hex::encode(pair_hash));
        tracing::debug!("price_hash:      0x{}", hex::encode(price_hash));
        tracing::debug!("timestamp_hash: 0x{}", hex::encode(timestamp_hash));
        tracing::debug!("----------------------------------------------");

        all_hashes.extend_from_slice(&pair_hash);
        all_hashes.extend_from_slice(&price_hash);
        all_hashes.extend_from_slice(&timestamp_hash);
    }

    let mut final_hasher = Keccak::v256();
    final_hasher.update(&all_hashes);
    let mut final_hash = [0u8; 32];
    final_hasher.finalize(&mut final_hash);

    tracing::info!("Final hash of all items: 0x{}", hex::encode(final_hash));

    // The following code is used to generate an attestation report
    // Must be run on sgx-supported machine
    let mut data: [u8; 64] = [
        // recognizable pattern can easily be seen in xxd
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8,
        2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8,
        4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8,
        6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
    ];

    data[..32].copy_from_slice(&final_hash);
    // TODO could add hashed request is some form, like pairs list, it is from file, not trusted
    // data[32..].copy_from_slice(&hashed_request);

    let attestation = automata_sgx_sdk::dcap::dcap_quote(data);
    let result = match attestation {
        Ok(attestation) => {
            tracing::info!("DCAP attestation:\n0x{}", hex::encode(&attestation));

            let filename_bytes = create_buffer_from_stirng("sgx_quote.bin".to_string());
            ocall_write_to_file(
                attestation.as_ptr(),
                attestation.len(),
                filename_bytes.as_ptr(),
                filename_bytes.len(),
            );

            SgxStatus::Success
        }
        Err(e) => {
            tracing::error!("Generating attestation failed: {:?}", e);
            SgxStatus::Unexpected
        }
    };
    tracing::debug!("=============== End of trusted execution =================");

    result
}

fn create_buffer_from_stirng(mut input: String) -> Vec<u8> {
    while input.len() % 8 != 0 {
        // needed for pointer alignment
        input.push('\0');
    }
    input.into_bytes()
}

unsafe fn print_vec_of_strings(input: Vec<String>, filename: &str) {
    let joined = input.join("\n");
    let input_bytes = create_buffer_from_stirng(joined.to_string());

    let filename_bytes = create_buffer_from_stirng(filename.to_string());

    ocall_write_to_file(
        input_bytes.as_ptr(),
        input_bytes.len(),
        filename_bytes.as_ptr(),
        filename_bytes.len(),
    );
}

#[derive(Debug)]
enum InputValue {
    Str(String),
    U64(u64),
}

fn abi_encode_and_keccak(input: InputValue) -> [u8; 32] {
    let token = match input {
        InputValue::Str(s) => Token::String(s),
        InputValue::U64(n) => Token::Uint(Uint::from(n)),
    };

    let encoded = encode_packed(token);

    let mut hasher = Keccak::v256();
    hasher.update(&encoded);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    output
}

fn encode_packed(token: Token) -> Vec<u8> {
    match token {
        Token::String(s) => s.into_bytes(),

        Token::Uint(u) => {
            let mut buf = [0u8; 32];
            u.to_big_endian(&mut buf);
            buf.to_vec()
        }

        _ => unimplemented!("encodePacked is not implemented for {:?}", token),
    }
}
