extern crate core;

mod error;
mod tcp_stream_oc;
mod tls;

use std::{fmt::Debug, string::String};

use automata_sgx_sdk::types::SgxStatus;
use ethabi::{Token, Uint};
use hex;
use serde_json::{json, Value};
use tiny_keccak::{Hasher, Keccak};

use crate::{tcp_stream_oc::UntrustedTcpStreamPtr, tls::tls_request};

extern "C" {
    fn ocall_get_tcp_stream(server_address: *const u8, stream_ptr: *mut UntrustedTcpStreamPtr);
    fn ocall_tcp_write(stream_ptr: UntrustedTcpStreamPtr, data: *const u8, data_len: usize);
    fn ocall_tcp_read(
        stream_ptr: UntrustedTcpStreamPtr,
        buffer: *mut u8,
        max_len: usize,
        read_len: *mut usize,
    );

    fn ocall_write_to_file(
        data_bytes: *const u8,
        data_len: usize,
        filename_bytes: *const u8,
        filename_len: usize,
    );

    fn ocall_read_from_file(
        pairs_list_buffer: *mut u8,
        pairs_list_buffer_len: usize,
        pairs_list_actual_len: *mut usize,
    );
}

pub(crate) const BINANCE_API_HOST: &str = "data-api.binance.vision";

/**
 * This is an ECALL function defined in the edl file.
 * It will be called by the application.
 */
#[no_mangle]
pub unsafe extern "C" fn trusted_execution() -> SgxStatus {
    println!("=============== Trusted execution =================");
    println!("form a request inside the TEE");

    // data can be passed betwen enclave and outer world only with byte arrays
    let mut pairs_list_buffer: [u8; 8192] = [0; 8192];
    let mut pairs_list_actual_len: usize = 0;

    ocall_read_from_file(
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

    let response_str = match tls_request(BINANCE_API_HOST.to_string(), currency_pairs_bytes) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Error encountered in TLS request: {e}");
            return SgxStatus::Unexpected;
        }
    };

    let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        eprintln!("Unexpected response format");
        return SgxStatus::Unexpected;
    }

    let json_body = parts[1].trim();

    let json_from_server: Value = serde_json::from_str(json_body).expect("Failed to parse JSON");

    // We don't need to output the data exactly as it came from the server.
    // The enclave content is trusted, so why not output JSON in a convenient form?

    let filtered_items: Vec<(String, u64, u64)> = json_from_server
        .as_array()
        .expect("Expected JSON array")
        .iter()
        .filter_map(|item| {
            let pair = item["symbol"].as_str()?;

            println!("let pair: {}", pair);

            println!(
                "currency_pairs.contains(&pair.to_string()): {}",
                currency_pairs.contains(&pair.to_string())
            );

            if !currency_pairs.contains(&pair.to_string()) {
                println!("!currency_pairs.contains(&pair.to_string())");
                return None;
            }

            let price_str = item["lastPrice"].as_str()?;
            let integer_and_fractional: Vec<&str> = price_str.split('.').collect();

            if integer_and_fractional.len() != 2 {
                panic!("price is not float number!");
            }

            let integer: u64 = integer_and_fractional[0]
                .parse()
                .expect("Failed to parse integer part");
            let fractional: u64 = integer_and_fractional[1]
                .parse()
                .expect("Failed to parse fractional part");

            let mut price: u64 = integer * 100000000;
            const HARDCODED_DECIMALS: u32 = 8;
            let decimal_points: u32 = integer_and_fractional[1]
                .chars()
                .count()
                .try_into()
                .unwrap();
            assert!(
                decimal_points <= HARDCODED_DECIMALS,
                "price decimal points <= 8 are hardcoded"
            ); // TODO 8 hardcoded

            price += fractional * 10u64.pow(HARDCODED_DECIMALS - decimal_points);

            let timestamp = item["closeTime"].as_u64()?;

            println!("pair: {}", pair);
            println!("price: {}", price);
            println!("timestamp: {}", timestamp);

            Some((pair.to_string(), price, timestamp))
        })
        .collect();

    println!("filtered_items:{:?}", filtered_items);

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

    println!("pairs:     {:?}", pairs);
    println!("Prices:      {:?}", prices);
    println!("Close times: {:?}", timestamps);

    print_vec_of_strings(pairs, "pairs.bin");
    print_vec_of_strings(prices, "prices.bin");
    print_vec_of_strings(timestamps, "timestamps.bin");

    let mut all_hashes = Vec::new();

    for (pair, price, timestamp) in &filtered_items {
        let pair_hash = abi_encode_and_keccak(InputValue::Str(pair.clone()));
        let price_hash = abi_encode_and_keccak(InputValue::U64(*price));
        let timestamp_hash = abi_encode_and_keccak(InputValue::U64(*timestamp));

        // debug info
        println!("pair_hash:     0x{}", hex::encode(pair_hash));
        println!("price_hash:      0x{}", hex::encode(price_hash));
        println!("timestamp_hash: 0x{}", hex::encode(timestamp_hash));
        println!("----------------------------------------------");

        all_hashes.extend_from_slice(&pair_hash);
        all_hashes.extend_from_slice(&price_hash);
        all_hashes.extend_from_slice(&timestamp_hash);
    }

    let mut final_hasher = Keccak::v256();
    final_hasher.update(&all_hashes);
    let mut final_hash = [0u8; 32];
    final_hasher.finalize(&mut final_hash);

    println!("Final hash of all items: 0x{}", hex::encode(final_hash));

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
            println!("DCAP attestation: 0x{}", hex::encode(&attestation));

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
            println!("Generating attestation failed: {:?}", e);
            SgxStatus::Unexpected
        }
    };
    println!("=============== End of trusted execution =================");

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
