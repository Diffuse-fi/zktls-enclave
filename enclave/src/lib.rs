use automata_sgx_sdk::types::SgxStatus;
// For most of the cases, you can use the external library directly.
use serde_json::{Value, json, Map};
// use std::vec::Vec;
use std::string::String;
// use std::slice;
use tiny_keccak::Keccak;
use tiny_keccak::Hasher;
use hex;

// Declare the OCALL function. The automata_sgx_sdk will link the OCALL to the mock_lib.

extern "C" {
    fn ocall_http_request(
        symbols: *const u8,
        symbols_len: usize,
        result: *mut u8,
        result_max_len: usize,
        actual_len: *mut usize,
        http_status: *mut u16
    );
}

extern "C" {
    fn ocall_write_to_file(
        data_bytes: *const u8,
        data_len: usize,
        filename_bytes: *const u8,
        filename_len: usize
    );
}

extern "C" {
    fn ocall_read_from_file(
        pairs_list_buffer: *mut u8,
        pairs_list_buffer_len: usize,
        pairs_list_actual_len: *mut usize
    );
}

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
        &mut pairs_list_actual_len as *mut usize
    );

    let currency_pairs_raw_str = String::from_utf8_lossy(&pairs_list_buffer[..pairs_list_actual_len]);

    let currency_pairs: Vec<String> = currency_pairs_raw_str
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let currency_pairs_bytes = create_buffer_from_stirng(json!(currency_pairs).to_string());


    let mut result_buffer: [u8; 16384] = [0; 16384];
    let mut actual_len: usize = 0;
    let mut http_status: u16 = 0;

    ocall_http_request(
        currency_pairs_bytes.as_ptr(),
        currency_pairs_bytes.len(),
        result_buffer.as_mut_ptr(),
        result_buffer.len(),
        &mut actual_len as *mut usize,
        &mut http_status as *mut u16
    );

    if http_status != 200u16  {
        println!("Failed to fetch data from Binance with http status {}", http_status);
        return SgxStatus::Unexpected;
    }

    let response = String::from_utf8_lossy(&result_buffer[..actual_len]);
    println!("Response from Binance: {}", response);

    let json_from_server: Value = serde_json::from_str(&response)
        .expect("Failed to parse JSON");

    // We don't need to output the data exactly as it came from the server.
    // The enclave content is trusted, so why not output JSON in a convenient form?
    let mut processed_prices = Map::new();

    json_from_server.as_array()
        .expect("Expected JSON array")
        .iter()
        .filter(|item| {
            item["symbol"].as_str()
            .map(|s| currency_pairs.contains(&s.to_string()))
                .unwrap_or(false)
        })
        .for_each(|item| {
            let symbol = item["symbol"].as_str().unwrap_or_default();

    processed_prices.insert(
        symbol.to_string(),
        json!({
            "price": item["lastPrice"],
            "closeTime": item["closeTime"]
        })
        );
    });

    let processed_prices_value = Value::Object(processed_prices);

    let processed_json_bytes = serde_json::to_vec_pretty(&processed_prices_value)
        .expect("Failed to serialize JSON");
    println! ("processed_json: {}", String::from_utf8_lossy(&processed_json_bytes));

    // There is only 64 bytes of user data in the enclave, server response cannot fit
    // we write to enclave only its hash to ensure that output is authentic
    let filename_bytes = create_buffer_from_stirng("requested_prices.bin".to_string());
    ocall_write_to_file (
        processed_json_bytes.as_ptr(),
        processed_json_bytes.len(),
        filename_bytes.as_ptr(),
        filename_bytes.len()
    );

    let mut hasher = Keccak::v256();
    hasher.update(&processed_json_bytes);
    let mut hashed_response = [0u8; 32];
    hasher.finalize(&mut hashed_response);

    let hashed_response_str = hex::encode(hashed_response);
    println!("hashed_response_str: {}", hashed_response_str);

    // The following code is used to generate an attestation report
    // Must be run on sgx-supported machine
    let mut data: [u8; 64] = [ // recognizable pattern can easily be seen in xxd
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8
        ];

    data[..32].copy_from_slice(&hashed_response);
    // TODO could add hashed request is some form, like pairs list, it is from file, not trusted
    // data[32..].copy_from_slice(&hashed_request);

    println!("Data: {:x?}", data);

    let attestation = automata_sgx_sdk::dcap::dcap_quote(data);
    let result = match attestation {
        Ok(attestation) => {
            println!("DCAP attestation: 0x{}", hex::encode(&attestation));

            let filename_bytes = create_buffer_from_stirng("sgx_quote.bin".to_string());
            ocall_write_to_file (
                attestation.as_ptr(),
                attestation.len(),
                filename_bytes.as_ptr(),
                filename_bytes.len()
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
    while input.len() % 8 != 0 { // needed for pointer allignment
        input.push('\0');
    }
    input.into_bytes()
}