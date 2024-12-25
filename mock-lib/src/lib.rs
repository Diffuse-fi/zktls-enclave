use reqwest::blocking::Client;
use std::slice;
use std::fs;

#[no_mangle]
pub fn ocall_http_request(
    symbols: *const u8,
    symbols_len: usize,
    result: *mut u8,
    result_max_len: usize,
    actual_len: *mut usize,
    http_status: *mut u16
) {
    println!("=============== Untrusted http_request =================");
    let symbols_slice = unsafe { slice::from_raw_parts(symbols, symbols_len) };
    let symbols_str = match std::str::from_utf8(symbols_slice) {
        Ok(s) => {
            println! ("parsed request params");
            println! ("{}", s);
            s.trim_end_matches('\0')
        },
        Err(_) => {
            println! ("failed to parse request params outside the TEE");
            return;
        },
    };

    let base_url = "https://data-api.binance.vision";
    let endpoint = "/api/v3/ticker/24hr";
    let url = format!("{}{}", base_url, endpoint);

    let client = Client::new();
    let res = client.get(&url)
        .query(&[("symbols", symbols_str)])
        .send();

    match res {
        Ok(response) => {
            let status_code = response.status().as_u16();
            let body = response.text().unwrap_or_else(|_| "Error".to_string());
            let body_bytes = body.as_bytes();

            assert! (body_bytes.len() <= result_max_len, "http response does not fit into buffer");
            unsafe {
                std::ptr::copy_nonoverlapping(body_bytes.as_ptr(), result, body_bytes.len());
                *actual_len = body_bytes.len();
                *http_status = status_code;
            }
            println! ("status_code: {}", status_code);

        }
        Err(err) => {
            let status = err.status().expect("Status must be present");
            unsafe {*http_status = status.as_u16();}
        }
    }

    println!("=============== End of untrusted http_request =================");
}


#[no_mangle]
pub fn ocall_write_to_file(
    data_buffer: *const u8,
    data_len: usize,
    filename_buffer: *const u8,
    filename_len: usize,
) {
    println!("=============== Untrusted write_to_file =================");
    let data: &[u8] = unsafe {
        assert!(!data_buffer.is_null(), "Data pointer is null");
        slice::from_raw_parts(data_buffer, data_len)
    };

    let filename: &[u8] = unsafe {
        assert!(!filename_buffer.is_null(), "Filename pointer is null");
        slice::from_raw_parts(filename_buffer, filename_len)
    };

    let filename_str_raw = std::str::from_utf8(filename).expect("unable to read string from filename buffer");
    let filename_str =  filename_str_raw.trim_end_matches('\0');

    fs::write(filename_str, data).expect("Failed to write bytes to file");

    println!("=============== End of untrusted write_to_file =================");
}

#[no_mangle]
pub fn ocall_read_from_file(
    pairs_list_buffer: *mut u8,
    pairs_list_buffer_len: usize,
    pairs_list_actual_len: *mut usize
) {
    println!("=============== Untrusted read_from_file =================");

    let pairs_list_path = "pairs/list.txt";

    let pairs_list = fs::read(pairs_list_path).expect("Unable to read file");

    assert! (pairs_list.len() <= pairs_list_buffer_len, "pairs list does not fit into pairs_list_buffer!");
    unsafe {
        std::ptr::copy_nonoverlapping(pairs_list.as_ptr(), pairs_list_buffer, pairs_list.len());
        *pairs_list_actual_len = pairs_list.len();
    }

    println!("=============== End of untrusted read_from_file =================");
}
