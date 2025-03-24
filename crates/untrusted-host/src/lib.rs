extern crate core;

use core::slice;
use std::{
    ffi::CStr,
    fs,
    io::{Read, Write},
    net::TcpStream,
    os::raw::c_char,
    ptr,
    time::Duration,
};

const DEFAULT_TCP_TIMEOUT_SEC: u64 = 5;

// # Safety
// The caller must ensure that the `server_address` is a valid C string.
// The caller must ensure that the `stream_ptr` is a valid pointer to a pointer.
#[no_mangle]
pub unsafe extern "C" fn ocall_get_tcp_stream(
    server_address: *const u8,
    stream_ptr: *mut *mut core::ffi::c_void,
) {
    tracing::debug!("=============== Untrusted get_tcp_stream =================");
    let cstr = CStr::from_ptr(server_address as *const c_char);
    let address = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => {
            *stream_ptr = ptr::null_mut();
            return;
        }
    };
    tracing::debug!("Tcp connection for {}", address);

    match TcpStream::connect(address) {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TCP_TIMEOUT_SEC)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(DEFAULT_TCP_TIMEOUT_SEC)));
            let boxed_stream = Box::new(stream);

            let raw_stream = Box::into_raw(boxed_stream) as *mut core::ffi::c_void;
            ptr::write_unaligned(stream_ptr, raw_stream);
        }
        Err(e) => {
            tracing::error!("ocall_get_tcp_stream failed: {}", e);
            *stream_ptr = ptr::null_mut();
        }
    }
    tracing::debug!("=============== End of untrusted get_tcp_stream =================");
}

// # Safety
// The caller must ensure that the `stream_ptr` is a valid pointer to a TcpStream.
// The caller must ensure that the `data` is a valid pointer to a buffer of `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ocall_tcp_write(
    stream_ptr: *mut core::ffi::c_void,
    data: *const u8,
    data_len: usize,
) {
    tracing::debug!("=============== Untrusted tcp_write =================");
    if stream_ptr.is_null() {
        return;
    }
    let stream = &mut *(stream_ptr as *mut TcpStream);
    let slice = slice::from_raw_parts(data, data_len);
    let _ = stream
        .write(slice)
        .inspect_err(|e| tracing::error!("ocall_tcp_write error: {}", e))
        .unwrap_or_default();
    tracing::debug!("=============== End of untrusted tcp_write =================");
}

// # Safety
// The caller must ensure that the `stream_ptr` is a valid pointer to a TcpStream.
// The caller must ensure that the `buffer` is a valid pointer to a buffer of `max_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ocall_tcp_read(
    stream_ptr: *mut core::ffi::c_void,
    buffer: *mut u8,
    max_len: usize,
    read_len: *mut usize,
) {
    tracing::debug!("=============== Untrusted tcp_read =================");
    if stream_ptr.is_null() {
        *read_len = 0;
        return;
    }
    let stream = &mut *(stream_ptr as *mut TcpStream);
    let buf = slice::from_raw_parts_mut(buffer, max_len);
    let stream_read_len = stream
        .read(buf)
        .inspect_err(|e| tracing::error!("ocall_tcp_read error: {}", e))
        .unwrap_or_default();
    ptr::write_unaligned(read_len, stream_read_len);
    tracing::debug!("=============== End of untrusted tcp_read =================");
}

// # Safety
#[no_mangle]
pub unsafe fn ocall_write_to_file(
    data_buffer: *const u8,
    data_len: usize,
    filename_buffer: *const u8,
    filename_len: usize,
) {
    tracing::debug!("=============== Untrusted write_to_file =================");
    assert!(!data_buffer.is_null(), "Data pointer is null");

    let data: &[u8] = slice::from_raw_parts(data_buffer, data_len);

    assert!(!filename_buffer.is_null(), "Filename pointer is null");
    let filename: &[u8] = slice::from_raw_parts(filename_buffer, filename_len);

    let filename_str_raw =
        std::str::from_utf8(filename).expect("unable to read string from filename buffer");
    let filename_str = filename_str_raw.trim_end_matches('\0');

    fs::write(filename_str, data).expect("Failed to write bytes to file");

    tracing::debug!("=============== End of untrusted write_to_file =================");
}

#[no_mangle]
pub unsafe fn ocall_read_from_file(
    filename_bytes: *const u8,
    pairs_list_buffer: *mut u8,
    pairs_list_buffer_len: usize,
    pairs_list_actual_len: *mut usize,
) {
    tracing::debug!("=============== Untrusted read_from_file =================");

    let cstr = CStr::from_ptr(filename_bytes as *const c_char);
    let filename = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("Failed to read filename from buffer");
            return;
        }
    };

    tracing::info!("Reading from file: {}", filename);
    let pairs_list = fs::read(filename).expect("Unable to read file");

    assert!(
        pairs_list.len() <= pairs_list_buffer_len,
        "pairs list does not fit into pairs_list_buffer!"
    );
    ptr::copy_nonoverlapping(pairs_list.as_ptr(), pairs_list_buffer, pairs_list.len());
    ptr::write_unaligned(pairs_list_actual_len, pairs_list.len());

    tracing::debug!("=============== End of untrusted read_from_file =================");
}
