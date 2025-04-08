use core::ffi::c_void;

pub type UntrustedTcpStreamPtr = *mut c_void;

extern "C" {
    pub fn ocall_get_tcp_stream(server_address: *const u8, stream_ptr: *mut UntrustedTcpStreamPtr);

    pub fn ocall_tcp_write(stream_ptr: UntrustedTcpStreamPtr, data: *const u8, data_len: usize);

    pub fn ocall_tcp_read(
        stream_ptr: UntrustedTcpStreamPtr,
        buffer: *mut u8,
        max_len: usize,
        read_len: *mut usize,
    );

    pub fn ocall_write_to_file(
        data_bytes: *const u8,
        data_len: usize,
        filename_bytes: *const u8,
        filename_len: usize,
    );

    pub fn ocall_read_from_file(
        filename_bytes: *const u8,
        pairs_list_buffer: *mut u8,
        pairs_list_buffer_len: usize,
        pairs_list_actual_len: *mut usize,
    );
}
