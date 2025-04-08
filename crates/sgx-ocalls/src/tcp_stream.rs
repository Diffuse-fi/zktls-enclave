use std::{
    fmt::Debug,
    io::{Read, Write},
};

use crate::bindings::{ocall_tcp_read, ocall_tcp_write, UntrustedTcpStreamPtr};

/// A safe wrapper for an untrusted TCP stream obtained via OCALLs.
pub struct TcpStreamOc {
    stream_ptr: UntrustedTcpStreamPtr,
}

impl TcpStreamOc {
    pub fn new(stream_ptr: UntrustedTcpStreamPtr) -> Self {
        TcpStreamOc { stream_ptr }
    }
}

impl Default for TcpStreamOc {
    fn default() -> Self {
        TcpStreamOc {
            stream_ptr: core::ptr::null_mut(),
        }
    }
}

impl Read for TcpStreamOc {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_len: usize = 0;
        unsafe {
            ocall_tcp_read(
                self.stream_ptr,
                buf.as_mut_ptr(),
                buf.len(),
                &mut read_len as *mut usize,
            );
        }
        Ok(read_len)
    }
}

impl Write for TcpStreamOc {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe {
            ocall_tcp_write(self.stream_ptr, buf.as_ptr(), buf.len());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Debug for TcpStreamOc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TcpStreamOc {{ stream_ptr: {:?} }}", self.stream_ptr)
    }
}

unsafe impl Send for TcpStreamOc {}
unsafe impl Sync for TcpStreamOc {}
