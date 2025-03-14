use std::{
    fmt::Debug,
    io::{Read, Write},
};

use crate::{ocall_tcp_read, ocall_tcp_write};

pub(crate) type UntrustedTcpStreamPtr = *mut core::ffi::c_void;

pub struct TcpStreamOc {
    stream_ptr: UntrustedTcpStreamPtr,
}

impl TcpStreamOc {
    pub fn new(stream_ptr: UntrustedTcpStreamPtr) -> Self {
        TcpStreamOc { stream_ptr }
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
        write!(f, "TcpStreamOc")
    }
}

unsafe impl Send for TcpStreamOc {}
unsafe impl Sync for TcpStreamOc {}
