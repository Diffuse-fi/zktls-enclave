use std::{ffi::CString, fmt::Debug, ptr};

use tls_enclave::{
    error::TlsResult,
    traits::{RequestProvider, TcpProvider},
};

use crate::{ocalls::ocall_get_tcp_stream, tcp_stream_oc::TcpStreamOc, UntrustedTcpStreamPtr};

#[derive(Debug)]
pub(crate) struct ZkTlsPairs {
    pub(crate) server_address: String,
    pub(crate) requested_symbols: String,
    pub(crate) stream_ptr: TcpStreamOc,
}

impl ZkTlsPairs {
    pub fn new(server_address: String, requested_symbols: String) -> Self {
        let address_cstr =
            CString::new(format!("{server_address}:443")).expect("Failed to create CString");
        let mut stream_ptr: UntrustedTcpStreamPtr = ptr::null_mut();

        unsafe {
            ocall_get_tcp_stream(
                address_cstr.as_ptr() as *const u8,
                &mut stream_ptr as *mut UntrustedTcpStreamPtr,
            );
        }

        if stream_ptr.is_null() {
            panic!("Failed to create TCP stream");
        }

        ZkTlsPairs {
            server_address,
            requested_symbols,
            stream_ptr: TcpStreamOc::new(stream_ptr),
        }
    }
}

impl<S: AsRef<str>> RequestProvider<S> for ZkTlsPairs {
    fn get_request(&self, server_address: S) -> Vec<u8> {
        format!(
            "GET /api/v3/ticker/24hr?symbols={} HTTP/1.1\r\n\
            Host: {}\r\n\
            Accept: application/json\r\n\
            Connection: close\r\n\r\n",
            self.requested_symbols,
            server_address.as_ref()
        )
        .into_bytes()
    }
}

impl<S: AsRef<str>> TcpProvider<S> for ZkTlsPairs {
    type Stream = TcpStreamOc;

    fn get(&mut self, server_address: S) -> TlsResult<Self::Stream> {
        assert_eq!(
            self.server_address,
            server_address.as_ref(),
            "Server address mismatch"
        );
        Ok(std::mem::take(&mut self.stream_ptr))
    }
}
