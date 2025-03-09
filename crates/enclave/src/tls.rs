use std::{
    ffi::CString,
    io::{Read, Write},
    ptr,
    sync::Arc,
};

use automata_sgx_sdk::types::SgxStatus;
use rustls::{pki_types::ServerName, ClientConnection, RootCertStore, StreamOwned};

use crate::{
    error::SgxResult, ocall_get_tcp_stream, tcp_stream_oc::TcpStreamOc, UntrustedTcpStreamPtr,
};

pub(crate) fn tls_request<S: AsRef<str>, T: AsRef<str>>(
    server_host_name: S,
    symbols: T,
) -> SgxResult<String> {
    let (mut connection, mut tcp_stream) = open_connection(server_host_name.as_ref())?;

    tracing::info!("Handshaking with {}", server_host_name.as_ref());
    handshake(&mut connection, &mut tcp_stream)?;
    tracing::info!("Is handshake done : {:?}", !connection.is_handshaking());
    tracing::info!("TLS version: {:?}", connection.protocol_version());

    let symbols_request_bytes = generate_request(symbols, server_host_name);
    tracing::debug!(
        "Sending request: {:?}",
        String::from_utf8_lossy(&symbols_request_bytes)
    );

    let resp = request_symbols(connection, tcp_stream, &symbols_request_bytes);
    tracing::info!("Is response fine : {}", resp.is_ok());
    resp
}

/// We are using the default rustls configuration, including patched version of ['_ring_'] crate.
fn open_connection<S: AsRef<str>>(
    server_host_name: S,
) -> SgxResult<(ClientConnection, TcpStreamOc)> {
    let server_name = ServerName::try_from(server_host_name.as_ref().to_string())?;
    let address_cstr = CString::new(server_host_name.as_ref().to_string() + ":443")?;
    let mut stream_ptr: UntrustedTcpStreamPtr = ptr::null_mut();

    // TODO: remove this call, create TcpStream directly
    unsafe {
        ocall_get_tcp_stream(
            address_cstr.as_ptr() as *const u8,
            &mut stream_ptr as *mut UntrustedTcpStreamPtr,
        );
    }
    if stream_ptr.is_null() {
        tracing::error!("Failed to get tcp stream");
        return Err(SgxStatus::Unexpected.into());
    }
    let tcp_stream_oc = TcpStreamOc::new(stream_ptr);

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connection = ClientConnection::new(Arc::new(config), server_name)?;

    Ok((connection, tcp_stream_oc))
}

fn handshake(connection: &mut ClientConnection, tcp_stream: &mut TcpStreamOc) -> SgxResult<()> {
    while connection.is_handshaking() {
        tracing::debug!("Handshake in progress...");
        if connection.wants_write() {
            tracing::debug!("Handshake in progress... write");
            let mut buf = Vec::new();
            connection.write_tls(&mut buf)?;
            tcp_stream.write_all(&buf)?;
        }
        if connection.wants_read() {
            tracing::debug!("Handshake in progress... read");
            let mut buf = vec![0u8; 4096];
            let bytes_read = tcp_stream.read(&mut buf)?;
            if bytes_read == 0 {
                break;
            }
            buf.truncate(bytes_read);
            connection.read_tls(&mut &buf[..])?;
        }
        connection.process_new_packets()?;
    }

    Ok(())
}

fn request_symbols(
    connection: ClientConnection,
    tcp_stream: TcpStreamOc,
    request: &[u8],
) -> SgxResult<String> {
    let mut tls = StreamOwned::new(connection, tcp_stream);

    tls.write_all(request)?;
    tls.flush()?;

    let mut resp_vec = Vec::new();
    tls.read_to_end(&mut resp_vec)?;

    Ok(String::from_utf8(resp_vec)?)
}

fn generate_request<S: AsRef<str>, T: AsRef<str>>(symbols: S, server_host_name: T) -> Vec<u8> {
    format!(
        "GET /api/v3/ticker/24hr?symbols={} HTTP/1.1\r\n\
         Host: {}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\r\n",
        symbols.as_ref(),
        server_host_name.as_ref()
    )
    .into_bytes()
}
