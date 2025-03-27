pub mod error;
pub mod traits;

use std::{
    io::{Read, Write},
    sync::Arc,
};

use rustls::{pki_types::ServerName, ClientConnection, RootCertStore, StreamOwned};

use crate::{
    error::TlsResult,
    traits::{RequestProvider, TcpProvider},
};

pub fn tls_request<S: AsRef<str> + Clone, P>(
    server_host_name: S,
    mut provider: P,
) -> TlsResult<String>
where
    P: RequestProvider<S> + TcpProvider<S>,
{
    tracing::info!("Handshaking with {}", server_host_name.as_ref());
    let (mut connection, mut tcp_stream) =
        open_connection(server_host_name.clone(), &mut provider)?;

    handshake(&mut connection, &mut tcp_stream)?;
    tracing::info!("Is handshake done : {:?}", !connection.is_handshaking());
    tracing::info!("TLS version: {:?}", connection.protocol_version());

    let symbols_request_bytes = provider.get_request(server_host_name);

    tracing::debug!(
        "Sending request: {:?}",
        String::from_utf8_lossy(&symbols_request_bytes)
    );

    let resp = request_symbols::<S, P>(connection, tcp_stream, &symbols_request_bytes);
    tracing::info!("Is response fine : {}", resp.is_ok());
    resp
}

/// We are using the default rustls configuration, including patched version of ['_ring_'] crate.
fn open_connection<S: AsRef<str>, P>(
    server_host_name: S,
    tcp_provider: &mut P,
) -> TlsResult<(ClientConnection, P::Stream)>
where
    P: TcpProvider<S>,
{
    let server_name = ServerName::try_from(server_host_name.as_ref().to_string())?;
    let tcp_stream = tcp_provider.get(server_host_name)?;
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connection = ClientConnection::new(Arc::new(config), server_name)?;

    Ok((connection, tcp_stream))
}

fn handshake(
    connection: &mut ClientConnection,
    tcp_stream: &mut (impl Read + Write),
) -> TlsResult<()> {
    while connection.is_handshaking() {
        if connection.wants_write() {
            let mut buf = Vec::new();
            connection.write_tls(&mut buf)?;
            tcp_stream.write_all(&buf)?;
        }
        if connection.wants_read() {
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

fn request_symbols<S: AsRef<str>, T: TcpProvider<S>>(
    connection: ClientConnection,
    tcp_stream: T::Stream,
    request: &[u8],
) -> TlsResult<String> {
    let mut tls = StreamOwned::new(connection, tcp_stream);

    tls.write_all(request)?;
    tls.flush()?;

    let mut resp_vec = Vec::new();
    match tls.read_to_end(&mut resp_vec) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !resp_vec.is_empty() => {}
        Err(e) => return Err(e.into()),
    }

    Ok(String::from_utf8(resp_vec)?)
}
