use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Tls(#[from] rustls::Error),

    #[error(transparent)]
    Ffi(#[from] std::ffi::NulError),

    #[error(transparent)]
    DnsName(#[from] rustls::pki_types::InvalidDnsNameError),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub type TlsResult<T> = Result<T, TlsError>;
