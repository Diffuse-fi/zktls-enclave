use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum SgxError {
    #[error(transparent)]
    Sgx(#[from] automata_sgx_sdk::types::SgxStatus),

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
}

pub(crate) type SgxResult<T> = Result<T, SgxError>;
