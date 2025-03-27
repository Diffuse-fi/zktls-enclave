use std::{
    fmt::Debug,
    io::{Read, Write},
};

use crate::error::TlsResult;

pub trait TcpProvider<S: AsRef<str>>: Debug {
    type Stream: Read + Write;
    fn get(&mut self, server_address: S) -> TlsResult<Self::Stream>;
}

pub trait FileProvider<S: AsRef<str>>: Debug {
    fn write_to_file(&self, data: &[u8], filename: S);
    fn read_from_file(&self, filename: S) -> Vec<u8>;
}

pub trait RequestProvider<S: AsRef<str>>: Debug {
    fn get_request(&self, server_address: S) -> Vec<u8>;
}
