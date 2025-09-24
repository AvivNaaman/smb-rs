use std::net::{SocketAddr, ToSocketAddrs};

pub struct TransportUtils;
use crate::TransportError;

impl TransportUtils {
    /// Parses a string endpoint into a [SocketAddr]. If no port is specified, port 0 is used.
    /// Returns [TransportError::InvalidAddress] if the address is invalid or cannot be resolved
    pub fn parse_socket_address(endpoint: &str) -> super::error::Result<SocketAddr> {
        let mut endpoint = endpoint.to_owned();
        if !endpoint.contains(':') {
            endpoint += ":0";
        }
        let mut socket_addrs = endpoint
            .to_socket_addrs()
            .map_err(|_| TransportError::InvalidAddress(endpoint.to_string()))?;
        socket_addrs
            .next()
            .ok_or(TransportError::InvalidAddress(endpoint))
    }
}
