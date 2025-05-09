use std::net::{SocketAddr, ToSocketAddrs};

pub struct TransportUtils;

impl TransportUtils {
    pub fn parse_socket_address(endpoint: &str) -> crate::Result<SocketAddr> {
        let mut socket_addrs = endpoint
            .to_socket_addrs()
            .map_err(|_| crate::Error::InvalidAddress(endpoint.to_string()))?;
        socket_addrs
            .next()
            .ok_or(crate::Error::InvalidAddress(endpoint.to_string()))
    }

    pub fn get_server_name(endpoint: &str) -> crate::Result<String> {
        let mut parts = endpoint.split(':');
        let server_name = parts
            .next()
            .ok_or(crate::Error::InvalidAddress(endpoint.to_string()))?;
        Ok(server_name.to_string())
    }
}
