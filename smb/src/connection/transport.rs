use std::time::Duration;

use super::TransportConfig;

pub mod error;
pub mod netbios;
pub mod quic;
pub mod rdma;
pub mod tcp;
pub mod traits;
pub mod utils;

pub use error::TransportError;
pub use traits::*;

pub fn make_transport(
    transport: &TransportConfig,
    timeout: Duration,
) -> Result<Box<dyn SmbTransport>, TransportError> {
    match transport {
        TransportConfig::Tcp => Ok(Box::new(tcp::TcpTransport::new(timeout))),
        #[cfg(feature = "quic")]
        TransportConfig::Quic(quic_config) => Ok(Box::new(quic::QuicTransport::new(quic_config)?)),
        #[cfg(feature = "rdma")]
        TransportConfig::Rdma => Ok(Box::new(rdma::RdmaTransport::new())),
        TransportConfig::NetBios => Ok(Box::new(netbios::NetBiosTransport::new(timeout))),
    }
}

// Force async if QUIC/RDMA are enabled
#[cfg(all(not(feature = "async"), feature = "quic"))]
compile_error!(
    "QUIC transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);
#[cfg(all(not(feature = "async"), feature = "rdma"))]
compile_error!(
    "RDMA transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);
