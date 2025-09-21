use std::time::Duration;

pub mod config;
pub mod error;
pub mod iovec;
pub mod netbios;
pub mod quic;
pub mod rdma;
pub mod tcp;
pub mod traits;
pub mod utils;

pub use config::*;
pub use error::TransportError;
pub use iovec::*;
#[cfg(feature = "netbios")]
pub use netbios::*;
#[cfg(feature = "quic")]
pub use quic::*;
#[cfg(feature = "rdma")]
pub use rdma::*;
pub use tcp::{SmbTcpMessageHeader, TcpTransport};
pub use traits::*;

/// Creates [`SmbTransport`] out of [`TransportConfig`].
///
/// ## Arguments
/// * `transport` - The transport configuration to make the transport by.
/// * `timeout` - The timeout duration to use for the transport.
pub fn make_transport(
    transport: &TransportConfig,
    timeout: Duration,
) -> Result<Box<dyn SmbTransport>, TransportError> {
    match transport {
        TransportConfig::Tcp => Ok(Box::new(tcp::TcpTransport::new(timeout))),
        TransportConfig::NetBios => Ok(Box::new(NetBiosTransport::new(timeout))),

        #[cfg(feature = "quic")]
        TransportConfig::Quic(quic_config) => {
            Ok(Box::new(quic::QuicTransport::new(quic_config, timeout)?))
        }

        #[cfg(feature = "rdma")]
        TransportConfig::Rdma(_rdma_config) => Ok(Box::new(RdmaTransport::new(timeout))),
    }
}

// Force async if QUIC/RDMA are enabled
#[cfg(all(feature = "is_sync", feature = "quic"))]
compile_error!(
    "QUIC transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);
#[cfg(all(feature = "is_sync", feature = "rdma"))]
compile_error!(
    "RDMA transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);
