use std::time::Duration;

use super::TransportConfig;

pub mod netbios;
pub mod quic;
pub mod rdma;
pub mod tcp;
pub mod traits;
pub mod utils;

pub use traits::*;

pub fn make_transport(
    transport: &TransportConfig,
    timeout: Duration,
) -> crate::Result<Box<dyn SmbTransport>> {
    match transport {
        TransportConfig::Tcp => Ok(Box::new(tcp::TcpTransport::new(timeout))),
        #[cfg(feature = "quic")]
        TransportConfig::Quic(quic_config) => Ok(Box::new(quic::QuicTransport::new(quic_config)?)),
        #[cfg(not(feature = "quic"))]
        TransportConfig::Quic(_) => Err(crate::Error::InvalidState(
            "Quic transport is not available in this build.".into(),
        )),
        TransportConfig::NetBios => Ok(Box::new(netbios::NetBiosTransport::new(timeout))),
    }
}

// Force async if QUIC is enabled
#[cfg(all(not(feature = "async"), feature = "quic"))]
compile_error!(
    "QUIC transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);
