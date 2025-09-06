use std::time::Duration;

use super::TransportConfig;

pub mod nb;
pub mod quic;
pub mod tcp;
pub mod traits;
pub mod utils;

pub use traits::*;

/// Creates [`SmbTransport`] out of [`TransportConfig`].
///
/// ## Arguments
/// * `transport` - The transport configuration to make the transport by.
/// * `timeout` - The timeout duration to use for the transport.
pub fn make_transport(
    transport: &TransportConfig,
    timeout: Duration,
) -> crate::Result<Box<dyn SmbTransport>> {
    match transport {
        TransportConfig::Tcp => Ok(Box::new(tcp::TcpTransport::new(timeout))),
        #[cfg(feature = "quic")]
        TransportConfig::Quic(quic_config) => {
            Ok(Box::new(quic::QuicTransport::new(quic_config, timeout)?))
        }
        #[cfg(not(feature = "quic"))]
        TransportConfig::Quic(_) => Err(crate::Error::InvalidState(
            "Quic transport is not available in this build.".into(),
        )),
        TransportConfig::NetBios => Ok(Box::new(nb::NetBiosTransport::new(timeout))),
    }
}
