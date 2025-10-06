#[cfg(feature = "quic")]
pub use crate::quic::config::*;
#[cfg(feature = "rdma")]
pub use crate::rdma::config::*;

/// Specifies the transport protocol to be used for the connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// Use TCP transport protocol.
    #[default]
    Tcp,

    #[cfg(feature = "netbios-transport")]
    /// Use NetBIOS over TCP transport protocol.
    NetBios,

    #[cfg(feature = "quic")]
    /// Use SMB over QUIC transport protocol.
    /// Note that this is only supported in dialects 3.1.1 and above.
    Quic(QuicConfig),

    #[cfg(feature = "rdma")]
    Rdma(RdmaConfig),
}
