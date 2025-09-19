/// Specifies the transport protocol to be used for the connection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// Use TCP transport protocol.
    #[default]
    Tcp,
    /// Use NetBIOS over TCP transport protocol.
    NetBios,
    #[cfg(feature = "quic")]
    /// Use SMB over QUIC transport protocol.
    /// Note that this is only suported in dialects 3.1.1 and above.
    Quic(QuicConfig),

    #[cfg(feature = "rdma")]
    Rdma(RdmaConfig),
}

#[cfg(feature = "quic")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicConfig {
    pub local_address: Option<SocketAddr>,
    pub cert_validation: QuicCertValidationOptions,
}

#[cfg(feature = "rdma")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RdmaConfig {}
