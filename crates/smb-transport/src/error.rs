use thiserror::Error;

/// Transport-related errors.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Already connected")]
    AlreadyConnected,
    #[error("Invalid transport message")]
    InvalidMessage,
    #[error("Failed to parse transport message {0}")]
    ParseError(#[from] binrw::Error),
    #[error("Not connected")]
    NotConnected,
    #[error("Connection already split")]
    AlreadySplit,
    #[error("Timed out after {}s", .0.as_secs())]
    Timeout(std::time::Duration),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[cfg(feature = "quic")]
    #[error("QUIC error: {0}")]
    QuicError(#[from] crate::quic::QuicError),

    #[cfg(feature = "rdma")]
    #[error("RDMA error: {0}")]
    RdmaError(#[from] crate::rdma::RdmaError),
}

pub type Result<T> = std::result::Result<T, TransportError>;
