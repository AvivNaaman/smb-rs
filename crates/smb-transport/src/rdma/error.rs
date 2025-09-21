use thiserror::Error;

#[derive(Error, Debug)]
pub enum RdmaError {
    #[error("SMBD negotiation error: {0}")]
    NegotiateError(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Already connected")]
    AlreadyConnected,
    #[error("Not connected")]
    NotConnected,
    #[error("Request data too large. Requested size: {0}, max size allowed: {1}")]
    RequestTooLarge(usize, usize),
    #[error("Failed to parse SMB message: {0}")]
    SmbdParseError(#[from] binrw::Error),
    #[error("Invalid endpoint format: {0}")]
    InvalidEndpoint(String),
}

pub type Result<T> = std::result::Result<T, RdmaError>;