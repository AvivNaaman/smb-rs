use std::num::TryFromIntError;

use thiserror::Error;

use crate::{
    connection::TransformError,
    packets::smb2::{Command, ErrorResponse, NegotiateDialect, Status},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsupported dialect revision")]
    UnsupportedDialect(NegotiateDialect),
    #[error("Unexpected Message, {0}")]
    InvalidMessage(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Binrw Error: {0}")]
    BinRWError(#[from] binrw::Error),
    #[error("Int parsing Error: {0}")]
    ParsingError(#[from] TryFromIntError),
    #[error("Client is not connected.")]
    NotConnected,
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Unable to transform message: {0}")]
    TranformFailed(TransformError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),
    #[error("Negotiation error: {0}")]
    NegotiationError(String),
    #[error("Signature verification failed!")]
    SignatureVerificationFailed,
    #[error("Unexpected message status: {0}")]
    UnexpectedMessageStatus(Status),
    #[error("Server returned an error message.")]
    RecievedErrorMessage(ErrorResponse),
    #[error("Unexpected command: {0}")]
    UnexpectedCommand(Command),
    #[error("Missing permissions to perform {0}")]
    MissingPermissions(String),
    #[error("Sspi error: {0}")]
    SspiError(#[from] sspi::Error),
    #[error("DER error: {0}")]
    DerError(#[from] der::Error),
    #[error("Unsupported authentication mechanism: {0}")]
    UnsupportedAuthenticationMechanism(String),
    #[error("Compression error: {0}")]
    CompressionError(#[from] crate::compression::CompressionError),
    #[error("Username error: {0}")]
    UsernameError(String),
    #[error("Message processing failed. {0}")]
    MessageProcessingError(String)
}
