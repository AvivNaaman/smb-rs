use std::{num::TryFromIntError, sync::PoisonError};

use thiserror::Error;

use crate::{
    UncPath,
    connection::TransformError,
    packets::smb2::{Command, ErrorResponse, NegotiateDialect, Status},
    sync_helpers::AcquireError,
};

#[derive(Debug)]
pub enum TimedOutTask {
    TcpConnect,
    QuicConnect,
    ReceiveNextMessage,
}

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
    #[error("Unexpected message status: {}.", Status::try_display_as_status(*.0))]
    UnexpectedMessageStatus(u32),
    // TODO: This vs UnexpectedMessageStatus?!
    #[error("Server returned an error message with status: {}.", Status::try_display_as_status(*.0))]
    ReceivedErrorMessage(u32, ErrorResponse),
    #[error("Unexpected command: {0}")]
    UnexpectedMessageCommand(Command),
    #[error("Unexpected content: {0} - expected {1}", actual, expected)]
    UnexpectedContent {
        actual: &'static str,
        expected: &'static str,
    },
    #[error("Missing permissions to perform {0}")]
    MissingPermissions(String),
    #[error("Sspi error: {0}")]
    SspiError(#[from] sspi::Error),
    #[error("Url parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Unsupported authentication mechanism: {0}")]
    UnsupportedAuthenticationMechanism(String),
    #[error("Compression error: {0}")]
    CompressionError(#[from] crate::compression::CompressionError),
    #[error("Message processing failed. {0}")]
    MessageProcessingError(String),
    #[error("Operation timed out: {0:?}, took >{1:?}")]
    OperationTimeout(TimedOutTask, std::time::Duration),
    #[error("Lock error.")]
    LockError,
    #[cfg(feature = "async")]
    #[error("Task join error.")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Acquire Error: {0}")]
    AcquireError(#[from] AcquireError),
    #[cfg(not(feature = "async"))]
    #[error("Thread join error: {0}")]
    JoinError(String),
    #[cfg(not(feature = "async"))]
    #[error("Channel recv error.")]
    ChannelRecvError(#[from] std::sync::mpsc::RecvError),
    #[error("Unexpected message with ID {0} (exp {1}).")]
    UnexpectedMessageId(u64, u64),
    #[error("Expected info of type {0} but got {1}")]
    UnexpectedInformationType(u8, u8),
    #[error("Invalid endpoint {0}")]
    InvalidAddress(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("SMB Operation Cancelled: {0}")]
    Cancelled(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("Unable to connect to DFS referrals for: {0}")]
    DfsReferralConnectionFail(UncPath),
    #[error("Not found: {0}")]
    NotFound(String),

    // -- QUIC --
    #[cfg(feature = "quic")]
    #[error("QUIC start connect error: {0}")]
    QuicConnectError(#[from] quinn::ConnectError),
    #[cfg(feature = "quic")]
    #[error("QUIC connection error: {0}")]
    QuicConnectionError(#[from] quinn::ConnectionError),
    #[cfg(feature = "quic")]
    #[error("QUIC write error: {0}")]
    QuicWriteError(#[from] quinn::WriteError),
    #[cfg(feature = "quic")]
    #[error("QUIC read error: {0}")]
    QuicReadError(#[from] quinn::ReadExactError),
    #[cfg(feature = "quic")]
    #[error("TLS error: {0}")]
    TlsError(#[from] rustls::Error),
    #[cfg(feature = "quic")]
    #[error("No cipher suites found")]
    NoCipherSuitesFound(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::LockError
    }
}
