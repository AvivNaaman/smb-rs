#![cfg(feature = "quic")]

//! SMB over QUIC transport for SMB.

pub mod config;
mod error;
mod transport;

pub use config::QuicConfig;
pub use error::QuicError;
pub use transport::QuicTransport;
