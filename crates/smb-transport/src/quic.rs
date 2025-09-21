#![cfg(feature = "quic")]

//! SMB over QUIC transport for SMB.

mod transport;
pub mod config;
mod error;

pub use transport::{QuicTransport};
pub use error::QuicError;
pub use config::QuicConfig;