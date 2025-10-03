//! RDMA transport for SMB.
#![cfg(feature = "rdma")]

pub mod config;
mod error;
mod smbd;
mod transport;

pub use config::RdmaConfig;
pub use error::RdmaError;
pub use transport::RdmaTransport;
