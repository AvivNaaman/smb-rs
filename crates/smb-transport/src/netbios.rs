//! NetBIOS Session Service (NBSS) transport implementation for SMB.
//!
//! This module provides an implementation of the NetBIOS Session Service (NBSS) transport protocol for SMB.
//! It is enabled by the `netbios` feature flag.

#![cfg(feature = "netbios")]

mod msg;
mod transport;

pub use transport::NetBiosTransport;
