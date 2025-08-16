//! smb-rs is a pure rust SMB2/3 client.

#[cfg(not(any(
    feature = "async",
    feature = "single_threaded",
    feature = "multi_threaded"
)))]
compile_error!(
    "You must enable exactly one of the following features: async, single_threaded, multi_threaded"
);
#[cfg(any(
    all(feature = "async", feature = "single_threaded"),
    all(feature = "async", feature = "multi_threaded"),
    all(feature = "single_threaded", feature = "multi_threaded")
))]
compile_error!(
    "You must enable exactly one of the following features: async, single_threaded, multi_threaded"
);

pub mod client;
pub mod compression;
pub mod connection;
pub mod crypto;
pub mod dialects;
pub mod docs;
pub mod error;
pub mod msg_handler;
pub mod packets;
pub mod resource;
pub mod session;
pub mod tree;

pub use client::{Client, ClientConfig, UncPath};
pub use connection::{Connection, ConnectionConfig};
pub use error::Error;
pub use resource::{Directory, File, FileCreateArgs, Resource};
pub use session::Session;
pub use tree::{DfsRootTreeRef, Tree};

pub type Result<T> = std::result::Result<T, crate::Error>;

// Re-exports of some dependencies for convenience
pub mod sync_helpers;
