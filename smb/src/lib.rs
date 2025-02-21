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

pub mod compression;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod msg_handler;
pub mod packets;
pub mod resource;
pub mod session;
pub mod tree;

pub use connection::Connection;
pub use error::Error;

type Result<T> = std::result::Result<T, crate::Error>;

// Re-exports of some dependencies for convenience
mod sync_helpers;
