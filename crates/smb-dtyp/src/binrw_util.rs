//! This module contains utility types for the binrw crate.

pub mod debug;
pub mod file_time;
pub mod helpers;
pub mod pos_marker;
pub mod sized_wide_string;

pub mod prelude {
    #[cfg(debug_assertions)]
    pub use super::debug::LogLocation;
    pub use super::file_time::FileTime;
    pub use super::helpers::*;
    pub use super::pos_marker::PosMarker;
    pub use super::sized_wide_string::{SizedAnsiString, SizedWideString};
}
