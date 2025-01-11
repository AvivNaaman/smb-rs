//! This module contains utility types for the binrw crate.

pub mod pos_marker;
pub mod pos_marker_3byte;
pub mod sized_wide_string;

pub mod prelude {
    pub use super::pos_marker::PosMarker;
    pub use super::pos_marker_3byte::PosMarker3Byte;
    pub use super::sized_wide_string::SizedWideString;
}