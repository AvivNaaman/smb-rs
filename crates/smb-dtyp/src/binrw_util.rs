//! This module contains utility types for the binrw crate.

pub mod boolean;
pub mod debug;
pub mod file_time;
pub mod fixed_string;
pub mod helpers;
pub mod multi_sz;
pub mod pos_marker;
pub mod sized_string;

pub mod prelude {
    pub use super::boolean::Boolean;
    #[cfg(debug_assertions)]
    pub use super::debug::LogLocation;
    pub use super::file_time::FileTime;
    pub use super::helpers::*;
    pub use super::multi_sz::MultiWSz;
    pub use super::pos_marker::PosMarker;
    pub use super::sized_string::{
        BaseSizedString, BaseSizedStringReadArgs, BaseSizedStringReadArgsBuilder, SizedAnsiString,
        SizedStringSize, SizedWideString,
    };
}
