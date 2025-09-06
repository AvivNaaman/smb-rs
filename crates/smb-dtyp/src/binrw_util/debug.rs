#![cfg(debug_assertions)]
//! This module contains a debug utility for logging read/write positions in binrw operations.

use binrw::prelude::*;

/// Prints the current stream position for debugging purposes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogLocation {}

impl BinRead for LogLocation {
    type Args<'a> = ();
    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<Self> {
        dbg!(("Reading log location is: ", reader.stream_position()?));
        Ok(LogLocation {})
    }
}
impl BinWrite for LogLocation {
    type Args<'a> = ();
    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        _endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        dbg!(("Writing log location is: ", writer.stream_position()?));
        Ok(())
    }
}
