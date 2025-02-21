use crate::sync_helpers::OnceCell;
use binrw::io::SeekFrom;
use binrw::{
    helpers::{read_u24, write_u24},
    prelude::*,
};
use std::{convert::TryFrom, fmt::Debug};

#[derive(Default)]
pub struct PosMarker3Byte {
    pub pos: OnceCell<u64>,
    pub value: u32,
}

impl PosMarker3Byte {
    fn get_pos(&self) -> binrw::BinResult<u64> {
        let value = self.pos.get().ok_or(binrw::error::Error::Custom {
            pos: 0,
            err: Box::new("PosMarker has not been written to yet"),
        })?;
        Ok(*value)
    }
}

impl BinRead for PosMarker3Byte {
    type Args<'a> = ();

    fn read_options<R: binrw::io::Read + binrw::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let pos = reader.stream_position()?;
        read_u24(reader, endian, args).map(|value| Self {
            pos: OnceCell::from(pos),
            value,
        })
    }
}

impl BinWrite for PosMarker3Byte {
    type Args<'a> = ();

    fn write_options<W: binrw::io::Write + binrw::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.pos.set(writer.stream_position()?).map_err(|_| binrw::error::Error::Custom {
            pos: writer.stream_position().unwrap(),
            err: Box::new("PosMarker has already been written to"),
        })?;
        write_u24(&u32::default(), writer, endian, args)
    }
}

impl PosMarker3Byte {
    /// Call this write to fill a PosMarker3Byte value to the size of the wrapped object that was written.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_size<U>(value: &U, this: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let begin_offset = writer.stream_position()?;
        value.write_options(writer, endian, ())?;
        let end_offset = writer.stream_position()?;
        let size_written = end_offset - begin_offset;
        // write the size written back to the position of the PosMarker3Byte.
        let written_bytes_value =
            u32::try_from(size_written).map_err(|err| binrw::error::Error::Custom {
                pos: begin_offset,
                err: Box::new(err),
            })?;
        writer.seek(SeekFrom::Start(this.get_pos()?))?;
        write_u24(&written_bytes_value, writer, endian, ())?;
        writer.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

impl Debug for PosMarker3Byte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PosMarker3Byte")
            .field("pos", &self.pos)
            .field("value", &self.value)
            .finish()
    }
}

impl From<u32> for PosMarker3Byte {
    fn from(value: u32) -> Self {
        Self {
            pos: OnceCell::new(),
            value,
        }
    }
}
