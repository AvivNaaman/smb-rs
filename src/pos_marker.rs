use std::{fmt::Debug, io::SeekFrom};

use binrw::{BinRead, BinResult, BinWrite};

/**
 * Source: https://github.com/jam1garner/binrw/discussions/229
 */
pub struct PosMarker<T> {
    pub pos: core::cell::Cell<u64>,
    pub value: T,
}

impl<T> BinRead for PosMarker<T>
where
    T: BinRead,
{
    type Args<'a> = T::Args<'a>;

    fn read_options<R: binrw::io::Read + binrw::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let pos = reader.stream_position()?;
        T::read_options(reader, endian, args).map(|value| Self {
            pos: core::cell::Cell::new(pos),
            value,
        })
    }
}

impl<T> BinWrite for PosMarker<T>
where
    T: BinWrite<Args<'static> = ()> + Default,
{
    type Args<'a> = ();

    fn write_options<W: binrw::io::Write + binrw::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.pos.set(writer.stream_position()?);
        T::default().write_options(writer, endian, args)
    }
}

impl<T> PosMarker<T>
where
    T: BinWrite<Args<'static> = ()> + TryFrom<u64>,
    T::Error: binrw::error::CustomError + 'static,
{
    /// Call this write to fill a PosMarker value to the position of the written value.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_start_offset<U>(value: &U, this: &Self) -> BinResult<()>
    where U : BinWrite<Args<'static> = ()> {
        let pos = writer.stream_position()?;
        let offset_value = T::try_from(pos).map_err(|err| binrw::error::Error::Custom {
            pos,
            err: Box::new(err),
        })?;
        writer.seek(SeekFrom::Start(this.pos.get()))?;
        // Write back the offset value
        offset_value.write_options(writer, endian, ())?;
        // Get back to the end of the file
        writer.seek(SeekFrom::End(0))?;
        // Continue writing the real value this writer is specified for
        value.write_options(writer, endian, ())
    }

    /// Call this write to fill a PosMarker value to the size of the wrapped object that was written.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_size<U>(value: &U, this: &Self) -> BinResult<()>
    where U : BinWrite<Args<'static> = ()> {
        let begin_offset = writer.stream_position()?;
        value.write_options(writer, endian, ())?;
        let end_offset = writer.stream_position()?;
        let size_written = end_offset - begin_offset;
        // write the size written back to the position of the PosMarker.
        let written_bytes_value = T::try_from(size_written).map_err(|err| binrw::error::Error::Custom {
            pos: begin_offset,
            err: Box::new(err),
        })?;
        writer.seek(SeekFrom::Start(this.pos.get()))?;
        written_bytes_value.write_options(writer, endian, ())?;
        writer.seek(SeekFrom::End(0))?;
        Ok(())
    }
}


impl PosMarker<u32> {
    #[binrw::writer(writer, endian)]
    pub fn write_u24(self: &PosMarker<u32>) -> BinResult<()> {
        self.pos.set(writer.stream_position()?);
        binrw::helpers::write_u24(&self.value, writer, endian, ())
    }

    #[binrw::parser(reader, endian)]
    pub fn read_u24() -> BinResult<PosMarker<u32>> {
        let pos = reader.stream_position()?;
        binrw::helpers::read_u24(reader, endian, ()).map(|value| Self {
            pos: core::cell::Cell::new(pos),
            value,
        })
    }
}

impl<T> Debug for PosMarker<T>
    where T: Debug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PosMarker")
            .field("pos", &self.pos)
            .field("value", &self.value)
            .finish()
    }
}


impl<T> Default for PosMarker<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            pos: core::cell::Cell::new(0),
            value: T::default(),
        }
    }
}