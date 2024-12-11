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
    pub fn fill<U>(_: &U, this: &Self) -> BinResult<()> {
        let pos = writer.stream_position()?;
        let value = T::try_from(pos).map_err(|err| binrw::error::Error::Custom {
            pos,
            err: Box::new(err),
        })?;
        writer.seek(SeekFrom::Start(this.pos.get()))?;
        value.write_options(writer, endian, ())
    }
}

impl Debug for PosMarker<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PosMarker")
            .field("pos", &self.pos)
            .field("value", &self.value)
            .finish()
    }
}