use std::{fmt::Debug, io::SeekFrom};

use binrw::{BinRead, BinResult, BinWrite, Endian};

/**
 * Source: https://github.com/jam1garner/binrw/discussions/229
 */
pub struct PosMarker<T> {
    pub pos: core::cell::Cell<u64>,
    pub value: T,
}

impl<T> PosMarker<T>
where
    T: Into<u64> + Copy,
{
    /// This function assumes the PosMarker is used to describe an offset from it's location.
    /// You can use it to get a `SeekFrom` to seek to the position described by the PosMarker
    pub fn seek_relative(&self, zero_check: bool) -> SeekFrom {
        debug_assert!(self.pos.get() != u64::MAX); // sanity
        let pos = SeekFrom::Start(self.pos.get() + self.value.into());
        if !zero_check || Into::<u64>::into(self.value) > 0 {
            pos
        } else {
            SeekFrom::Current(0)
        }
    }
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
    /// Move back the writer, update the written value and return to the end of the file.
    ///
    /// # Arguments
    /// * value: The value to write.
    /// * writer: The writer to write to ([binrw::io::Write] + [binrw::io::Seek])
    /// * endian: The endian to write with ([binrw::Endian])
    pub fn write_back<V, W>(&self, value: V, writer: &mut W, endian: Endian) -> BinResult<()>
    where
        V: TryInto<T>,
        W: binrw::io::Write + binrw::io::Seek,
    {
        let return_to = writer.stream_position()?;
        writer.seek(SeekFrom::Start(self.pos.get()))?;
        value
            .try_into()
            .map_err(|_| binrw::error::Error::Custom {
                pos: self.pos.get(),
                err: Box::new("Error converting value to T"),
            })?
            .write_options(writer, endian, ())?;
        writer.seek(SeekFrom::Start(return_to))?;
        Ok(())
    }

    /// This is the hero function that does all the fun writing stuff.
    ///
    /// This function should be inlined to make unused arguments disappear on some cases.
    ///
    /// # Arguments
    /// * value: The value to wrap when writing.
    /// * write_size_at: If Some, write the size of the wrapped value at this position.
    /// * write_offset_at: If Some, write the offset of the wrapped value at this position.
    /// * offset_relative_to: If Some, subtract this value from the current position to get the offset.
    ///     For example, if set to None, this will set write_offset_at to the absolute position of the written value from
    ///     the beginning of the stream. If it's set to write_offset_at, it will write the offset relative to the position
    ///     of the field referred to by write_offset_at.
    /// * args: The arguments to pass to the wrapped value's write function.
    #[inline]
    #[binrw::writer(writer, endian)]
    fn write_hero<V, S, B>(
        value: &V,
        write_size_to: Option<&Self>,
        write_offset_to: Option<&PosMarker<S>>,
        offset_relative_to: Option<&PosMarker<B>>,
        value_args: V::Args<'_>,
    ) -> BinResult<()>
    where
        V: BinWrite,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        // Write offset if needed
        let start_offset = writer.stream_position()?;
        match write_offset_to {
            Some(write_offset_at) => {
                // Is there a base offset marker? Subtract it from the current position.
                let base_offset_val = match offset_relative_to {
                    Some(offset_base) => offset_base.pos.get(),
                    None => 0,
                };
                let offset_to_write = start_offset - base_offset_val;
                write_offset_at.write_back(offset_to_write, writer, endian)?;
            }
            None => (),
        };

        // Write the underlying value
        value.write_options(writer, endian, value_args)?;

        let total_size = writer.stream_position()? - start_offset;
        // Write size if needed
        match write_size_to {
            Some(write_size_to) => write_size_to.write_back(total_size, writer, endian)?,
            None => (),
        };
        Ok(())
    }

    /// Writer for value
    /// * fill relative offset to offset location.
    #[binrw::writer(writer, endian)]
    pub fn write_roff<U>(value: &U, write_offset_to: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_size: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (no_size, Some(write_offset_to), Some(write_offset_to), ()),
        )
    }

    /// A utillity function that writes the current offset to the current PosMarker.
    pub fn write_offset<W>(&self, writer: &mut W, endian: Endian) -> BinResult<u64>
    where
        W: binrw::io::Write + binrw::io::Seek,
    {
        let stream_position = writer.stream_position()?;
        self.write_back(stream_position, writer, endian)?;
        Ok(stream_position)
    }

    /// Writer for value
    /// * fill relative offset to offset location relative to base.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_b<U, B>(
        value: &U,
        write_offset_to: &Self,
        offset_relative_to: &PosMarker<B>,
    ) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_size: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (no_size, Some(write_offset_to), Some(offset_relative_to), ()),
        )
    }

    /// Writer for value,
    /// * fill relative offset to offset location relative to base.
    /// * fill written size to size location.
    /// * with value args.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_size_ba<U, B, S>(
        value: &U,
        write_offset_to: &Self,
        write_size_to: &PosMarker<S>,
        offset_relative_to: &PosMarker<B>,
        value_args: U::Args<'_>,
    ) -> BinResult<()>
    where
        U: BinWrite,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        PosMarker::<S>::write_hero(
            value,
            writer,
            endian,
            (
                Some(write_size_to),
                Some(write_offset_to),
                Some(offset_relative_to),
                value_args,
            ),
        )
    }

    /// Writer for value
    /// * fill absolute offset to offset location.
    #[binrw::writer(writer, endian)]
    pub fn write_aoff<U>(value: &U, write_offset_to: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_size: Option<&PosMarker<T>> = None;
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (no_size, Some(write_offset_to), no_base, ()),
        )
    }

    /// Writer for value
    /// * fill absolute offset to offset location.
    /// * fill written size to size location.
    /// * with value args.
    #[binrw::writer(writer, endian)]
    pub fn write_aoff_size_a<U, S>(
        value: &U,
        write_offset_to: &PosMarker<S>,
        write_size_to: &Self,
        value_args: U::Args<'_>,
    ) -> BinResult<()>
    where
        U: BinWrite,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (
                Some(write_size_to),
                Some(write_offset_to),
                no_base,
                value_args,
            ),
        )
    }

    #[binrw::writer(writer, endian)]
    pub fn write_aoff_size<U, S>(
        value: &U,
        write_offset_to: &PosMarker<S>,
        write_size_to: &Self,
    ) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (Some(write_size_to), Some(write_offset_to), no_base, ()),
        )
    }

    /// Writer for value
    /// * fill written size to size location.
    #[binrw::writer(writer, endian)]
    pub fn write_size<U>(value: &U, write_size_to: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_offset: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (Some(write_size_to), no_offset, no_offset, ()),
        )
    }
}

impl<T> Debug for PosMarker<T>
where
    T: Debug,
{
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
            pos: core::cell::Cell::new(u64::MAX),
            value: T::default(),
        }
    }
}
