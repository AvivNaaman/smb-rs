use binrw::{BinRead, BinResult, BinWrite, Endian};
use std::{fmt::Debug, io::SeekFrom, sync::OnceLock};

/**
 * Source: <https://github.com/jam1garner/binrw/discussions/229>
 */
#[derive(Default, PartialEq, Eq)]
pub struct PosMarker<T> {
    pub pos: OnceLock<u64>,
    pub value: T,
}

impl<T> PosMarker<T> {
    /// Create a new PosMarker with the given value.
    pub fn new(value: T) -> Self {
        Self {
            pos: OnceLock::new(),
            value,
        }
    }

    /// Returns a [SeekFrom] that seeks relative from the position of the PosMarker.
    pub fn seek_from(&self, offset: u64) -> SeekFrom {
        SeekFrom::Start(self.pos.get().unwrap() + offset)
    }

    fn get_pos(&self) -> binrw::BinResult<u64> {
        let value = self.pos.get().ok_or(binrw::error::Error::Custom {
            pos: 0,
            err: Box::new("PosMarker has not been written to yet"),
        })?;
        Ok(*value)
    }
}

impl<T> PosMarker<T>
where
    T: Into<u64> + Copy,
{
    /// This function assumes the PosMarker is used to describe an offset from it's location.
    /// You can use it to get a `SeekFrom` to seek to the position described by the PosMarker
    pub fn try_seek_relative(&self, zero_check: bool) -> BinResult<SeekFrom> {
        let pos = SeekFrom::Start(self.get_pos()? + self.value.into());
        Ok(if !zero_check || Into::<u64>::into(self.value) > 0 {
            pos
        } else {
            SeekFrom::Current(0)
        })
    }

    /// Just like [try_seek_relative](Self::try_seek_relative), but unwraps the result.
    pub fn seek_relative(&self, zero_check: bool) -> SeekFrom {
        self.try_seek_relative(zero_check).unwrap()
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
            pos: OnceLock::from(pos),
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
        self.pos
            .set(writer.stream_position()?)
            .map_err(|_| binrw::error::Error::Custom {
                pos: writer.stream_position().unwrap(),
                err: Box::new("PosMarker has already been written to"),
            })?;
        T::default().write_options(writer, endian, args)
    }
}

impl<T> PosMarker<T>
where
    T: BinWrite<Args<'static> = ()> + TryFrom<u64>,
    T::Error: binrw::error::CustomError + 'static,
{
    const NO_EXTRA_SIZE: u64 = 0;
    const NO_EXTRA_OFFSET: u64 = 0;

    /// Move back the writer, update the written value and return to the end of the file.
    ///
    /// # Arguments
    /// * value: The value to write.
    /// * writer: The writer to write to ([binrw::io::Write] + [binrw::io::Seek])
    /// * endian: The endian to write with ([binrw::Endian])
    pub fn write_back<V, W>(&self, value: V, writer: &mut W, endian: Endian) -> BinResult<()>
    where
        V: TryInto<T> + std::fmt::Debug,
        W: binrw::io::Write + binrw::io::Seek,
    {
        let return_to = writer.stream_position()?;
        writer.seek(SeekFrom::Start(self.get_pos()?))?;
        value
            .try_into()
            .map_err(|_| binrw::error::Error::Custom {
                pos: self.get_pos().unwrap(),
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
    /// * size_plus: An additional size to add to the written size. This is useful for writing
    ///     the size of a structure that includes the size of the structure itself.
    #[inline]
    #[binrw::writer(writer, endian)]
    fn write_hero<V, S, B>(
        value: &V,
        write_size_to: Option<&Self>,
        write_offset_to: Option<&PosMarker<S>>,
        offset_relative_to: Option<&PosMarker<B>>,
        value_args: V::Args<'_>,
        size_plus: u64,
        offset_plus: u64,
    ) -> BinResult<()>
    where
        V: BinWrite,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        // Write offset if needed
        let start_offset = writer.stream_position()?;
        if let Some(write_offset_at) = write_offset_to {
            // Is there a base offset marker? Subtract it from the current position.
            let base_offset_val = match offset_relative_to {
                Some(offset_base) => offset_base.get_pos()?,
                None => 0,
            };
            let offset_to_write = start_offset - base_offset_val + offset_plus;
            write_offset_at.write_back(offset_to_write, writer, endian)?;
        };

        // Write the underlying value
        value.write_options(writer, endian, value_args)?;

        let total_size = writer.stream_position()? - start_offset;
        // Write size if needed
        if let Some(write_size_to) = write_size_to {
            write_size_to.write_back(total_size + size_plus, writer, endian)?
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
            (
                no_size,
                Some(write_offset_to),
                Some(write_offset_to),
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }

    /// Writer for value
    /// * fill relative offset to offset location.
    /// * add extra size to the written offset.
    ///     useful for writing the offset of a structure that includes the size of the structure itself.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_plus<U>(value: &U, write_offset_to: &Self, plus: u64) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_size: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (
                no_size,
                Some(write_offset_to),
                Some(write_offset_to),
                (),
                Self::NO_EXTRA_SIZE,
                plus,
            ),
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
            (
                no_size,
                Some(write_offset_to),
                Some(offset_relative_to),
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }

    /// Writer for value
    /// * fill relative offset to offset location.
    /// * fill written size to size location.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_size_b<U, S, B>(
        value: &U,
        write_offset_to: &PosMarker<S>,
        write_size_to: &Self,
        offset_relative_to: &PosMarker<B>,
    ) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        Self::write_hero(
            value,
            writer,
            endian,
            (
                Some(write_size_to),
                Some(write_offset_to),
                Some(offset_relative_to),
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
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
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
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
            (
                no_size,
                Some(write_offset_to),
                no_base,
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }
    /// Writer for value
    /// * fill absolute offset to offset location.
    #[binrw::writer(writer, endian)]
    pub fn write_aoff_m<U>(value: &U, write_offset_to: Option<&Self>) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_size: Option<&PosMarker<T>> = None;
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (
                no_size,
                write_offset_to,
                no_base,
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }

    /// Writer for value
    /// * fill absolute offset to offset location.
    /// * with value args.
    #[binrw::writer(writer, endian)]
    pub fn write_aoff_a<U>(
        value: &U,
        write_offset_to: &Self,
        value_args: U::Args<'_>,
    ) -> BinResult<()>
    where
        U: BinWrite,
    {
        let no_size: Option<&PosMarker<T>> = None;
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (
                no_size,
                Some(write_offset_to),
                no_base,
                value_args,
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }

    /// Writer for value
    /// * fill absolute offset to offset location.
    /// * fill written size to size location.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_size<U, S>(
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
            (
                Some(write_size_to),
                Some(write_offset_to),
                no_base,
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }

    /// Writer for value
    /// * fill absolute offset to offset location.
    /// * fill written size to size location.
    /// * add extra size to the written **offset**.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_size_b_plus<U, S, B>(
        value: &U,
        write_offset_to: &PosMarker<S>,
        write_size_to: &Self,
        offset_relative_to: &PosMarker<B>,
        offset_plus: u64,
    ) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        Self::write_hero(
            value,
            writer,
            endian,
            (
                Some(write_size_to),
                Some(write_offset_to),
                Some(offset_relative_to),
                (),
                Self::NO_EXTRA_SIZE,
                offset_plus,
            ),
        )
    }

    /// Writer for value
    /// * fill relative offset to offset location.
    /// * fill written size to size location.
    /// * with value args.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_size_a<U, S>(
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
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
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
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
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
            (
                Some(write_size_to),
                Some(write_offset_to),
                no_base,
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
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
            (
                Some(write_size_to),
                no_offset,
                no_offset,
                (),
                Self::NO_EXTRA_SIZE,
                Self::NO_EXTRA_OFFSET,
            ),
        )
    }

    /// Writer for value
    /// * fill written size to size location.
    /// * add extra size to the written size.
    ///     useful for writing the size of a structure that includes the size of the structure itself.
    #[binrw::writer(writer, endian)]
    pub fn write_size_plus<U>(value: &U, write_size_to: &Self, extra_size: u64) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_offset: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (
                Some(write_size_to),
                no_offset,
                no_offset,
                (),
                extra_size,
                Self::NO_EXTRA_OFFSET,
            ),
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
