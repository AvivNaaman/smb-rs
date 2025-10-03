//! A genric utility struct to wrap "chained"-encoded entries.
//! Many fscc-query structs have a common "next entry offset" field,
//! which is used to chain multiple entries together.
//! This struct wraps the value, and the offset, and provides a way to iterate over them.
//! See [`ChainedItem<T>::write_chained`] to see how to write this type when in a list.
//!
use std::ops::{Deref, DerefMut};

use binrw::prelude::*;
use smb_dtyp::binrw_util::prelude::*;

const DEFAULT_OFFSET_PAD: u32 = 4;

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(last: bool))]
#[allow(clippy::manual_non_exhaustive)]
pub struct ChainedItem<T, const OFFSET_PAD: u32 = DEFAULT_OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(assert(next_entry_offset.value % OFFSET_PAD == 0))]
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    pub value: T,
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(!last))]
    #[bw(align_before = OFFSET_PAD)]
    #[bw(write_with = PosMarker::write_roff, args(&next_entry_offset))]
    _write_offset_placeholder: (),
}

impl<T, const OFFSET_PAD: u32> ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    pub fn new(value: T) -> Self {
        Self::from(value)
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    #[binrw::writer(writer, endian)]
    #[allow(clippy::ptr_arg)] // writer accepts exact type.
    pub fn write_chained(value: &Vec<ChainedItem<T, OFFSET_PAD>>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            item.write_options(writer, endian, (i == value.len() - 1,))?;
        }
        Ok(())
    }

    /// Write a vector of chained items, and write the size of the vector
    /// to the given `size_dest` position marker.
    #[binrw::writer(writer, endian)]
    #[allow(clippy::ptr_arg)] // writer accepts exact type.
    pub fn write_chained_size(
        value: &Vec<ChainedItem<T, OFFSET_PAD>>,
        size_dest: &PosMarker<u32>,
    ) -> BinResult<()> {
        let pos = writer.stream_position()?;
        for (i, item) in value.iter().enumerate() {
            item.write_options(writer, endian, (i == value.len() - 1,))?;
        }
        size_dest.write_back(pos, writer, endian)?;
        Ok(())
    }

    #[binrw::writer(writer, endian)]
    pub fn write_chained_size_opt(
        value: &Option<Vec<ChainedItem<T, OFFSET_PAD>>>,
        size_dest: &PosMarker<u32>,
    ) -> BinResult<()> {
        if let Some(value) = value {
            Self::write_chained_size(value, writer, endian, (size_dest,))
        } else {
            Ok(())
        }
    }
}

impl<T, const OFFSET_PAD: u32> PartialEq for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite + PartialEq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T, const OFFSET_PAD: u32> Eq for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite + Eq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
}

impl<T, const OFFSET_PAD: u32> Deref for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T, const OFFSET_PAD: u32> From<T> for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(value: T) -> Self {
        Self {
            value,
            _write_offset_placeholder: (),
        }
    }
}

/// Implement a chained item list.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ChainedItemList<T, const OFFSET_PAD: u32 = DEFAULT_OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = ChainedItem::<T, OFFSET_PAD>::write_chained)]
    values: Vec<ChainedItem<T, OFFSET_PAD>>,
}

impl<T, const OFFSET_PAD: u32> From<ChainedItemList<T, OFFSET_PAD>> for Vec<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(list: ChainedItemList<T, OFFSET_PAD>) -> Self {
        list.values.into_iter().map(|i| i.value).collect()
    }
}

impl<T, const OFFSET_PAD: u32> From<Vec<T>> for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(vec: Vec<T>) -> Self {
        Self {
            values: vec.into_iter().map(|v| ChainedItem::from(v)).collect(),
        }
    }
}

impl<T, const OFFSET_PAD: u32> Default for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn default() -> Self {
        Self { values: Vec::new() }
    }
}

impl<T, const OFFSET_PAD: u32> Deref for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Target = Vec<ChainedItem<T, OFFSET_PAD>>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T, const OFFSET_PAD: u32> DerefMut for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<T, const OFFSET_PAD: u32> From<Vec<ChainedItem<T, OFFSET_PAD>>>
    for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(value: Vec<ChainedItem<T, OFFSET_PAD>>) -> Self {
        Self { values: value }
    }
}
