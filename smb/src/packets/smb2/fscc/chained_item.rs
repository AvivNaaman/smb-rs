//! A genric utility struct to wrap "chained"-encoded entries.
//! Many fscc-query structs have a common "next entry offset" field,
//! which is used to chain multiple entries together.
//! This struct wraps the value, and the offset, and provides a way to iterate over them.
//! See [ChainedItem<T>::write_chained] to see how to write this type when in a list.
//!
use std::ops::Deref;

use super::super::super::binrw_util::prelude::*;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(last: bool))]
pub struct ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(assert(next_entry_offset.value % 4 == 0))]
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    value: T,
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(!last))]
    #[bw(align_before = 4)]
    #[bw(write_with = PosMarker::write_roff, args(&next_entry_offset))]
    __: (),
}

impl<T> ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[binrw::writer(writer, endian)]
    pub fn write_chained(value: &Vec<ChainedItem<T>>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            item.write_options(writer, endian, (i == value.len() - 1,))?;
        }
        Ok(())
    }
}

impl<T> PartialEq for ChainedItem<T>
where
    T: BinRead + BinWrite + PartialEq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> Eq for ChainedItem<T>
where
    T: BinRead + BinWrite + Eq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
}

impl<T> Deref for ChainedItem<T>
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

impl<T> From<T> for ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(value: T) -> Self {
        Self { value, __: () }
    }
}
