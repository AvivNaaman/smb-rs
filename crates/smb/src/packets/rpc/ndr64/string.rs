use std::{fmt::Display, str::FromStr};

use super::align::*;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[br(import_raw(args: <E as BinRead>::Args<'_>))]
#[bw(import_raw(args: <E as BinWrite>::Args<'_>))]
pub struct NdrString<E, const SIZE: u32 = 0>
where
    E: BinRead + BinWrite + Clone + 'static,
    for<'a> <E as BinRead>::Args<'a>: Clone,
    for<'a> <E as BinWrite>::Args<'a>: Clone,
{
    // This is only for non-conformant strings -
    // strings that have a variable allocation size.
    // for conformant strings, const SIZE is non-zero!
    #[bw(if(SIZE == 0), calc = Some((data.len() as u64).into()))]
    #[br(if(SIZE == 0))]
    alloc_length: Option<NdrAlign<u64>>,

    #[bw(calc = 0.into())]
    #[br(assert(*offset == 0))] // TODO: Support non-zero offsets!
    offset: NdrAlign<u64>,
    #[bw(calc = (data.len() as u64).into())]
    #[br(assert((SIZE == 0 || *actual_count < SIZE as u64) || *actual_count < { *(alloc_length.unwrap()) }
    ))]
    actual_count: NdrAlign<u64>,
    #[br(count = *actual_count, args { inner: args })]
    #[bw(args_raw(args))]
    pub data: NdrAlign<Vec<E>>,
}

impl<E> NdrAligned for NdrString<E>
where
    E: BinRead + BinWrite + Clone + 'static,
    for<'a> <E as BinRead>::Args<'a>: Clone,
    for<'a> <E as BinWrite>::Args<'a>: Clone,
{
}

// String to NdrString<u16> conversion:
impl FromStr for NdrString<u16, 0> {
    type Err = std::string::FromUtf16Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data: Vec<u16> = s
            .encode_utf16()
            .chain(
                std::iter::once(0), // Null terminator
            )
            .collect();
        Ok(Self {
            data: NdrAlign { value: data },
        })
    }
}

impl<const SIZE: u32> Display for NdrString<u16, SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = self.data.value.iter().map(|&c| c as u8 as char).collect();
        write!(f, "{s}")
    }
}
