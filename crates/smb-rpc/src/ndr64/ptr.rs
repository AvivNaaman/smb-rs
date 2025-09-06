use std::ops::{Deref, DerefMut};

use super::align::*;
use binrw::{endian, prelude::*};

pub const REF_ID_UNIQUE_DEFAULT: u64 = 0x20000;
pub const NULL_PTR_REF_ID: u64 = 0x0;

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum NdrPtrReadMode {
    // Default: do not write in multi stages (ref id, data)
    #[default]
    NoArraySupport,
    // Write in two stages: first write the reference ID, then write the data.
    // This should generally be used by internal Ndr64 structures.
    WithArraySupport,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum NdrPtrWriteStage {
    #[default]
    NoArraySupport,
    ArraySupportWriteRefId,
    ArraySupportWriteData,
}

/// Ndr represents a pointer.
///
/// *Note*: This is only aligned if the type argument `T` is aligned!
#[derive(Debug, Default, PartialEq, Eq)]
pub enum NdrPtr<T>
where
    for<'a, 'b> T: BinRead + BinWrite,
{
    // read started, with no value yet.
    #[default]
    Uninit,
    // read started, with a reference ID read.
    RefIdRead(u64),
    // read done, with a value resolved.
    Resolved(Option<NdrAlign<T>>),
}

impl<T> BinRead for NdrPtr<T>
where
    T: BinRead + BinWrite + 'static,
{
    type Args<'a> = (
        Option<&'a Self>,
        NdrPtrReadMode,
        <NdrAlign<Option<T>> as BinRead>::Args<'a>,
    );

    fn read_options<R: binrw::io::Read + binrw::io::Seek>(
        reader: &mut R,
        endian: endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let (parent, read_mode, align_args) = args;
        match read_mode {
            NdrPtrReadMode::NoArraySupport => {
                debug_assert!(
                    parent.is_none(),
                    "NdrPtrReadMode::NoArraySupport does not support parent pointers"
                );
                let ref_id = NdrAlign::<u64>::read_options(reader, endian, ())?;
                let value = if *ref_id != NULL_PTR_REF_ID {
                    debug_assert!(
                        *ref_id == REF_ID_UNIQUE_DEFAULT,
                        "Reference ID must be unique when read_mode is NoArraySupport"
                    );
                    Some(NdrAlign::<T>::read_options(reader, endian, align_args)?)
                } else {
                    None
                };

                Ok(Self::Resolved(value))
            }
            NdrPtrReadMode::WithArraySupport => match parent {
                Some(p) => {
                    debug_assert!(
                        matches!(p, Self::RefIdRead(_)),
                        "Parent pointer must be in RefIdRead state when read_mode is WithArraySupport"
                    );
                    // If parent pointer is in ArrayRefIdRead state, we read the reference ID
                    let ref_id = match p {
                        Self::RefIdRead(ref_id) => *ref_id,
                        _ => panic!("Parent pointer must be in ArrayRefIdRead state"),
                    };

                    let value = if ref_id != NULL_PTR_REF_ID {
                        debug_assert!(
                            ref_id == REF_ID_UNIQUE_DEFAULT,
                            "Reference ID must be unique when read_mode is NoArraySupport"
                        );
                        Some(NdrAlign::<T>::read_options(reader, endian, align_args)?)
                    } else {
                        None
                    };

                    Ok(Self::Resolved(value))
                }
                None => {
                    // Read reference ID and assign into the state.
                    let ref_id = NdrAlign::<u64>::read_options(reader, endian, ())?;
                    Ok(Self::RefIdRead(*ref_id))
                }
            },
        }
    }
}

pub struct NdrPtrWriteArgs<'a, T>(
    pub NdrPtrWriteStage,
    pub <NdrAlign<Option<T>> as BinWrite>::Args<'a>,
)
where
    T: BinRead + BinWrite + 'static;

impl<T> Default for NdrPtrWriteArgs<'_, T>
where
    T: BinRead + BinWrite + 'static,
    for<'a> <T as BinWrite>::Args<'a>: Default,
{
    fn default() -> Self {
        Self(NdrPtrWriteStage::NoArraySupport, Default::default())
    }
}

impl<T> BinWrite for NdrPtr<T>
where
    T: BinRead + BinWrite + 'static,
{
    type Args<'a> = NdrPtrWriteArgs<'a, T>;

    fn write_options<W: binrw::io::Write + binrw::io::Seek>(
        &self,
        writer: &mut W,
        endian: endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let NdrPtrWriteArgs(write_stage, align_args) = args;
        debug_assert!(
            matches!(self, Self::Resolved(_)),
            "NdrPtr must be in Resolved state to write"
        );
        let write_refid = matches!(
            write_stage,
            NdrPtrWriteStage::NoArraySupport | NdrPtrWriteStage::ArraySupportWriteRefId
        );
        let write_data = matches!(
            write_stage,
            NdrPtrWriteStage::NoArraySupport | NdrPtrWriteStage::ArraySupportWriteData
        );

        let resolved_val = match self {
            Self::Resolved(x) => x,
            _ => {
                panic!("NdrPtr must be in Resolved state to write data");
            }
        };

        if write_refid {
            let ref_id = match resolved_val {
                Some(_) => REF_ID_UNIQUE_DEFAULT,
                None => NULL_PTR_REF_ID,
            };
            Ndr64Align::from(ref_id).write_options(writer, endian, ())?;
        }

        if write_data {
            // Let's trust T to be aligned if it desires to.
            resolved_val.write_options(writer, endian, align_args)?;
        }

        Ok(())
    }
}

impl<T> NdrAligned for NdrPtr<T> where T: BinRead + BinWrite + NdrAligned {}

impl<T> Deref for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    type Target = Option<NdrAlign<T>>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Resolved(value) => value,
            Self::RefIdRead(_) => panic!("Cannot deref on a pointer that is in RefIdRead state"),
            Self::Uninit => panic!("Cannot deref on an uninitialized pointer"),
        }
    }
}

impl<T> DerefMut for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Resolved(value) => value,
            _ => panic!("Cannot deref_mut on an uninitialized or unresolved pointer"),
        }
    }
}

impl<T> From<T> for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    fn from(value: T) -> Self {
        Self::from(Some(value))
    }
}

impl<T> From<Option<T>> for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    fn from(value: Option<T>) -> Self {
        Self::Resolved(value.map(NdrAlign::from))
    }
}

impl<T> Clone for NdrPtr<T>
where
    T: BinRead + BinWrite + Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Uninit => Self::Uninit,
            Self::RefIdRead(ref_id) => Self::RefIdRead(*ref_id),
            Self::Resolved(value) => Self::Resolved(value.clone()),
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use std::io::Cursor;

    #[binrw::binrw]
    #[derive(Debug, PartialEq, Eq)]
    struct TestNdrU32Ptr {
        unalign: u8,
        null_ptr: NdrPtr<u32>,
        other: u32,
    }

    #[test]
    fn test_nullptr_no_array() {
        let data = TestNdrU32Ptr {
            unalign: 0x1,
            null_ptr: None.into(),
            other: 0x12345678,
        };

        let mut cursor = Cursor::new(vec![]);
        data.write_le(&mut cursor).unwrap();
        let write_result = cursor.into_inner();
        assert_eq!(
            write_result,
            [
                0x1, // unaligned byte
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // alignment padding
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // null pointer, no data!
                0x78, 0x56, 0x34, 0x12 // other value
            ]
        );
    }

    #[test]
    fn test_value_no_array() {
        let data = TestNdrU32Ptr {
            unalign: 0x2,
            null_ptr: Some(0xdeadbeef).into(),
            other: 0x12345678,
        };
        let mut cursor = Cursor::new(vec![]);
        data.write_le(&mut cursor).unwrap();
        let write_result = cursor.into_inner();
        assert_eq!(
            write_result,
            [
                0x2, // unaligned byte
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // alignment padding
                0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, // reference ID for unique value
                0xef, 0xbe, 0xad, 0xde, // value data
                0x78, 0x56, 0x34, 0x12 // other value
            ]
        );
    }
}
