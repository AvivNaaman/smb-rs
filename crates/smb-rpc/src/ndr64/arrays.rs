use std::ops::Deref;
use std::ops::DerefMut;

use super::align::*;
use super::ptr::*;
use binrw::prelude::*;

/// Array NDR structure.
///
/// Each item in the array is assured to be aligned properly in the NDR buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    pub data: Vec<NdrAlign<E>>,
}

impl<E> BinRead for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    type Args<'a> = (u64,);

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        // Begin by reading the count of elements in the array.
        let max_count = *NdrAlign::<u64>::read_options(reader, endian, ())?;
        // First read: direct data (ptr refs & actual data)
        let count = args.0;
        // TODO: Test if that's real, and generally --should we just use `max_count`?
        if count > max_count {
            return Err(binrw::Error::AssertFail {
                pos: reader.stream_position()?,
                message: format!(
                    "NdrArray read count requested ({count}) is more than the array's max count ({max_count})"
                ),
            });
        }
        let mut data = Vec::with_capacity(count as usize);
        for _ in 0..count {
            data.push(NdrAlign::<E>::read_options(reader, endian, (None,))?);
        }
        // Second read: ptr values
        let mut resolved = Vec::with_capacity(count as usize);
        for refs_only in &data {
            let ptr_value = NdrAlign::<E>::read_options(reader, endian, (Some(refs_only),))?;
            resolved.push(ptr_value);
        }
        Ok(Self { data: resolved })
    }
}

impl<E> BinWrite for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        // Max count:
        let max_count = self.data.len() as u64;
        Ndr64Align::from(max_count).write_options(writer, endian, ())?;
        // First write: direct data (ptr refs)
        for item in &self.data {
            item.write_options(writer, endian, (NdrPtrWriteStage::ArraySupportWriteRefId,))?;
        }
        // Second write: ptr values
        for item in &self.data {
            item.write_options(writer, endian, (NdrPtrWriteStage::ArraySupportWriteData,))?;
        }
        Ok(())
    }
}

impl<E> NdrAligned for NdrArray<E> where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static
{
}

impl<E> From<Vec<E>> for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    fn from(val: Vec<E>) -> Self {
        NdrArray {
            data: val.into_iter().map(NdrAlign::from).collect(),
        }
    }
}

impl<E> Deref for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    type Target = [NdrAlign<E>];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<E> DerefMut for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// A helper for wrapping in-structure NDR elements, that may be used
/// for arrays of structures.
///
/// See example usage in the tests below.
#[derive(Debug, PartialEq, Eq)]
pub struct NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + 'static,
{
    val: NdrAlign<T>,
}

impl<T> BinRead for NdrArrayStructureElement<T>
where
    T: BinRead<Args<'static> = ()> + BinWrite + Clone + 'static,
{
    type Args<'a> = (Option<&'a T>,);

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        match args.0 {
            Some(prev) => Ok(Self {
                val: (*prev).clone().into(),
            }),
            None => {
                let val = NdrAlign::<T>::read_options(reader, endian, ())?;
                Ok(Self { val })
            }
        }
    }
}

impl<T> BinWrite for NdrArrayStructureElement<T>
where
    for<'a> T: BinWrite<Args<'a> = ()> + BinRead + Clone + 'static,
{
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        self.val.write_options(writer, endian, ())
    }
}

impl<T> From<T> for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    fn from(value: T) -> Self {
        Self {
            val: NdrAlign::from(value),
        }
    }
}
impl<T> NdrAligned for NdrArrayStructureElement<T> where T: BinRead + BinWrite + Clone + 'static {}

impl<T> Deref for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    type Target = NdrAlign<T>;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T> DerefMut for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.val
    }
}

impl<T> Default for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + Default + 'static,
{
    fn default() -> Self {
        Self {
            val: NdrAlign::from(T::default()),
        }
    }
}

impl<T> Clone for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use smb_tests::test_binrw;

    use crate::ndr64::NdrString;

    use super::*;

    #[binrw::binrw]
    #[derive(Debug, PartialEq, Eq)]
    #[bw(import(stage: NdrPtrWriteStage))]
    #[br(import(prev: Option<&Self>))]
    struct InArrayElement {
        #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
        #[br(args(prev.map(|x| &x.ptr_to_value), NdrPtrReadMode::WithArraySupport, ()))]
        ptr_to_value: NdrPtr<u32>,
        #[bw(if(stage == NdrPtrWriteStage::ArraySupportWriteRefId))]
        #[br(args(prev.map(|x| &**x.random_byte)))]
        random_byte: NdrArrayStructureElement<u8>,
        #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
        #[br(args(prev.map(|x| &x.string_val), NdrPtrReadMode::WithArraySupport, ()))]
        string_val: NdrPtr<NdrString<u16>>,
    }

    #[binrw::binrw]
    #[derive(Debug, PartialEq, Eq)]
    struct WithArray {
        #[bw(calc = (array.len() as u32).into())]
        size: NdrAlign<u32>,
        #[br(args(*size as u64))] // TODO: prevent default to 0
        array: NdrArray<InArrayElement>,
    }

    test_binrw! {
        struct WithArray {
            array: vec![
                InArrayElement {
                    ptr_to_value: 42.into(),
                    random_byte: 0x01.into(),
                    string_val: "Hello".parse::<NdrString<u16>>().unwrap().into(),
                },
                InArrayElement {
                    ptr_to_value: 84.into(),
                    random_byte: 0x02.into(),
                    string_val: "World".parse::<NdrString<u16>>().unwrap().into(),
                },
            ]
            .into(),
        } => "020000000000000002000000000000000000020000000000010000000000000000000200000000000000020000000000020000000000000000000200000000002a00000000000000060000000000000000000000000000000600000000000000480065006c006c006f00000000000000540000000000000006000000000000000000000000000000060000000000000057006f0072006c0064000000"
    }
}
