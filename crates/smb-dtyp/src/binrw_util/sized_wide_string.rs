use binrw::io::Write;
use binrw::{Endian, prelude::*};
use core::fmt::{self, Write as _};
use std::{io::prelude::*, string::FromUtf16Error};

/// Based on binrw::strings::NullWideString, but terminated by provided size rather than null char.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct BaseSizedString<T> {
    /// The raw wide byte string.
    data: Vec<T>,
}

impl<T> BaseSizedString<T> {
    const CHAR_WIDTH: u64 = std::mem::size_of::<T>() as u64;

    /// Size of the string's data, in bytes.
    pub fn size(&self) -> u64 {
        self.data.len() as u64 * Self::CHAR_WIDTH
    }
}

impl<T> BinRead for BaseSizedString<T>
where
    T: BinRead,
    T::Args<'static>: Default,
{
    type Args<'a> = (u64,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        size_bytes: Self::Args<'_>,
    ) -> BinResult<Self> {
        // Size is in bytes, but we need to read in chars.
        assert!(
            size_bytes.0 % Self::CHAR_WIDTH == 0,
            "Size must be a multiple of char width"
        );
        let size_chars = size_bytes.0 / Self::CHAR_WIDTH;

        let mut values = Vec::with_capacity(size_chars as usize);

        for _ in 0..size_chars {
            let val = <T>::read_options(reader, endian, Default::default())?;
            values.push(val);
        }
        Ok(Self { data: values })
    }
}

impl<T> BinWrite for BaseSizedString<T>
where
    T: BinWrite + 'static,
    for<'a> T::Args<'a>: Clone,
{
    type Args<'a> = T::Args<'a>;

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.data.write_options(writer, endian, args)?;

        Ok(())
    }
}

impl<T> From<BaseSizedString<T>> for Vec<T> {
    fn from(s: BaseSizedString<T>) -> Self {
        s.data
    }
}

impl<T> core::ops::Deref for BaseSizedString<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> core::ops::DerefMut for BaseSizedString<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

// TODO: Use this everywhere!
// TODO: implement all the things beyond for it, as well.
/// A fixed-size ANSI (single-byte) string, as opposed to [`binrw::NullString`].
///
/// Note: there's no support for locales in this structure.
pub type SizedAnsiString = BaseSizedString<u8>;

impl From<&str> for SizedAnsiString {
    fn from(s: &str) -> Self {
        assert!(s.is_ascii(), "String must be ASCII");
        Self {
            data: s.bytes().collect(),
        }
    }
}

impl FromIterator<u8> for SizedAnsiString {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        Self {
            data: iter.into_iter().collect(),
        }
    }
}

impl TryFrom<SizedAnsiString> for String {
    type Error = std::string::FromUtf8Error;

    fn try_from(value: SizedAnsiString) -> Result<Self, Self::Error> {
        // Every ANSI string is valid UTF-8 (ignoring page codes & locales)
        String::from_utf8(value.data)
    }
}

impl PartialEq<&str> for SizedAnsiString {
    fn eq(&self, other: &&str) -> bool {
        if !other.is_ascii() {
            return false;
        }
        other.as_bytes().iter().eq(self.data.iter())
    }
}

impl fmt::Display for SizedAnsiString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_ansi(&self.data, f, core::iter::once)
    }
}

impl fmt::Debug for SizedAnsiString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SizedAnsiString(\"")?;
        display_ansi(&self.data, f, char::escape_debug)?;
        write!(f, "\")")
    }
}

#[inline]
fn display_ansi<Transformer: Fn(char) -> O + Clone, O: Iterator<Item = char>>(
    input: &[u8],
    f: &mut fmt::Formatter<'_>,
    t: Transformer,
) -> fmt::Result {
    input
        .iter()
        .flat_map(|&b| char::from_u32(b as u32).into_iter().flat_map(t.clone()))
        .try_for_each(|c| f.write_char(c))
}

/// A fixed-size wide (UTF-16) string, as opposed to [`binrw::NullWideString`].
pub type SizedWideString = BaseSizedString<u16>;

impl From<&str> for SizedWideString {
    fn from(s: &str) -> Self {
        Self {
            data: s.encode_utf16().collect(),
        }
    }
}

impl FromIterator<u16> for SizedWideString {
    fn from_iter<T: IntoIterator<Item = u16>>(iter: T) -> Self {
        Self {
            data: iter.into_iter().collect(),
        }
    }
}

impl From<String> for SizedWideString {
    fn from(s: String) -> Self {
        Self {
            data: s.encode_utf16().collect(),
        }
    }
}

impl TryFrom<SizedWideString> for String {
    type Error = FromUtf16Error;

    fn try_from(value: SizedWideString) -> Result<Self, Self::Error> {
        String::from_utf16(&value.data)
    }
}

impl PartialEq<&str> for SizedWideString {
    fn eq(&self, other: &&str) -> bool {
        other.encode_utf16().eq(self.data.iter().copied())
    }
}

impl fmt::Display for SizedWideString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_utf16(&self.data, f, core::iter::once)
    }
}

impl fmt::Debug for SizedWideString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SizedWideString(\"")?;
        display_utf16(&self.data, f, char::escape_debug)?;
        write!(f, "\")")
    }
}

#[inline]
fn display_utf16<Transformer: Fn(char) -> O, O: Iterator<Item = char>>(
    input: &[u16],
    f: &mut fmt::Formatter<'_>,
    t: Transformer,
) -> fmt::Result {
    char::decode_utf16(input.iter().copied())
        .flat_map(|r| t(r.unwrap_or(char::REPLACEMENT_CHARACTER)))
        .try_for_each(|c| f.write_char(c))
}

mod tests {
    macro_rules! make_sized_string_tests {
        ($name:ident, $type:ty) => {
            #[test]
            fn $name() {
                use super::*;
                let a = BaseSizedString::<$type>::from("hello");
                assert_eq!(a, "hello");
                assert_ne!(a, "hello world");
                assert_ne!(a, "hel");
                assert_ne!(a, "hello\0");

                let b: BaseSizedString<$type> = a.clone();
                assert_eq!(b, a);
                assert_eq!(b.data, a.data);
            }
        };
    }
    make_sized_string_tests!(test_ansi_peq, u8);
    make_sized_string_tests!(test_wide_peq, u16);
}
