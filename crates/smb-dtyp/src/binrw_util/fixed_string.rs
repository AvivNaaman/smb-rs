use std::{str::FromStr, string::FromUtf16Error};

use binrw::prelude::*;

/// Fixed-size string with a specified character type and length.
///
/// The string always takes up exactly N characters,
/// with unused characters filled with default values of the character type.
///
/// Notes:
/// - `From<&str>` trims or pads the string to fit exactly N characters.
/// - `TryInto<String>` only pads with default values, it does not trim.
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseFixedString<C: Sized, const N: usize>
where
    C: BinRead + BinWrite + Copy + Clone + Default + 'static,
    for<'a> <C as BinRead>::Args<'a>: Default + Clone,
    for<'b> <C as BinWrite>::Args<'b>: Default + Clone,
{
    pub(crate) data: [C; N],
}

/// Fixed-size wide string with UTF-16 encoding.
pub type FixedWideString<const N: usize> = BaseFixedString<u16, N>;

/// Fixed-size ANSI string with UTF-8 encoding.
pub type FixedAnsiString<const N: usize> = BaseFixedString<u8, N>;

impl<C: Sized, const N: usize> BaseFixedString<C, N>
where
    C: BinRead + BinWrite + Copy + Clone + Default + 'static,
    for<'a> <C as BinRead>::Args<'a>: Default + Clone,
    for<'b> <C as BinWrite>::Args<'b>: Default + Clone,
{
    /// The size of the FixedString in memory, in bytes.
    ///
    /// This is also it's size when bin-read or bin-written.
    pub const SIZE_BYTES: usize = N * std::mem::size_of::<C>();

    /// The maximum number of characters in the FixedString.
    ///
    /// This is the very same as the generic const parameter N.
    pub const MAX_CHARS: usize = N;

    /// Creates a new FixedString from a slice.
    ///
    /// If the slice is shorter than N, the remaining bytes are filled with default values.
    /// If the slice is longer than N, it is truncated.
    pub fn from_slice(slice: &[C]) -> Self {
        let mut data = [C::default(); N];
        let len = slice.len().min(N);
        data[..len].copy_from_slice(&slice[..len]);
        Self { data }
    }

    /// Returns the inner data as a slice.
    pub fn as_slice(&self) -> &[C] {
        &self.data
    }
}

impl<C: Sized, const N: usize> Default for BaseFixedString<C, N>
where
    C: BinRead + BinWrite + Copy + Clone + Default + 'static,
    for<'a> <C as BinRead>::Args<'a>: Default + Clone,
    for<'b> <C as BinWrite>::Args<'b>: Default + Clone,
{
    fn default() -> Self {
        Self {
            data: [C::default(); N],
        }
    }
}

impl<const N: usize> From<&str> for FixedAnsiString<N> {
    fn from(s: &str) -> Self {
        let bytes = s.as_bytes();
        Self::from_slice(bytes)
    }
}

macro_rules! same_generic_impls {
    ($($chartype:ty)+) => {
        $(

impl<const N: usize> FromStr for BaseFixedString<$chartype, N> {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > Self::MAX_CHARS {
            return Err("Input string is longer than fixed size");
        }
        Ok(Self::from(s))
    }
}
        )+
    };
}

same_generic_impls!(u8 u16);

impl<const N: usize> From<&str> for FixedWideString<N> {
    fn from(s: &str) -> Self {
        let wide: Vec<u16> = s.encode_utf16().collect();
        Self::from_slice(&wide)
    }
}

impl<const N: usize> TryInto<String> for FixedAnsiString<N> {
    type Error = std::string::FromUtf8Error;
    fn try_into(self) -> Result<String, Self::Error> {
        String::from_utf8(self.as_slice().to_vec())
    }
}

impl<const N: usize> TryInto<String> for FixedWideString<N> {
    type Error = FromUtf16Error;
    fn try_into(self) -> Result<String, Self::Error> {
        String::from_utf16(self.as_slice())
    }
}

impl<const N: usize> std::fmt::Display for FixedAnsiString<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = String::from_utf8_lossy(self.as_slice());
        write!(f, "{}", s)
    }
}

impl<const N: usize> std::fmt::Display for FixedWideString<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        super::sized_wide_string::display_utf16(self.as_slice(), f, core::iter::once)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::{test_binrw, test_binrw_read_fail};

    type Ansi6 = FixedAnsiString<6>;

    /* From - sanity */

    test_binrw! {
        Ansi6 => A60: Ansi6::from("HelloA") => [72, 101, 108, 108, 111, 65]
    }

    test_binrw! {
        Ansi6 => A61: Ansi6::from("Sh") => [83, 104, 0, 0, 0, 0]
    }

    test_binrw! {
        Ansi6 => A62: Ansi6::from("") => [0, 0, 0, 0, 0, 0]
    }

    test_binrw! {
        Ansi6 => A63: Ansi6::from("HelloALLLLLLLLLLLLLLLLL") => [72, 101, 108, 108, 111, 65]
    }

    type Wide6 = FixedWideString<6>;
    test_binrw! {
        Wide6 => W60: Wide6::from("HelloA") => [72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 65, 0]
    }
    test_binrw! {
        Wide6 => W61: Wide6::from("Hi") => [72, 0, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }
    test_binrw! {
        Wide6 => W62: Wide6::from("") => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }
    test_binrw! {
        Wide6 => W63: Wide6::from("HelloAWWWWWWWWWWWWWWWWWW") => [72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 65, 0]
    }

    macro_rules! fixed_string_tests {
        ($($chartype:ty)+) => {
            $(
                pastey::paste! {
    #[test]
    fn [<test_fixed_string_size_bytes_ $chartype:lower>]() {
        type FS = BaseFixedString<$chartype, 10>;
        assert_eq!(FS::SIZE_BYTES, 10 * std::mem::size_of::<$chartype>());
    }

    #[test]
    fn [<test_fixed_string_max_chars_ $chartype:lower>]() {
        type FS = BaseFixedString<$chartype, 15>;
        assert_eq!(FS::MAX_CHARS, 15);
    }

    /* TryFrom */
    #[test]
    fn [<test_fixed_string_try_from_str_ $chartype:lower>]() {
        type FS = BaseFixedString<$chartype, 5>;
        let s = "abc";
        let fs: FS = s.parse().unwrap();
        assert_eq!(fs.as_slice()[0], 'a' as $chartype);
        assert_eq!(fs.as_slice()[1], 'b' as $chartype);
        assert_eq!(fs.as_slice()[2], 'c' as $chartype);
        for &c in &fs.as_slice()[3..] {
            assert_eq!(c, <$chartype>::default());
        }
    }

    #[test]
    fn [<test_fixed_string_try_from_str_too_long_ $chartype:lower>]() {
        type FS = BaseFixedString<$chartype, 3>;
        let s = "abcd";
        let result: Result<FS, _> = s.parse();
        assert!(result.is_err());
    }

    type [<TemplatedTest $chartype:camel 6>] = BaseFixedString<$chartype, 6>;

    test_binrw_read_fail! {
        [<TemplatedTest $chartype:camel 6>]: [255, 255, 255]
    }
                }
            )+
        };
    }

    fixed_string_tests! { u8 u16 }
}
