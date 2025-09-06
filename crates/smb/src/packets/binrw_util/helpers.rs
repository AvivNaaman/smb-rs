use binrw::{Endian, NullWideString, prelude::*};
use std::io::{Read, Seek, Write};
use std::ops::{Deref, DerefMut};

#[binrw::writer(writer, endian)]
pub fn write_u48(value: &u64) -> binrw::BinResult<()> {
    let (buf, range) = match endian {
        Endian::Little => (value.to_le_bytes(), 0..6),
        Endian::Big => (value.to_be_bytes(), 2..8),
    };
    writer.write_all(&buf[range]).map_err(Into::into)
}

#[binrw::parser(reader, endian)]
pub fn read_u48() -> binrw::BinResult<u64> {
    type ConvFn = fn([u8; 8]) -> u64;
    let mut buf = [0u8; 8];
    let (conv, out): (ConvFn, &mut [u8]) = match endian {
        Endian::Little => (u64::from_le_bytes, &mut buf[..6]),
        Endian::Big => (u64::from_be_bytes, &mut buf[2..]),
    };
    reader.read_exact(out)?;
    Ok(conv(buf))
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;

    #[binrw::binrw]
    #[derive(Debug, PartialEq, Eq)]
    struct TestReadU48 {
        pub arr0: [u8; 2],
        #[br(parse_with = super::read_u48)]
        #[bw(write_with = super::write_u48)]
        pub value: u64,
        pub arr1: [u8; 4],
    }

    const DATA_BYTES: &[u8] = &[
        0x01, 0x02, // arr0
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // value
        0x09, 0x0A, 0x0B, 0x0C, // arr1
    ];

    const PARSED_LE: TestReadU48 = TestReadU48 {
        arr0: [0x01, 0x02],
        value: 0x080706050403,
        arr1: [0x09, 0x0A, 0x0B, 0x0C],
    };

    const PARSED_BE: TestReadU48 = TestReadU48 {
        arr0: [0x01, 0x02],
        value: 0x030405060708,
        arr1: [0x09, 0x0A, 0x0B, 0x0C],
    };

    #[test]
    fn test_read_u48() {
        // LE
        let mut reader = Cursor::new(DATA_BYTES);
        let parsed = TestReadU48::read_le(&mut reader).unwrap();
        assert_eq!(parsed, PARSED_LE);
        // BE
        reader.set_position(0);
        let parsed = TestReadU48::read_be(&mut reader).unwrap();
        assert_eq!(parsed, PARSED_BE);
    }

    #[test]
    fn test_write_u48() {
        let mut buf = Vec::new();
        PARSED_LE.write_le(&mut Cursor::new(&mut buf)).unwrap();
        assert_eq!(buf, DATA_BYTES);
        buf.clear();
        PARSED_BE.write_be(&mut Cursor::new(&mut buf)).unwrap();
        assert_eq!(buf, DATA_BYTES);
    }
}

/// A simple Boolean type that reads and writes as a single byte.
/// Any non-zero value is considered `true`, as defined by MS-FSCC 2.1.8.
/// Similar to the WinAPI `BOOL` type.
///
/// This type supports `std::size_of::<Boolean>() == 1`, ensuring it is 1 byte in size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boolean(bool);

impl Boolean {
    const _VALIDATE_SIZE_OF: [u8; 1] = [0; size_of::<Self>()];
}

impl BinRead for Boolean {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let value: u8 = u8::read_options(reader, Endian::Little, ())?;
        Ok(Boolean(value != 0))
    }
}

impl BinWrite for Boolean {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let value: u8 = if self.0 { 1 } else { 0 };
        value.write_options(writer, Endian::Little, ())
    }
}

impl From<bool> for Boolean {
    fn from(value: bool) -> Self {
        Boolean(value)
    }
}

/// A MultiSz (Multiple Null-terminated Wide Strings) type that reads and writes a sequence of
/// null-terminated wide strings, ending with an additional null string.
///
/// Similar to the Registry [`REG_MULTI_SZ`](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types) type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiSz(Vec<NullWideString>);

impl BinRead for MultiSz {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let mut strings = Vec::new();
        loop {
            let string: NullWideString = NullWideString::read_options(reader, endian, ())?;
            if string.is_empty() {
                break;
            }
            strings.push(string);
        }
        Ok(MultiSz(strings))
    }
}

impl BinWrite for MultiSz {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<()> {
        for string in &self.0 {
            string.write_options(writer, endian, ())?;
        }
        NullWideString::default().write_options(writer, endian, ())?;
        Ok(())
    }
}

impl Deref for MultiSz {
    type Target = Vec<NullWideString>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MultiSz {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<NullWideString>> for MultiSz {
    fn from(strings: Vec<NullWideString>) -> Self {
        MultiSz(strings)
    }
}
