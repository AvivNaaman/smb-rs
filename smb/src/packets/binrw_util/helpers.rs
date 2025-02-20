use binrw::{prelude::*, Endian};

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
