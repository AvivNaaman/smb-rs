use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
#[brw(big, magic(b"\x00"))]
pub struct SmbTcpMessageHeader {
    #[br(parse_with = binrw::helpers::read_u24)]
    #[bw(write_with = binrw::helpers::write_u24)]
    pub stream_protocol_length: u32,
}

impl SmbTcpMessageHeader {
    /// Size of the header, including the magic number (0x00).
    pub const SIZE: usize = 4;
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    #[test]
    fn test_transport_header_write() {
        let header = SmbTcpMessageHeader {
            stream_protocol_length: 0x123456,
        };
        let mut buf = Vec::new();
        header.write(&mut Cursor::new(&mut buf)).unwrap();
        assert_eq!(&[0x00, 0x12, 0x34, 0x56], &buf.as_ref());
    }

    #[test]
    fn test_transport_header_read() {
        let buf = [0x00, 0x12, 0x34, 0x56];
        let header = SmbTcpMessageHeader::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(header.stream_protocol_length, 0x123456);
    }
}
