use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
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
    use smb_tests::*;

    use super::*;

    test_binrw! {
        struct SmbTcpMessageHeader {
            stream_protocol_length: 0x123456,
        } => "00 12 34 56"
    }
}
