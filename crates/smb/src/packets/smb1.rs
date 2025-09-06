//! SMBv1 negotiation packet support.
//!
//! For multi-protocol negotiation only.

use binrw::io::TakeSeekExt;
use binrw::prelude::*;

use super::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
#[brw(magic(b"\xffSMB"))]
pub struct SMB1NegotiateMessage {
    #[bw(calc = 0x72)]
    #[br(assert(_command == 0x72))]
    _command: u8,
    status: u32,
    flags: u8,
    flags2: u16,
    #[bw(calc = 0)]
    #[br(assert(_pid_high == 0))]
    _pid_high: u16,
    security_features: [u8; 8],
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = 0xffff)]
    _tid: u16,
    #[bw(calc = 1)]
    #[br(assert(_pid_low == 1))]
    _pid_low: u16,
    #[bw(calc = 0)]
    _uid: u16,
    #[bw(calc = 0)]
    _mid: u16,
    // word count is always 0x0 according to MS-CIFS.
    #[bw(calc = 0)]
    #[br(assert(_word_count == 0))]
    _word_count: u8,
    byte_count: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(byte_count.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_size, args(byte_count))]
    dialects: Vec<Smb1Dialect>,
}

impl SMB1NegotiateMessage {
    pub fn is_smb2_supported(&self) -> bool {
        self.dialects
            .iter()
            .any(|d| d.name.to_string() == "SMB 2.002")
    }
}

impl Default for SMB1NegotiateMessage {
    fn default() -> Self {
        Self {
            status: 0,
            flags: 0x18,
            flags2: 0xc853,
            security_features: [0; 8],
            byte_count: PosMarker::default(),
            dialects: vec![
                Smb1Dialect {
                    name: binrw::NullString::from("NT LM 0.12"),
                },
                Smb1Dialect {
                    name: binrw::NullString::from("SMB 2.002"),
                },
                Smb1Dialect {
                    name: binrw::NullString::from("SMB 2.???"),
                },
            ],
        }
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(magic(b"\x02"))]
pub struct Smb1Dialect {
    name: binrw::NullString,
}

impl TryInto<Vec<u8>> for SMB1NegotiateMessage {
    type Error = binrw::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = std::io::Cursor::new(Vec::new());
        self.write(&mut buf)?;
        Ok(buf.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_smb1_negotiate_req_write() {
        let msg = SMB1NegotiateMessage::default();
        let buf: Result<Vec<u8>, binrw::Error> = msg.try_into();
        assert_eq!(
            buf.unwrap(),
            [
                0xff, 0x53, 0x4d, 0x42, 0x72, 0x0, 0x0, 0x0, 0x0, 0x18, 0x53, 0xc8, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x01, 0x00, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x22, 0x0, 0x2, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31,
                0x32, 0x0, 0x2, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x0, 0x2,
                0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x0
            ]
        )
    }
}
