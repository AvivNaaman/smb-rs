use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SessionSetupRequest {
    #[bw(calc = 25)]
    #[br(assert(_structure_size == 25))]
    _structure_size: u16,
    pub flags: SetupRequestFlags,
    pub security_mode: SessionSecurityMode,
    pub capabilities: NegotiateCapabilities,
    pub channel: u32,
    #[bw(calc = PosMarker::default())]
    __security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    pub previous_session_id: u64,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&__security_buffer_offset))]
    pub buffer: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SessionSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip]
    __: B6,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SetupRequestFlags {
    pub binding: bool,
    #[skip]
    __: B7,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NegotiateCapabilities {
    pub dfs: bool,
    #[skip]
    __: B31,
}

impl SessionSetupRequest {
    pub fn new(buffer: Vec<u8>, security_mode: SessionSecurityMode) -> SessionSetupRequest {
        SessionSetupRequest {
            flags: SetupRequestFlags::new(),
            security_mode,
            capabilities: NegotiateCapabilities::new().with_dfs(true),
            channel: 0,
            previous_session_id: 0,
            buffer,
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SessionSetupResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    pub session_flags: SessionFlags,
    #[bw(calc = PosMarker::default())]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SessionFlags {
    pub is_guest: bool,
    pub is_null_session: bool,
    pub encrypt_data: bool,
    #[skip]
    __: B13,
}

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct LogoffRequest {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LogoffResponse {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_setup_req_write() {
        let data = encode_content(Content::SessionSetupRequest(SessionSetupRequest::new(
            [
                0x60, 0x57, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x4d, 0x30, 0x4b, 0xa0,
                0xe, 0x30, 0xc, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa,
                0xa2, 0x39, 0x4, 0x37, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x0, 0x1, 0x0,
                0x0, 0x0, 0x97, 0xb2, 0x8, 0xe2, 0x9, 0x0, 0x9, 0x0, 0x2e, 0x0, 0x0, 0x0, 0x6, 0x0,
                0x6, 0x0, 0x28, 0x0, 0x0, 0x0, 0xa, 0x0, 0x5d, 0x58, 0x0, 0x0, 0x0, 0xf, 0x41,
                0x56, 0x49, 0x56, 0x56, 0x4d, 0x57, 0x4f, 0x52, 0x4b, 0x47, 0x52, 0x4f, 0x55, 0x50,
            ]
            .to_vec(),
            SessionSecurityMode::new().with_signing_enabled(true),
        )));

        assert_eq!(
            data,
            [
                0x19, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x58, 0x0, 0x59, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x60, 0x57, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5,
                0x5, 0x2, 0xa0, 0x4d, 0x30, 0x4b, 0xa0, 0xe, 0x30, 0xc, 0x6, 0xa, 0x2b, 0x6, 0x1,
                0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa, 0xa2, 0x39, 0x4, 0x37, 0x4e, 0x54, 0x4c, 0x4d,
                0x53, 0x53, 0x50, 0x0, 0x1, 0x0, 0x0, 0x0, 0x97, 0xb2, 0x8, 0xe2, 0x9, 0x0, 0x9,
                0x0, 0x2e, 0x0, 0x0, 0x0, 0x6, 0x0, 0x6, 0x0, 0x28, 0x0, 0x0, 0x0, 0xa, 0x0, 0x5d,
                0x58, 0x0, 0x0, 0x0, 0xf, 0x41, 0x56, 0x49, 0x56, 0x56, 0x4d, 0x57, 0x4f, 0x52,
                0x4b, 0x47, 0x52, 0x4f, 0x55, 0x50,
            ],
        )
    }

    #[test]
    pub fn test_setup_resp_parse() {
        let data = [
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x16, 0x0, 0x0, 0xc0, 0x1, 0x0, 0x1, 0x0,
            0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff,
            0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x31, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0,
            0x0, 0x0, 0x48, 0x0, 0xb3, 0x0, 0xa1, 0x81, 0xb0, 0x30, 0x81, 0xad, 0xa0, 0x3, 0xa,
            0x1, 0x1, 0xa1, 0xc, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa,
            0xa2, 0x81, 0x97, 0x4, 0x81, 0x94, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x0, 0x2,
            0x0, 0x0, 0x0, 0xc, 0x0, 0xc, 0x0, 0x38, 0x0, 0x0, 0x0, 0x15, 0xc2, 0x8a, 0xe2, 0xab,
            0xf1, 0x94, 0xbd, 0xb7, 0x56, 0xda, 0xa9, 0x14, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x50, 0x0, 0x50, 0x0, 0x44, 0x0, 0x0, 0x0, 0xa, 0x0, 0x5d, 0x58, 0x0, 0x0, 0x0, 0xf,
            0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0, 0x4d, 0x0, 0x2, 0x0, 0xc, 0x0,
            0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0, 0x4d, 0x0, 0x1, 0x0, 0xc, 0x0,
            0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0, 0x4d, 0x0, 0x4, 0x0, 0xc, 0x0,
            0x41, 0x0, 0x76, 0x0, 0x69, 0x0, 0x76, 0x0, 0x56, 0x0, 0x6d, 0x0, 0x3, 0x0, 0xc, 0x0,
            0x41, 0x0, 0x76, 0x0, 0x69, 0x0, 0x76, 0x0, 0x56, 0x0, 0x6d, 0x0, 0x7, 0x0, 0x8, 0x0,
            0xa8, 0x76, 0xd8, 0x78, 0xc5, 0x69, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0,
        ];

        let response = decode_content(&data)
            .content
            .to_sessionsetupresponse()
            .unwrap();

        assert_eq!(
            response,
            SessionSetupResponse {
                session_flags: SessionFlags::new(),
                buffer: [
                    0xa1, 0x81, 0xb0, 0x30, 0x81, 0xad, 0xa0, 0x3, 0xa, 0x1, 0x1, 0xa1, 0xc, 0x6,
                    0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa, 0xa2, 0x81, 0x97,
                    0x4, 0x81, 0x94, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x0, 0x2, 0x0, 0x0,
                    0x0, 0xc, 0x0, 0xc, 0x0, 0x38, 0x0, 0x0, 0x0, 0x15, 0xc2, 0x8a, 0xe2, 0xab,
                    0xf1, 0x94, 0xbd, 0xb7, 0x56, 0xda, 0xa9, 0x14, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x50, 0x0, 0x50, 0x0, 0x44, 0x0, 0x0, 0x0, 0xa, 0x0, 0x5d, 0x58, 0x0, 0x0,
                    0x0, 0xf, 0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0, 0x4d, 0x0,
                    0x2, 0x0, 0xc, 0x0, 0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0,
                    0x4d, 0x0, 0x1, 0x0, 0xc, 0x0, 0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0,
                    0x56, 0x0, 0x4d, 0x0, 0x4, 0x0, 0xc, 0x0, 0x41, 0x0, 0x76, 0x0, 0x69, 0x0,
                    0x76, 0x0, 0x56, 0x0, 0x6d, 0x0, 0x3, 0x0, 0xc, 0x0, 0x41, 0x0, 0x76, 0x0,
                    0x69, 0x0, 0x76, 0x0, 0x56, 0x0, 0x6d, 0x0, 0x7, 0x0, 0x8, 0x0, 0xa8, 0x76,
                    0xd8, 0x78, 0xc5, 0x69, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0
                ]
                .to_vec()
            }
        )
    }
}
