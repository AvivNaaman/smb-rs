use binrw::prelude::*;
use modular_bitfield::prelude::*;

use smb_dtyp::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SessionSetupRequest {
    #[bw(calc = 25)]
    #[br(assert(_structure_size == 25))]
    _structure_size: u16,
    pub flags: SetupRequestFlags,
    pub security_mode: SessionSecurityMode,
    pub capabilities: NegotiateCapabilities,
    #[bw(calc = 0)]
    _channel: u32, // reserved
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
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SessionSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip]
    __: B6,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SetupRequestFlags {
    pub binding: bool,
    #[skip]
    __: B7,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NegotiateCapabilities {
    pub dfs: bool,
    #[skip]
    __: B31,
}

impl SessionSetupRequest {
    pub fn new(
        buffer: Vec<u8>,
        security_mode: SessionSecurityMode,
        flags: SetupRequestFlags,
    ) -> SessionSetupRequest {
        SessionSetupRequest {
            flags,
            security_mode,
            capabilities: NegotiateCapabilities::new().with_dfs(true),
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
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SessionFlags {
    pub is_guest: bool,
    pub is_null_session: bool,
    pub encrypt_data: bool,
    #[skip]
    __: B13,
}

impl SessionFlags {
    pub fn is_guest_or_null_session(&self) -> bool {
        self.is_guest() || self.is_null_session()
    }
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
    use smb_tests::hex_to_u8_array;

    use crate::*;

    use super::*;

    #[test]
    pub fn test_setup_req_write() {
        let data = encode_content(
            SessionSetupRequest::new(
                [
                    0x60, 0x57, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x4d, 0x30, 0x4b,
                    0xa0, 0xe, 0x30, 0xc, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2,
                    0xa, 0xa2, 0x39, 0x4, 0x37, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x0, 0x1,
                    0x0, 0x0, 0x0, 0x97, 0xb2, 0x8, 0xe2, 0x9, 0x0, 0x9, 0x0, 0x2e, 0x0, 0x0, 0x0,
                    0x6, 0x0, 0x6, 0x0, 0x28, 0x0, 0x0, 0x0, 0xa, 0x0, 0x5d, 0x58, 0x0, 0x0, 0x0,
                    0xf, 0x41, 0x56, 0x49, 0x56, 0x56, 0x4d, 0x57, 0x4f, 0x52, 0x4b, 0x47, 0x52,
                    0x4f, 0x55, 0x50,
                ]
                .to_vec(),
                SessionSecurityMode::new().with_signing_enabled(true),
                SetupRequestFlags::new(),
            )
            .into(),
        );

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

    const SETUP_RESPONSE_DATA: &'static str = "a181b03081ada0030a0101a10c060a2b06010401823702020aa281970481944e544c4d53535000020000000c000c003800000015c28ae2abf194bdb756daa9140001000000000050005000440000000a005d580000000f410056004900560056004d0002000c00410056004900560056004d0001000c00410056004900560056004d0004000c00410076006900760056006d0003000c00410076006900760056006d0007000800a876d878c569db0100000000";
    test_response_read! {
        SessionSetup {
            session_flags: SessionFlags::new(),
            buffer: hex_to_u8_array! {SETUP_RESPONSE_DATA}
        } => const_format::concatcp!("fe534d4240000100160000c00100010011000000000000000200000000000000fffe000000000000310000280030000000000000000000000000000000000000090000004800b300", SETUP_RESPONSE_DATA)
    }
}
