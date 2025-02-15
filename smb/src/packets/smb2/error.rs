//! Error response message

use binrw::prelude::*;

use crate::packets::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,

    #[bw(try_calc = error_data.len().try_into())]
    _error_context_count: u8,

    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u8,

    #[bw(calc = PosMarker::default())]
    _byte_count: PosMarker<u32>,

    #[br(count = _error_context_count)]
    pub error_data: Vec<ErrorResponseContext>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponseContext {
    // each context item should be aligned to 8 bytes,
    // relative to the start of the error context.
    // luckily, it appears after the header, which is, itself, aligned to 8 bytes.
    #[brw(align_before = 8)]
    #[bw(try_calc = error_data.len().try_into())]
    _error_data_length: u32,
    pub error_id: ErrorId,
    #[br(count = _error_data_length)]
    pub error_data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum ErrorId {
    Default = 0,
    ShareRedirect = 0x72645253,
}

#[cfg(test)]
mod tests {
    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_simple_error_pasrsed() {
        let msg = decode_content(&[
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x34, 0x0, 0x0, 0xc0, 0x5, 0x0, 0x1, 0x0,
            0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x71, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0xf7,
            0xd, 0xa6, 0x1d, 0x9b, 0x2c, 0x43, 0xd3, 0x26, 0x88, 0x74, 0xf, 0xdf, 0x47, 0x59, 0x24,
            0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]);
        assert_eq!(msg.header.status, Status::ObjectNameNotFound);
        let msg = match msg.content {
            Content::ErrorResponse(msg) => msg,
            _ => panic!("Unexpected response"),
        };
        assert_eq!(msg, ErrorResponse { error_data: vec![] })
    }
}
