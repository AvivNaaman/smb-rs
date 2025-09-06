//! Cancel Request

use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct CancelRequest {
    #[br(assert(_structure_size == 4))]
    #[bw(calc = 4)]
    _structure_size: u16,
    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use crate::packets::smb2::{RequestContent, test::encode_content};

    use super::*;

    #[test]
    pub fn test_cancel_req_write() {
        let data = encode_content(RequestContent::Cancel(CancelRequest::default()));
        assert_eq!(data, [0x4, 0x0, 0x0, 0x0])
    }
}
