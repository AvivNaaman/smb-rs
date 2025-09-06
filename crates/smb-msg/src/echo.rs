//! Echo request and response messages
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EchoMesasge {
    #[br(assert(_structure_size == 4))]
    #[bw(calc = 4)]
    _structure_size: u16,
    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u16,
}

pub type EchoRequest = EchoMesasge;
pub type EchoResponse = EchoMesasge;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_echo_req_write() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let echo_req = EchoRequest::default();
        echo_req.write_le(&mut cursor).unwrap();
        assert_eq!(cursor.into_inner(), [0x4, 0x0, 0x0, 0x0])
    }

    #[test]
    pub fn test_echo_resp_parse() {
        let data = [0x4, 0x0, 0x0, 0x0];
        let echo_resp = EchoResponse::read_le(&mut std::io::Cursor::new(&data)).unwrap();
        assert_eq!(echo_resp, EchoResponse::default());
    }
}
