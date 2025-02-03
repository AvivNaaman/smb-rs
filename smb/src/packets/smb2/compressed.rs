//! Compressed messages

use std::io::SeekFrom;

use crate::packets::binrw_util::prelude::*;

use super::negotiate::CompressionAlgorithm;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum CompressedMessage {
    Unchained(CompressedUnchainedMessage),
    Chained(CompressedChainedMessage),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\xfcSMB"), little)]
pub struct CompressedUnchainedMessage {
    pub original_size: u32,
    // The same as the negotiation, but must be set.
    #[brw(assert(!matches!(compression_algorithm, CompressionAlgorithm::None)))]
    pub compression_algorithm: CompressionAlgorithm,
    #[br(assert(flags == 0))]
    #[bw(calc = 0)]
    flags: u16,
    #[bw(calc = 0)]
    offset: u32,
    #[br(seek_before = SeekFrom::Current(offset as i64))]
    #[br(parse_with = binrw::helpers::until_eof)]
    pub data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\xfcSMB"), little)]
pub struct CompressedChainedMessage {
    pub original_size: u32,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub items: Vec<CompressedChainedItem>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct CompressedChainedItem {
    pub compression_algorithm: CompressionAlgorithm,
    pub flags: u16,
    #[bw(calc = PosMarker::default())]
    length: PosMarker<u32>,
    // Only present if algorithms require it.
    #[brw(if(compression_algorithm.original_size_required()))]
    #[bw(assert(original_size.is_none() ^ compression_algorithm.original_size_required()))]
    pub original_size: Option<u32>,
    // The length specified in `length` also includes `original_size` if present!
    #[br(map_stream = |s| s.take_seek(length.value as u64 - (if compression_algorithm.original_size_required() {4} else {0})), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_size, args(&length))]
    pub payload_data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct CompressedData {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    pub fn test_comp_chained_simple() {
        // This is a simple compressed chained message.
        // No special compression (LZ??) is used.
        // Does not test the presence of original_size.
        let data_bytes = [
            0xfcu8, 0x53, 0x4d, 0x42, 0x70, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x68, 0x0, 0x0, 0x0,
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x1, 0x0,
            0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x91, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff,
            0xfe, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x7d, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x29, 0x0,
            0x1, 0xf, 0x2a, 0x2, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x3, 0x0, 0x0, 0x0, 0xee, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x8d, 0x0, 0x0, 0x0,
            0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x75, 0xb9, 0x1a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x15, 0x24, 0x4d, 0x70, 0x45, 0x61, 0x5f, 0x44, 0x32, 0x36, 0x32, 0x41, 0x43, 0x36,
            0x32, 0x34, 0x34, 0x35, 0x31, 0x32, 0x39, 0x35, 0x4, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0xee, 0x0, 0x0, 0x0,
        ];

        let mut cursor = Cursor::new(data_bytes);

        assert_eq!(
            CompressedMessage::read_le(&mut cursor).unwrap(),
            CompressedMessage::Chained(CompressedChainedMessage {
                original_size: 368,
                items: vec![
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::None,
                        flags: 1,
                        original_size: None,
                        payload_data: vec![
                            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10,
                            0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x91, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
                            0x7d, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x29, 0x0, 0x1,
                            0xf, 0x2a, 0x2, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x8, 0x1, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0xee, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0,
                            0x0, 0x8d, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0
                        ],
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::None,
                        flags: 0xb975,
                        original_size: None,
                        payload_data: vec![
                            0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d, 0x70, 0x45, 0x61, 0x5f, 0x44,
                            0x32, 0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34, 0x35, 0x31, 0x32,
                            0x39, 0x35
                        ],
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::PatternV1,
                        flags: 0,
                        original_size: None,
                        payload_data: vec![0x0, 0x0, 0x0, 0x0, 0xee, 0x0, 0x0, 0x0]
                    }
                ]
            })
        );
    }

    #[test]
    pub fn test_comp_chained_with_orig_size() {
        // as opposed to the first test, this DOES test original_size field!
        let data = vec![
            0xfc, 0x53, 0x4d, 0x42, 0x50, 0x10, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x50, 0x0, 0x0, 0x0,
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x1, 0x0,
            0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1d, 0x0, 0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x25,
            0x16, 0x98, 0xbc, 0x89, 0x8e, 0x3e, 0x86, 0xae, 0xb7, 0x13, 0x55, 0x7c, 0xfa, 0xf1,
            0xbb, 0x11, 0x0, 0x50, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x5, 0x0, 0x0, 0x0, 0xf7, 0x4, 0x0, 0x0, 0xc8, 0x7, 0x0, 0x0, 0xf2, 0x3, 0x4d,
            0x5a, 0x90, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0xb8,
            0x0, 0x1, 0x0, 0x12, 0x40, 0x7, 0x0, 0xf, 0x2, 0x0, 0xa, 0xf3, 0x2e, 0x20, 0x1, 0x0,
            0x0, 0xe, 0x1f, 0xba, 0xe, 0x0, 0xb4, 0x9, 0xcd, 0x21, 0xb8, 0x1, 0x4c, 0xcd, 0x21,
            0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63,
            0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69,
            0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0xd, 0xd, 0xa, 0x24,
            0x5a, 0x0, 0x84, 0xa9, 0x8e, 0xee, 0xb9, 0xed, 0xef, 0x80, 0xea, 0x4, 0x0, 0xd1, 0x99,
            0x6e, 0x86, 0xeb, 0xdd, 0xef, 0x80, 0xea, 0x9f, 0x6e, 0x83, 0xeb, 0xe8, 0x10, 0x0,
            0xb1, 0x81, 0xeb, 0xe1, 0xef, 0x80, 0xea, 0xbe, 0x90, 0x84, 0xeb, 0xec, 0x8, 0x0, 0x31,
            0x83, 0xeb, 0xe3, 0x20, 0x0, 0x31, 0x81, 0xeb, 0xef, 0x38, 0x0, 0xb1, 0x81, 0xea, 0xad,
            0xef, 0x80, 0xea, 0xe4, 0x97, 0x13, 0xea, 0xf0, 0x10, 0x0, 0x31, 0x80, 0xea, 0x7f,
            0x38, 0x0, 0x40, 0x88, 0xeb, 0x5e, 0xe9, 0x40, 0x0, 0x31, 0x85, 0xeb, 0xf3, 0x10, 0x0,
            0x31, 0x84, 0xeb, 0x90, 0x8, 0x0, 0x31, 0x83, 0xeb, 0xa9, 0x8, 0x0, 0x11, 0x80, 0x50,
            0x0, 0x40, 0x99, 0x6e, 0x7f, 0xea, 0x58, 0x0, 0x31, 0x99, 0x6e, 0x82, 0x10, 0x0, 0x40,
            0x52, 0x69, 0x63, 0x68, 0x44, 0x0, 0x3, 0x9f, 0x0, 0xd4, 0x0, 0x50, 0x45, 0x0, 0x0,
            0x64, 0x86, 0x24, 0x0, 0xbb, 0xf4, 0xba, 0x23, 0x14, 0x0, 0xf1, 0xb, 0xf0, 0x0, 0x22,
            0x0, 0xb, 0x2, 0xe, 0x26, 0x0, 0x90, 0xa6, 0x0, 0x0, 0xe0, 0x1d, 0x0, 0x0, 0xf0, 0x61,
            0x0, 0x90, 0x2, 0xb1, 0x0, 0x0, 0x10, 0x22, 0x0, 0x20, 0x40, 0x1, 0x7, 0x0, 0x0, 0xc,
            0x0, 0x56, 0x10, 0x0, 0x0, 0xa, 0x0, 0x4, 0x0, 0x1, 0x2, 0x0, 0x30, 0xf0, 0x44, 0x1,
            0x28, 0x0, 0xb1, 0x26, 0xd1, 0xc2, 0x0, 0x1, 0x0, 0x60, 0x41, 0x0, 0x0, 0x8, 0x17, 0x0,
            0x22, 0x0, 0x20, 0x7, 0x0, 0x1, 0x35, 0x0, 0x0, 0x2, 0x0, 0x0, 0x40, 0x0, 0x3, 0x2,
            0x0, 0x1, 0xb, 0x0, 0xc1, 0x70, 0x14, 0x0, 0x8f, 0xb3, 0x1, 0x0, 0x28, 0x47, 0x14, 0x0,
            0xb8, 0x61, 0x0, 0xf3, 0x14, 0x40, 0x1, 0x28, 0x8e, 0x3, 0x0, 0x0, 0x70, 0xd, 0x0,
            0xb4, 0xcf, 0x6, 0x0, 0x0, 0x70, 0xc2, 0x0, 0xb8, 0x25, 0x0, 0x0, 0x0, 0x90, 0x43, 0x1,
            0xdc, 0x5f, 0x0, 0x0, 0x10, 0x10, 0x4, 0x0, 0x70, 0x40, 0x0, 0xf, 0x2, 0x0, 0x1, 0x20,
            0xa0, 0x5b, 0x42, 0x0, 0x7, 0x1a, 0x0, 0x57, 0x40, 0x14, 0x0, 0xf8, 0x6, 0x10, 0x0,
            0xb, 0x2, 0x0, 0xb2, 0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x0, 0x0, 0x30, 0x5c, 0xd,
            0x91, 0x0, 0x13, 0x60, 0x8, 0x0, 0x7, 0x2, 0x0, 0x62, 0x40, 0x0, 0x0, 0x48, 0x2e, 0x70,
            0x28, 0x0, 0x2, 0x94, 0x0, 0x40, 0xd, 0x0, 0x0, 0xd0, 0x9c, 0x0, 0x17, 0xd, 0x26, 0x0,
            0x3, 0x28, 0x0, 0x12, 0x69, 0x28, 0x0, 0x22, 0x24, 0x26, 0x7c, 0x0, 0x23, 0x0, 0x30,
            0x8, 0x0, 0x7, 0x2, 0x0, 0x1, 0x50, 0x0, 0x12, 0x65, 0x28, 0x0, 0x0, 0xfc, 0x0, 0x63,
            0x0, 0x70, 0x14, 0x0, 0x0, 0xc0, 0x8, 0x0, 0x7, 0x2, 0x0, 0xc1, 0x40, 0x0, 0x0, 0x40,
            0x50, 0x52, 0x4f, 0x54, 0x44, 0x41, 0x54, 0x41, 0x1b, 0x1, 0x22, 0x30, 0x16, 0xa4, 0x0,
            0x0, 0x8, 0x0, 0x7, 0x2, 0x0, 0x0, 0x50, 0x0, 0xa0, 0x47, 0x46, 0x49, 0x44, 0x53, 0x0,
            0x0, 0x0, 0x2c, 0xa9, 0x70, 0x0, 0x43, 0x16, 0x0, 0x0, 0xb0, 0x8, 0x0, 0x7, 0x2, 0x0,
            0x81, 0x40, 0x0, 0x0, 0x42, 0x50, 0x61, 0x64, 0x31, 0x13, 0x0, 0x61, 0x10, 0x9, 0x0,
            0x0, 0xf0, 0x16, 0xb, 0x0, 0xc, 0x2, 0x0, 0xf2, 0x0, 0x80, 0x0, 0x0, 0x42, 0x2e, 0x74,
            0x65, 0x78, 0x74, 0x0, 0x0, 0x0, 0xb, 0xa1, 0x4c, 0xc5, 0x1, 0x2d, 0xb0, 0x4c, 0x30,
            0x0, 0x80, 0x20, 0x0, 0x0, 0x68, 0x50, 0x41, 0x47, 0x45, 0x40, 0x0, 0xf0, 0x0, 0x80,
            0x42, 0x44, 0x0, 0x0, 0xb0, 0x6c, 0x0, 0x0, 0x50, 0x44, 0x0, 0x0, 0xa0, 0x63, 0x13,
            0x0, 0x5, 0x2, 0x0, 0x40, 0x20, 0x0, 0x0, 0x60, 0x28, 0x0, 0xf5, 0x4, 0x4c, 0x4b, 0x0,
            0x0, 0x1c, 0x64, 0x2, 0x0, 0x0, 0x0, 0xb1, 0x0, 0x0, 0x70, 0x2, 0x0, 0x0, 0xf0, 0xa7,
            0x24, 0x0, 0x0, 0x2, 0x0, 0x1, 0x28, 0x0, 0x80, 0x4f, 0x4f, 0x4c, 0x43, 0x4f, 0x44,
            0x45, 0xbe, 0xf4, 0x1, 0x22, 0x70, 0xb3, 0x40, 0x1, 0x20, 0x60, 0xaa, 0x1f, 0x0, 0x5,
            0x2, 0x0, 0x4, 0x78, 0x0, 0xe0, 0x4b, 0x44, 0x0, 0x0, 0xea, 0x5d, 0x0, 0x0, 0x0, 0xa0,
            0xb3, 0x0, 0x0, 0x60, 0x24, 0x2, 0xd, 0x28, 0x0, 0x1, 0x78, 0x0, 0x60, 0x56, 0x52,
            0x46, 0x59, 0x19, 0x15, 0xe, 0x4, 0x8f, 0xb4, 0x0, 0x0, 0x20, 0x3, 0x0, 0x0, 0xf0,
            0x28, 0x0, 0x3, 0x50, 0x48, 0x44, 0x4c, 0x53, 0x76, 0xe, 0x3, 0x22, 0x20, 0xb7, 0x78,
            0x0, 0x25, 0x10, 0xae, 0x74, 0x0, 0x0, 0x2, 0x0, 0x1, 0xa0, 0x0, 0x90, 0x41, 0x47,
            0x45, 0x42, 0x47, 0x46, 0x58, 0x68, 0x69, 0x45, 0x3, 0x21, 0xb7, 0x0, 0x8d, 0x2, 0x1e,
            0x40, 0x28, 0x0, 0xf1, 0x0, 0x54, 0x52, 0x41, 0x43, 0x45, 0x53, 0x55, 0x50, 0xa3, 0x19,
            0x0, 0x0, 0x0, 0xc0, 0xb7, 0x3d, 0x0, 0x2d, 0x0, 0xb0, 0x28, 0x0, 0x1, 0x40, 0x1, 0xb2,
            0x43, 0x4d, 0x52, 0x43, 0xf3, 0xe, 0x0, 0x0, 0x0, 0xe0, 0xb7, 0xe0, 0x1, 0x1d, 0xd0,
            0x28, 0x0, 0x50, 0x60, 0x4b, 0x56, 0x41, 0x53, 0x18, 0x1, 0x10, 0x7e, 0x61, 0x4, 0x13,
            0xf0, 0xa0, 0x0, 0x1d, 0xe0, 0x28, 0x0, 0x50, 0x68, 0x4b, 0x53, 0x43, 0x50, 0xac, 0x0,
            0x10, 0x60, 0x7f, 0x3, 0x22, 0x20, 0xb8, 0x50, 0x0, 0x20, 0x10, 0xaf, 0x13, 0x0, 0x5,
            0x2, 0x0, 0x0, 0x40, 0x1, 0x90, 0x44, 0x52, 0x56, 0x50, 0x52, 0x58, 0x0, 0x0, 0xb7,
            0x16, 0x0, 0x13, 0x30, 0x28, 0x0, 0x1e, 0x20, 0x28, 0x0, 0x50, 0x66, 0x6f, 0x74, 0x68,
            0x6b, 0x24, 0x0, 0x0, 0xad, 0x3, 0x13, 0x40, 0x28, 0x0, 0x1e, 0x30, 0x28, 0x0, 0xe0,
            0x49, 0x4e, 0x49, 0x54, 0x4b, 0x44, 0x42, 0x47, 0xa6, 0xf1, 0x1, 0x0, 0x0, 0x50, 0x6e,
            0x5, 0x4e, 0x2, 0x0, 0x0, 0x40, 0x28, 0x0, 0x90, 0x4d, 0x49, 0x4e, 0x49, 0x45, 0x58,
            0x0, 0x0, 0xbc, 0x20, 0x3, 0x22, 0x50, 0xba, 0x68, 0x1, 0x20, 0x40, 0xb1, 0x62, 0x0,
            0x5, 0x2, 0x0, 0x40, 0x20, 0x0, 0x0, 0x62, 0x50, 0x0, 0x0, 0x11, 0x0, 0xee, 0x1b, 0xe0,
            0x9, 0x0, 0x0, 0x80, 0xba, 0x0, 0x0, 0xf0, 0x9, 0x0, 0x0, 0x70, 0x28, 0x0, 0x40, 0x50,
            0x61, 0x64, 0x32, 0x28, 0x0, 0x71, 0x0, 0x90, 0x1b, 0x0, 0x0, 0x70, 0xc4, 0xb, 0x0,
            0xc, 0x2, 0x0, 0x52, 0x80, 0x0, 0x0, 0x62, 0x2e, 0x6f, 0x3, 0x40, 0x0, 0x80, 0x29,
            0x1c, 0x69, 0x1, 0x0, 0xed, 0x4, 0x49, 0x0, 0x0, 0x60, 0xbb, 0x2b, 0x0, 0xf1, 0x4,
            0x40, 0x0, 0x0, 0xc8, 0x41, 0x4c, 0x4d, 0x4f, 0x53, 0x54, 0x52, 0x4f, 0x40, 0x9c, 0x0,
            0x0, 0x0, 0x30, 0xfc, 0x8d, 0x0, 0x3d, 0x0, 0x50, 0xbc, 0x28, 0x0, 0xf2, 0x0, 0x43,
            0x41, 0x43, 0x48, 0x45, 0x41, 0x4c, 0x49, 0x0, 0x8e, 0x0, 0x0, 0x0, 0xd0, 0xfc, 0x20,
            0x1, 0x1e, 0x70, 0x28, 0x0, 0x0, 0xf8, 0x2, 0x0, 0xc0, 0x3, 0x72, 0x50, 0xb4, 0x1, 0x0,
            0x0, 0x60, 0xfd, 0x50, 0x0, 0x1d, 0x80, 0x28, 0x0, 0x10, 0xc0, 0x28, 0x0, 0xe0, 0x56,
            0x52, 0x46, 0x44, 0x50, 0x3c, 0x1, 0x0, 0x0, 0x20, 0xff, 0x0, 0x0, 0xa0, 0xd8, 0x2,
            0xe, 0x28, 0x0, 0x0, 0x18, 0x1, 0x0, 0x50, 0x0, 0x30, 0xb4, 0x14, 0x2, 0xf4, 0x2, 0x1,
            0x74, 0x5, 0x39, 0x0, 0x40, 0xbd, 0xa0, 0x0, 0x81, 0x20, 0x0, 0x0, 0xc2, 0x50, 0x61,
            0x64, 0x33, 0x15, 0x0, 0x61, 0x80, 0x1d, 0x0, 0x0, 0x80, 0x2, 0x3f, 0x4, 0xc, 0x2, 0x0,
            0x90, 0x80, 0x0, 0x0, 0xc2, 0x43, 0x46, 0x47, 0x52, 0x4f, 0xe3, 0x0, 0x1, 0xa8, 0x5,
            0x21, 0x20, 0x1, 0x70, 0x3, 0x1a, 0x50, 0x50, 0x0, 0x0, 0x18, 0x1, 0x41, 0x50, 0x61,
            0x64, 0x34, 0x40, 0x0, 0x50, 0xd0, 0x1f, 0x0, 0x0, 0x30, 0x22, 0x7, 0xe, 0x2, 0x0,
            0x80, 0x80, 0x0, 0x0, 0xca, 0x2e, 0x72, 0x73, 0x72, 0xfe, 0x3, 0x1, 0xc4, 0x5, 0x9d,
            0x0, 0x40, 0x1, 0x0, 0x90, 0x3, 0x0, 0x0, 0x80, 0x50, 0x0, 0xc1, 0x42, 0x2e, 0x72,
            0x65, 0x6c, 0x6f, 0x63, 0x0, 0x0, 0xdc, 0x55, 0x1, 0xdc, 0x5, 0x78, 0x0, 0x60, 0x1,
            0x0, 0x0, 0x10, 0xc1, 0x55, 0x0, 0x50, 0x0, 0x40, 0x0, 0x0, 0x42, 0x4, 0x0, 0x0, 0x0,
            0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x8, 0x0, 0x0,
        ];
        let mut cursor = Cursor::new(data);
        let comp_msg = CompressedMessage::read_le(&mut cursor).unwrap();
        assert_eq!(
            comp_msg,
            CompressedMessage::Chained(CompressedChainedMessage {
                original_size: 4176,
                items: vec![
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::None,
                        flags: 1,
                        original_size: None,
                        payload_data: vec![
                            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8,
                            0x0, 0x1, 0x0, 0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1d,
                            0x0, 0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x25, 0x16, 0x98, 0xbc, 0x89, 0x8e,
                            0x3e, 0x86, 0xae, 0xb7, 0x13, 0x55, 0x7c, 0xfa, 0xf1, 0xbb, 0x11, 0x0,
                            0x50, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                        ],
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::LZ4,
                        flags: 0,
                        original_size: Some(0x7c8),
                        payload_data: vec![
                            0xf2, 0x3, 0x4d, 0x5a, 0x90, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0,
                            0x0, 0xff, 0xff, 0x0, 0x0, 0xb8, 0x0, 0x1, 0x0, 0x12, 0x40, 0x7, 0x0,
                            0xf, 0x2, 0x0, 0xa, 0xf3, 0x2e, 0x20, 0x1, 0x0, 0x0, 0xe, 0x1f, 0xba,
                            0xe, 0x0, 0xb4, 0x9, 0xcd, 0x21, 0xb8, 0x1, 0x4c, 0xcd, 0x21, 0x54,
                            0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20,
                            0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75,
                            0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64,
                            0x65, 0x2e, 0xd, 0xd, 0xa, 0x24, 0x5a, 0x0, 0x84, 0xa9, 0x8e, 0xee,
                            0xb9, 0xed, 0xef, 0x80, 0xea, 0x4, 0x0, 0xd1, 0x99, 0x6e, 0x86, 0xeb,
                            0xdd, 0xef, 0x80, 0xea, 0x9f, 0x6e, 0x83, 0xeb, 0xe8, 0x10, 0x0, 0xb1,
                            0x81, 0xeb, 0xe1, 0xef, 0x80, 0xea, 0xbe, 0x90, 0x84, 0xeb, 0xec, 0x8,
                            0x0, 0x31, 0x83, 0xeb, 0xe3, 0x20, 0x0, 0x31, 0x81, 0xeb, 0xef, 0x38,
                            0x0, 0xb1, 0x81, 0xea, 0xad, 0xef, 0x80, 0xea, 0xe4, 0x97, 0x13, 0xea,
                            0xf0, 0x10, 0x0, 0x31, 0x80, 0xea, 0x7f, 0x38, 0x0, 0x40, 0x88, 0xeb,
                            0x5e, 0xe9, 0x40, 0x0, 0x31, 0x85, 0xeb, 0xf3, 0x10, 0x0, 0x31, 0x84,
                            0xeb, 0x90, 0x8, 0x0, 0x31, 0x83, 0xeb, 0xa9, 0x8, 0x0, 0x11, 0x80,
                            0x50, 0x0, 0x40, 0x99, 0x6e, 0x7f, 0xea, 0x58, 0x0, 0x31, 0x99, 0x6e,
                            0x82, 0x10, 0x0, 0x40, 0x52, 0x69, 0x63, 0x68, 0x44, 0x0, 0x3, 0x9f,
                            0x0, 0xd4, 0x0, 0x50, 0x45, 0x0, 0x0, 0x64, 0x86, 0x24, 0x0, 0xbb,
                            0xf4, 0xba, 0x23, 0x14, 0x0, 0xf1, 0xb, 0xf0, 0x0, 0x22, 0x0, 0xb, 0x2,
                            0xe, 0x26, 0x0, 0x90, 0xa6, 0x0, 0x0, 0xe0, 0x1d, 0x0, 0x0, 0xf0, 0x61,
                            0x0, 0x90, 0x2, 0xb1, 0x0, 0x0, 0x10, 0x22, 0x0, 0x20, 0x40, 0x1, 0x7,
                            0x0, 0x0, 0xc, 0x0, 0x56, 0x10, 0x0, 0x0, 0xa, 0x0, 0x4, 0x0, 0x1, 0x2,
                            0x0, 0x30, 0xf0, 0x44, 0x1, 0x28, 0x0, 0xb1, 0x26, 0xd1, 0xc2, 0x0,
                            0x1, 0x0, 0x60, 0x41, 0x0, 0x0, 0x8, 0x17, 0x0, 0x22, 0x0, 0x20, 0x7,
                            0x0, 0x1, 0x35, 0x0, 0x0, 0x2, 0x0, 0x0, 0x40, 0x0, 0x3, 0x2, 0x0, 0x1,
                            0xb, 0x0, 0xc1, 0x70, 0x14, 0x0, 0x8f, 0xb3, 0x1, 0x0, 0x28, 0x47,
                            0x14, 0x0, 0xb8, 0x61, 0x0, 0xf3, 0x14, 0x40, 0x1, 0x28, 0x8e, 0x3,
                            0x0, 0x0, 0x70, 0xd, 0x0, 0xb4, 0xcf, 0x6, 0x0, 0x0, 0x70, 0xc2, 0x0,
                            0xb8, 0x25, 0x0, 0x0, 0x0, 0x90, 0x43, 0x1, 0xdc, 0x5f, 0x0, 0x0, 0x10,
                            0x10, 0x4, 0x0, 0x70, 0x40, 0x0, 0xf, 0x2, 0x0, 0x1, 0x20, 0xa0, 0x5b,
                            0x42, 0x0, 0x7, 0x1a, 0x0, 0x57, 0x40, 0x14, 0x0, 0xf8, 0x6, 0x10, 0x0,
                            0xb, 0x2, 0x0, 0xb2, 0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x0, 0x0,
                            0x30, 0x5c, 0xd, 0x91, 0x0, 0x13, 0x60, 0x8, 0x0, 0x7, 0x2, 0x0, 0x62,
                            0x40, 0x0, 0x0, 0x48, 0x2e, 0x70, 0x28, 0x0, 0x2, 0x94, 0x0, 0x40, 0xd,
                            0x0, 0x0, 0xd0, 0x9c, 0x0, 0x17, 0xd, 0x26, 0x0, 0x3, 0x28, 0x0, 0x12,
                            0x69, 0x28, 0x0, 0x22, 0x24, 0x26, 0x7c, 0x0, 0x23, 0x0, 0x30, 0x8,
                            0x0, 0x7, 0x2, 0x0, 0x1, 0x50, 0x0, 0x12, 0x65, 0x28, 0x0, 0x0, 0xfc,
                            0x0, 0x63, 0x0, 0x70, 0x14, 0x0, 0x0, 0xc0, 0x8, 0x0, 0x7, 0x2, 0x0,
                            0xc1, 0x40, 0x0, 0x0, 0x40, 0x50, 0x52, 0x4f, 0x54, 0x44, 0x41, 0x54,
                            0x41, 0x1b, 0x1, 0x22, 0x30, 0x16, 0xa4, 0x0, 0x0, 0x8, 0x0, 0x7, 0x2,
                            0x0, 0x0, 0x50, 0x0, 0xa0, 0x47, 0x46, 0x49, 0x44, 0x53, 0x0, 0x0, 0x0,
                            0x2c, 0xa9, 0x70, 0x0, 0x43, 0x16, 0x0, 0x0, 0xb0, 0x8, 0x0, 0x7, 0x2,
                            0x0, 0x81, 0x40, 0x0, 0x0, 0x42, 0x50, 0x61, 0x64, 0x31, 0x13, 0x0,
                            0x61, 0x10, 0x9, 0x0, 0x0, 0xf0, 0x16, 0xb, 0x0, 0xc, 0x2, 0x0, 0xf2,
                            0x0, 0x80, 0x0, 0x0, 0x42, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x0, 0x0, 0x0,
                            0xb, 0xa1, 0x4c, 0xc5, 0x1, 0x2d, 0xb0, 0x4c, 0x30, 0x0, 0x80, 0x20,
                            0x0, 0x0, 0x68, 0x50, 0x41, 0x47, 0x45, 0x40, 0x0, 0xf0, 0x0, 0x80,
                            0x42, 0x44, 0x0, 0x0, 0xb0, 0x6c, 0x0, 0x0, 0x50, 0x44, 0x0, 0x0, 0xa0,
                            0x63, 0x13, 0x0, 0x5, 0x2, 0x0, 0x40, 0x20, 0x0, 0x0, 0x60, 0x28, 0x0,
                            0xf5, 0x4, 0x4c, 0x4b, 0x0, 0x0, 0x1c, 0x64, 0x2, 0x0, 0x0, 0x0, 0xb1,
                            0x0, 0x0, 0x70, 0x2, 0x0, 0x0, 0xf0, 0xa7, 0x24, 0x0, 0x0, 0x2, 0x0,
                            0x1, 0x28, 0x0, 0x80, 0x4f, 0x4f, 0x4c, 0x43, 0x4f, 0x44, 0x45, 0xbe,
                            0xf4, 0x1, 0x22, 0x70, 0xb3, 0x40, 0x1, 0x20, 0x60, 0xaa, 0x1f, 0x0,
                            0x5, 0x2, 0x0, 0x4, 0x78, 0x0, 0xe0, 0x4b, 0x44, 0x0, 0x0, 0xea, 0x5d,
                            0x0, 0x0, 0x0, 0xa0, 0xb3, 0x0, 0x0, 0x60, 0x24, 0x2, 0xd, 0x28, 0x0,
                            0x1, 0x78, 0x0, 0x60, 0x56, 0x52, 0x46, 0x59, 0x19, 0x15, 0xe, 0x4,
                            0x8f, 0xb4, 0x0, 0x0, 0x20, 0x3, 0x0, 0x0, 0xf0, 0x28, 0x0, 0x3, 0x50,
                            0x48, 0x44, 0x4c, 0x53, 0x76, 0xe, 0x3, 0x22, 0x20, 0xb7, 0x78, 0x0,
                            0x25, 0x10, 0xae, 0x74, 0x0, 0x0, 0x2, 0x0, 0x1, 0xa0, 0x0, 0x90, 0x41,
                            0x47, 0x45, 0x42, 0x47, 0x46, 0x58, 0x68, 0x69, 0x45, 0x3, 0x21, 0xb7,
                            0x0, 0x8d, 0x2, 0x1e, 0x40, 0x28, 0x0, 0xf1, 0x0, 0x54, 0x52, 0x41,
                            0x43, 0x45, 0x53, 0x55, 0x50, 0xa3, 0x19, 0x0, 0x0, 0x0, 0xc0, 0xb7,
                            0x3d, 0x0, 0x2d, 0x0, 0xb0, 0x28, 0x0, 0x1, 0x40, 0x1, 0xb2, 0x43,
                            0x4d, 0x52, 0x43, 0xf3, 0xe, 0x0, 0x0, 0x0, 0xe0, 0xb7, 0xe0, 0x1,
                            0x1d, 0xd0, 0x28, 0x0, 0x50, 0x60, 0x4b, 0x56, 0x41, 0x53, 0x18, 0x1,
                            0x10, 0x7e, 0x61, 0x4, 0x13, 0xf0, 0xa0, 0x0, 0x1d, 0xe0, 0x28, 0x0,
                            0x50, 0x68, 0x4b, 0x53, 0x43, 0x50, 0xac, 0x0, 0x10, 0x60, 0x7f, 0x3,
                            0x22, 0x20, 0xb8, 0x50, 0x0, 0x20, 0x10, 0xaf, 0x13, 0x0, 0x5, 0x2,
                            0x0, 0x0, 0x40, 0x1, 0x90, 0x44, 0x52, 0x56, 0x50, 0x52, 0x58, 0x0,
                            0x0, 0xb7, 0x16, 0x0, 0x13, 0x30, 0x28, 0x0, 0x1e, 0x20, 0x28, 0x0,
                            0x50, 0x66, 0x6f, 0x74, 0x68, 0x6b, 0x24, 0x0, 0x0, 0xad, 0x3, 0x13,
                            0x40, 0x28, 0x0, 0x1e, 0x30, 0x28, 0x0, 0xe0, 0x49, 0x4e, 0x49, 0x54,
                            0x4b, 0x44, 0x42, 0x47, 0xa6, 0xf1, 0x1, 0x0, 0x0, 0x50, 0x6e, 0x5,
                            0x4e, 0x2, 0x0, 0x0, 0x40, 0x28, 0x0, 0x90, 0x4d, 0x49, 0x4e, 0x49,
                            0x45, 0x58, 0x0, 0x0, 0xbc, 0x20, 0x3, 0x22, 0x50, 0xba, 0x68, 0x1,
                            0x20, 0x40, 0xb1, 0x62, 0x0, 0x5, 0x2, 0x0, 0x40, 0x20, 0x0, 0x0, 0x62,
                            0x50, 0x0, 0x0, 0x11, 0x0, 0xee, 0x1b, 0xe0, 0x9, 0x0, 0x0, 0x80, 0xba,
                            0x0, 0x0, 0xf0, 0x9, 0x0, 0x0, 0x70, 0x28, 0x0, 0x40, 0x50, 0x61, 0x64,
                            0x32, 0x28, 0x0, 0x71, 0x0, 0x90, 0x1b, 0x0, 0x0, 0x70, 0xc4, 0xb, 0x0,
                            0xc, 0x2, 0x0, 0x52, 0x80, 0x0, 0x0, 0x62, 0x2e, 0x6f, 0x3, 0x40, 0x0,
                            0x80, 0x29, 0x1c, 0x69, 0x1, 0x0, 0xed, 0x4, 0x49, 0x0, 0x0, 0x60,
                            0xbb, 0x2b, 0x0, 0xf1, 0x4, 0x40, 0x0, 0x0, 0xc8, 0x41, 0x4c, 0x4d,
                            0x4f, 0x53, 0x54, 0x52, 0x4f, 0x40, 0x9c, 0x0, 0x0, 0x0, 0x30, 0xfc,
                            0x8d, 0x0, 0x3d, 0x0, 0x50, 0xbc, 0x28, 0x0, 0xf2, 0x0, 0x43, 0x41,
                            0x43, 0x48, 0x45, 0x41, 0x4c, 0x49, 0x0, 0x8e, 0x0, 0x0, 0x0, 0xd0,
                            0xfc, 0x20, 0x1, 0x1e, 0x70, 0x28, 0x0, 0x0, 0xf8, 0x2, 0x0, 0xc0, 0x3,
                            0x72, 0x50, 0xb4, 0x1, 0x0, 0x0, 0x60, 0xfd, 0x50, 0x0, 0x1d, 0x80,
                            0x28, 0x0, 0x10, 0xc0, 0x28, 0x0, 0xe0, 0x56, 0x52, 0x46, 0x44, 0x50,
                            0x3c, 0x1, 0x0, 0x0, 0x20, 0xff, 0x0, 0x0, 0xa0, 0xd8, 0x2, 0xe, 0x28,
                            0x0, 0x0, 0x18, 0x1, 0x0, 0x50, 0x0, 0x30, 0xb4, 0x14, 0x2, 0xf4, 0x2,
                            0x1, 0x74, 0x5, 0x39, 0x0, 0x40, 0xbd, 0xa0, 0x0, 0x81, 0x20, 0x0, 0x0,
                            0xc2, 0x50, 0x61, 0x64, 0x33, 0x15, 0x0, 0x61, 0x80, 0x1d, 0x0, 0x0,
                            0x80, 0x2, 0x3f, 0x4, 0xc, 0x2, 0x0, 0x90, 0x80, 0x0, 0x0, 0xc2, 0x43,
                            0x46, 0x47, 0x52, 0x4f, 0xe3, 0x0, 0x1, 0xa8, 0x5, 0x21, 0x20, 0x1,
                            0x70, 0x3, 0x1a, 0x50, 0x50, 0x0, 0x0, 0x18, 0x1, 0x41, 0x50, 0x61,
                            0x64, 0x34, 0x40, 0x0, 0x50, 0xd0, 0x1f, 0x0, 0x0, 0x30, 0x22, 0x7,
                            0xe, 0x2, 0x0, 0x80, 0x80, 0x0, 0x0, 0xca, 0x2e, 0x72, 0x73, 0x72,
                            0xfe, 0x3, 0x1, 0xc4, 0x5, 0x9d, 0x0, 0x40, 0x1, 0x0, 0x90, 0x3, 0x0,
                            0x0, 0x80, 0x50, 0x0, 0xc1, 0x42, 0x2e, 0x72, 0x65, 0x6c, 0x6f, 0x63,
                            0x0, 0x0, 0xdc, 0x55, 0x1, 0xdc, 0x5, 0x78, 0x0, 0x60, 0x1, 0x0, 0x0,
                            0x10, 0xc1, 0x55, 0x0, 0x50, 0x0, 0x40, 0x0, 0x0, 0x42
                        ]
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::PatternV1,
                        flags: 0,
                        original_size: None,
                        payload_data: vec![0x0, 0x0, 0x0, 0x0, 0x38, 0x8, 0x0, 0x0]
                    },
                ]
            })
        )
    }

    #[test]
    pub fn test_compressed_data_chained_write() {
        let value = CompressedMessage::Chained(CompressedChainedMessage {
            original_size: 368,
            items: vec![
                CompressedChainedItem {
                    compression_algorithm: CompressionAlgorithm::None,
                    flags: 1,
                    original_size: None,
                    payload_data: vec![
                        0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0,
                        0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1e, 0x3, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x9, 0x0,
                        0x0, 0x2c, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x29, 0x0, 0x1, 0xf, 0x2a, 0x2,
                        0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3,
                        0x0, 0x0, 0x0, 0x11, 0x7, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x69, 0x0, 0x20,
                        0x0, 0xc, 0x0, 0x0, 0x0,
                    ],
                },
                CompressedChainedItem {
                    compression_algorithm: CompressionAlgorithm::None,
                    flags: 0,
                    original_size: None,
                    payload_data: vec![
                        0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d, 0x70, 0x45, 0x61, 0x5f, 0x44, 0x32,
                        0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34, 0x35, 0x31, 0x32, 0x39,
                        0x35,
                    ],
                },
                CompressedChainedItem {
                    compression_algorithm: CompressionAlgorithm::PatternV1,
                    flags: 0,
                    original_size: None,
                    payload_data: vec![0x0, 0x0, 0x0, 0x0, 0xee, 0x0, 0x0, 0x0],
                },
            ],
        });

        let mut cursor = Cursor::new(Vec::new());
        value.write_le(&mut cursor).unwrap();

        assert_eq!(
            cursor.into_inner(),
            [
                0xfc, 0x53, 0x4d, 0x42, 0x70, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x68, 0x0, 0x0,
                0x0, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0,
                0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1e, 0x3, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x9, 0x0, 0x0, 0x2c, 0x0, 0x30,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x29, 0x0, 0x1, 0xf, 0x2a, 0x2, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x8, 0x1,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x11, 0x7, 0x0, 0x0, 0xc, 0x0,
                0x0, 0x0, 0x69, 0x0, 0x20, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d, 0x70, 0x45, 0x61, 0x5f, 0x44, 0x32,
                0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34, 0x35, 0x31, 0x32, 0x39, 0x35, 0x4,
                0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xee, 0x0, 0x0, 0x0
            ]
        );
    }
}
