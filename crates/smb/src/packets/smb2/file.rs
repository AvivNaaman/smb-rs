//! File-related messages: Flush, Read, Write.

use std::io::SeekFrom;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::FileId;
use super::header::Header;
use crate::packets::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct FlushRequest {
    #[bw(calc = 24)]
    #[br(assert(_structure_size == 24))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved1 == 0))]
    _reserved1: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,
    pub file_id: FileId,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FlushResponse {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct ReadRequest {
    #[bw(calc = 49)]
    #[br(assert(_structure_size == 49))]
    _structure_size: u16,
    #[bw(calc = 0)]
    _padding: u8,
    pub flags: ReadFlags,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    // Currently, we do not have support for RDMA.
    // Therefore, all the related fields are set to zero.
    #[bw(calc = CommunicationChannel::None)]
    #[br(assert(channel == CommunicationChannel::None))]
    channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_offset == 0))]
    _read_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_length == 0))]
    _read_channel_info_length: u16,

    // Well, that's a little awkward, but since we never provide a blob, and yet,
    // Msft decided it makes sense to make the structure size 0x31, we need to add this padding.
    #[bw(calc = 0)]
    _pad_blob_placeholder: u8,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ReadResponse {
    #[bw(calc = Self::STRUCT_SIZE as u16)]
    #[br(assert(_structure_size == Self::STRUCT_SIZE as u16))]
    _structure_size: u16,
    // Sanity check: The offset is from the SMB header beginning.
    // it should be greater than the sum of the header and the response.
    // the STRUCT_SIZE includes the first byte of the buffer, so the offset is validated against a byte before that.
    #[br(assert(_data_offset.value as usize >= Header::STRUCT_SIZE + Self::STRUCT_SIZE - 1))]
    #[bw(calc = PosMarker::default())]
    _data_offset: PosMarker<u8>,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u8,
    #[bw(try_calc = buffer.len().try_into())]
    #[br(assert(_data_length > 0))] // sanity
    _data_length: u32,
    #[bw(calc = 0)]
    #[br(assert(_data_remaining == 0))]
    _data_remaining: u32,

    // No RDMA support -- always zero, for both reserved and flags case:
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,

    #[br(seek_before = SeekFrom::Start(_data_offset.value as u64))]
    #[br(count = _data_length)]
    #[bw(assert(!buffer.is_empty()))] // sanity _data_length > 0 on write.
    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    pub buffer: Vec<u8>,
}

impl ReadResponse {
    const STRUCT_SIZE: usize = 17;
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ReadFlags {
    pub read_unbuffered: bool,
    pub read_compressed: bool,
    #[skip]
    __: B6,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum CommunicationChannel {
    None = 0,
    RdmaV1 = 1,
    RdmaV1Invalidate = 2,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct WriteRequest {
    #[bw(calc = 49)]
    #[br(assert(_structure_size == 49))]
    _structure_size: u16,
    /// internal buffer offset in packet, relative to header.
    #[bw(calc = PosMarker::default())]
    _data_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.len().try_into())]
    _length: u32,
    pub offset: u64,
    pub file_id: FileId,
    // Again, RDMA off, all 0.
    #[bw(calc = CommunicationChannel::None)]
    #[br(assert(channel == CommunicationChannel::None))]
    pub channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(assert(_write_channel_info_offset == 0))]
    _write_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(assert(_write_channel_info_length == 0))]
    _write_channel_info_length: u16,
    pub flags: WriteFlags,
    #[br(seek_before = SeekFrom::Start(_data_offset.value as u64))]
    #[br(count = _length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    pub buffer: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct WriteResponse {
    #[bw(calc = 17)]
    #[br(assert(_structure_size == 17))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub count: u32,
    #[bw(calc = 0)] // reserved
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)] // reserved
    #[br(assert(_write_channel_info_offset == 0))]
    _write_channel_info_offset: u16,
    #[bw(calc = 0)] // reserved
    #[br(assert(_write_channel_info_length == 0))]
    _write_channel_info_length: u16,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct WriteFlags {
    pub write_unbuffered: bool,
    pub write_through: bool,
    #[skip]
    __: B30,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_flush_req_write() {
        let mut cursor = Cursor::new(Vec::new());
        FlushRequest {
            file_id: [
                0x14, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x51, 0x00, 0x10, 0x00, 0x0c, 0x00,
                0x00, 0x00,
            ]
            .into(),
        }
        .write_le(&mut cursor)
        .unwrap();
        assert_eq!(
            cursor.into_inner(),
            [
                0x18, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x4, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0,
                0x51, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0
            ]
        )
    }

    #[test]
    pub fn test_flush_res_parse() {
        let data = [0x4u8, 0, 0, 0, 0, 0, 0, 0];
        let mut cursor = Cursor::new(data);
        let resp = FlushResponse::read_le(&mut cursor).unwrap();
        assert_eq!(resp, FlushResponse {});
    }

    #[test]
    pub fn test_read_req_write() {
        let req = ReadRequest {
            flags: ReadFlags::new(),
            length: 0x10203040,
            offset: 0x5060708090a0b0c,
            file_id: [
                0x03, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x00, 0x0c, 0x00,
                0x00, 0x00,
            ]
            .into(),
            minimum_count: 1,
        };
        let data = encode_content(req.into());
        assert_eq![
            data,
            [
                0x31, 0x0, 0x0, 0x0, 0x40, 0x30, 0x20, 0x10, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
                0x06, 0x05, 0x3, 0x3, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xc5, 0x0, 0x0, 0x0, 0xc, 0x0,
                0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, // The famous padding byte.
                0x0
            ]
        ]
    }

    #[test]
    pub fn test_read_resp_parse() {
        let data = [
            0xfeu8, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x1, 0x0,
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff,
            0xfe, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x31, 0x0, 0x0, 0x20, 0x0, 0x30, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x0,
            0x50, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x62, 0x62,
            0x62, 0x62, 0x62, 0x62,
        ];

        let resp = decode_content(&data).content.to_read().unwrap();
        assert_eq!(
            resp,
            ReadResponse {
                buffer: b"bbbbbb".to_vec(),
            }
        );
    }

    #[test]
    pub fn test_write_req_write() {
        let data = encode_content(
            WriteRequest {
                offset: 0x1234abcd,
                file_id: [
                    0x14, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x51, 0x00, 0x10, 0x00, 0x0c,
                    0x00, 0x00, 0x00,
                ]
                .into(),
                flags: WriteFlags::new(),
                buffer: "MeFriend!THIS IS FINE!".as_bytes().to_vec(),
            }
            .into(),
        );
        assert_eq!(
            data,
            [
                0x31, 0x0, 0x70, 0x0, 0x16, 0x0, 0x0, 0x0, 0xcd, 0xab, 0x34, 0x12, 0x0, 0x0, 0x0,
                0x0, 0x14, 0x4, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x51, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x4d, 0x65, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x21, 0x54, 0x48, 0x49, 0x53,
                0x20, 0x49, 0x53, 0x20, 0x46, 0x49, 0x4e, 0x45, 0x21
            ]
        );
    }

    #[test]
    pub fn test_write_resp_parse() {
        let data = [
            0x11u8, 0x0, 0x0, 0x0, 0xaf, 0xba, 0xef, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let mut cursor = Cursor::new(data);
        let resp = WriteResponse::read_le(&mut cursor).unwrap();
        assert_eq!(resp, WriteResponse { count: 0xbeefbaaf });
    }
}
