//! File-related messages: Flush, Read, Write.

use std::io::SeekFrom;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::FileId;
use super::header::Header;
use smb_dtyp::binrw_util::prelude::*;

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

/// Zero-copy write request.
///
///
/// i.e. the data is not included in the message, but is sent separately.
///
/// **note:** it is currently assumed that the data is sent immediately after the message.
#[binrw::binrw]
#[derive(Debug)]
#[allow(clippy::manual_non_exhaustive)]
pub struct WriteRequest {
    #[bw(calc = 49)]
    #[br(assert(_structure_size == 49))]
    _structure_size: u16,
    /// internal buffer offset in packet, relative to header.
    #[bw(calc = PosMarker::new(0))]
    _data_offset: PosMarker<u16>,

    /// Length of data to write.
    pub length: u32,
    /// Offset in file to write to.
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

    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    _write_offset: (),
}

impl WriteRequest {
    pub fn new(offset: u64, file_id: FileId, flags: WriteFlags, length: u32) -> Self {
        Self {
            length,
            offset,
            file_id,
            flags,
            _write_offset: (),
        }
    }
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

    use crate::*;

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

    smb_tests::test_binrw! {
        struct FlushResponse {  } => "04 00 00 00"
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

    test_response_read! {
        Read {
            buffer: b"bbbbbb".to_vec(),
        } => "fe534d424000010000000000080001000100000000000000d400000000000000fffe00000500000031000020003000000000000000000000000000000000000011005000060000000000000000000000626262626262"
    }

    #[test]
    pub fn test_write_req_write() {
        let data = encode_content(
            WriteRequest::new(
                0x1234abcd,
                [
                    0x14, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x51, 0x00, 0x10, 0x00, 0x0c,
                    0x00, 0x00, 0x00,
                ]
                .into(),
                WriteFlags::new(),
                "MeFriend!THIS IS FINE!".as_bytes().to_vec().len() as u32,
            )
            .into(),
        );
        assert_eq!(
            data,
            [
                0x31, 0x0, 0x70, 0x0, 0x16, 0x0, 0x0, 0x0, 0xcd, 0xab, 0x34, 0x12, 0x0, 0x0, 0x0,
                0x0, 0x14, 0x4, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x51, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0
            ]
        );
    }

    smb_tests::test_binrw! {
        struct WriteResponse { count: 0xbeefbaaf, } => "11000000afbaefbe0000000000000000"
    }
}
