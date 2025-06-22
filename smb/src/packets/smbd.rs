///! SMB-Direct (SMBD) packets & structures
///
/// [MS-SMBD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/b25587c4-2507-47a4-aa89-e5d3f04f7197)
use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::{binrw_util::prelude::PosMarker, smb2::Status};

const SMBD_VERSION: u16 = 0x100; // SMBD v1.0

/// MS-SMBD 2.2.1
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SmbdNegotiateRequest {
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(min_version == SMBD_VERSION))]
    min_version: u16,
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(max_version == SMBD_VERSION))]
    max_version: u16,

    #[bw(calc = 0)]
    _reserved: u16,

    pub credits_requested: u16,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

impl SmbdNegotiateRequest {
    pub const ENCODED_SIZE: usize = size_of::<u16>() * 4 + size_of::<u32>() * 3;
}

/// MS-SMBD 2.2.2
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SmbdNegotiateResponse {
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(min_version == SMBD_VERSION))]
    min_version: u16,
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(max_version == SMBD_VERSION))]
    max_version: u16,
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(negotiated_version == SMBD_VERSION))]
    negotiated_version: u16,
    #[bw(calc = 0)]
    _reserved: u16,

    pub credits_requested: u16,
    pub credits_granted: u16,

    pub status: Status,

    pub max_read_write_size: u32,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

impl SmbdNegotiateResponse {
    pub const ENCODED_SIZE: usize = size_of::<u16>() * 6 + size_of::<u32>() * 5;
}

const DATA_ALIGNMENT: u32 = 8;

/// MS-SMBD 2.2.3
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SmbdDataTransfer {
    credits_requested: u16,
    credits_granted: u16,
    flags: u16,

    #[bw(calc = 0)]
    _reserved: u16,

    remaining_data_length: u32,
    #[bw(calc = PosMarker::default())]
    #[br(assert(data_offset.value % DATA_ALIGNMENT == 0))]
    data_offset: PosMarker<u32>,
    #[bw(calc = data.len() as u32)]
    data_length: u32,

    #[br(seek_before = SeekFrom::Start(data_offset.value as u64),
        parse_with = binrw::helpers::until_eof,
        map_stream = |s| s.take_seek(data_length as u64))]
    #[bw(align_before = DATA_ALIGNMENT as usize)]
    #[bw(write_with = PosMarker::write_aoff, args(&data_offset))]
    data: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SmbdDataTransferFlags {
    /// The peer is requested to promptly send a message in response. This value is used for keep alives.
    pub response_requested: bool,
    #[skip]
    __: B31,
}

/// MS-SMBD 2.2.3.1
///
/// Represents a registered RDMA buffer and is
/// used to Advertise the source and destination of RDMA Read and RDMA Write operations,
/// respectively. The upper layer optionally embeds one or more of these structures in its payload when
/// requesting RDMA direct placement of peer data via the protocol.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct BufferDescriptorV1 {
    /// The RDMA provider-specific offset, in bytes, identifying the first byte of data to be
    /// transferred to or from the registered buffer
    pub offset: u64,
    /// An RDMA provider-assigned Steering Tag for accessing the registered buffer.
    pub token: u32,
    /// The size, in bytes, of the data to be transferred to or from the registered buffer.
    pub length: u32,
}
