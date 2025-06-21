use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
///! SMB-Direct packets
use binrw::prelude::*;

use crate::packets::{binrw_util::prelude::PosMarker, smb2::Status};

const SMBD_VERSION: u16 = 0x100; // SMBD v1.0

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
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
    pub max_fragemnted_size: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
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

    pub status: Status,

    pub max_read_write_size: u32,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

const DATA_ALIGNMENT: u32 = 8;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
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
