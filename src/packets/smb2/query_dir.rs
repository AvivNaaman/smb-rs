use binrw::io::TakeSeekExt;
use std::io::SeekFrom;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::{binrw_util::SizedWideString, pos_marker::PosMarker};

use super::fscc::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2QueryDirectoryRequest {
    #[bw(calc = 33)]
    #[br(assert(_structure_size == 33))]
    _structure_size: u16,
    pub file_information_class: FileInformationClass,
    pub flags: QueryDirectoryFlags,
    // If SMB2_INDEX_SPECIFIED is set in Flags, this value MUST be supplied.
    // Otherwise, it MUST be set to zero and the server MUST ignore it.
    #[bw(assert(flags.index_specified() || *file_index == 0))]
    pub file_index: u32,
    pub file_id: u128,
    #[bw(calc = PosMarker::default())]
    pub file_name_offset: PosMarker<u16>,
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u16, // in bytes.
    pub output_buffer_length: u32,
    #[br(seek_before = SeekFrom::Start(file_name_offset.value as u64))]
    // map stream take until eof:
    #[br(args(file_name_length as u64))]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&file_name_offset))]
    pub file_name: SizedWideString,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct QueryDirectoryFlags {
    pub restart_scans: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    pub reopen: bool,
    #[allow(non_snake_case)]
    _reserved: B4,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2QueryDirectoryResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    #[bw(calc = PosMarker::default())]
    output_buffer_offset: PosMarker<u16>,
    #[bw(try_calc = output_buffer.len().try_into())]
    output_buffer_length: u32,
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length as u64), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&output_buffer_offset))]
    pub output_buffer: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    #[test]
    pub fn test_both_directory_information_attribute_parse() {
        let data = [
            0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x39, 0x75, 0x91, 0xbf, 0xc8, 0x4b, 0xdb, 0x1,
            0xe7, 0xb8, 0x48, 0xcd, 0xc8, 0x5d, 0xdb, 0x1, 0xe7, 0x1b, 0xed, 0xd4, 0x6a, 0x58,
            0xdb, 0x1, 0xe7, 0x1b, 0xed, 0xd4, 0x6a, 0x58, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7b,
            0x80, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3c, 0x8, 0x38, 0x96, 0xae, 0x4b, 0xdb, 0x1, 0x10, 0x6a,
            0x87, 0x4b, 0x49, 0x5d, 0xdb, 0x1, 0x62, 0xc, 0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x1, 0x62,
            0xc, 0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2a, 0xe7, 0x1, 0x0,
            0x0, 0x0, 0x4, 0x0, 0x2e, 0x0, 0x2e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x5b, 0x6c, 0x44, 0xce,
            0x6a, 0x58, 0xdb, 0x1, 0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x5f, 0xd9, 0xd5,
            0xce, 0x6a, 0x58, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf0, 0xa4, 0x0, 0x0, 0x0, 0x0,
            0xa, 0x0, 0x61, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd8, 0xce, 0xec, 0xcf, 0x6a, 0x58,
            0xdb, 0x1, 0x7e, 0xc, 0x17, 0xd9, 0x6a, 0x58, 0xdb, 0x1, 0x7e, 0xc, 0x17, 0xd9, 0x6a,
            0x58, 0xdb, 0x1, 0x7e, 0xc, 0x17, 0xd9, 0x6a, 0x58, 0xdb, 0x1, 0x6, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xb9, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x62, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0,
            0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x57,
            0x8e, 0x2f, 0xd0, 0x6a, 0x58, 0xdb, 0x1, 0xe2, 0xa8, 0xc1, 0xdd, 0x6a, 0x58, 0xdb, 0x1,
            0xe2, 0xa8, 0xc1, 0xdd, 0x6a, 0x58, 0xdb, 0x1, 0xe2, 0xa8, 0xc1, 0xdd, 0x6a, 0x58,
            0xdb, 0x1, 0xe6, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xbb, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x63, 0x0,
            0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x32, 0x66, 0x47, 0xd0, 0x6a, 0x58, 0xdb, 0x1, 0x3, 0xc,
            0x39, 0x53, 0x49, 0x5d, 0xdb, 0x1, 0x3, 0xc, 0x39, 0x53, 0x49, 0x5d, 0xdb, 0x1, 0x3,
            0xc, 0x39, 0x53, 0x49, 0x5d, 0xdb, 0x1, 0x26, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xbc, 0xf8, 0x0, 0x0,
            0x0, 0x0, 0x4, 0x0, 0x64, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0,
        ];
        let result = QueryResponseResultVector::read_args(
            &mut Cursor::new(&data),
            (FileInformationClass::IdBothDirectoryInformation,),
        )
        .unwrap();

        dbg!(&result);
    }
}
