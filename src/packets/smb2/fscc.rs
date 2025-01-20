//! File System Control Codes (MS-FSCC)
//!
//! The FSCC types are widely used in SMB messages.

use std::io::{Cursor, SeekFrom};

use binrw::{io::TakeSeekExt, prelude::*, NullString};
use modular_bitfield::prelude::*;

use super::super::binrw_util::prelude::*;

/// MS-FSCC 2.6
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    #[skip]
    __: bool,

    pub directory: bool,
    pub archive: bool,
    #[skip]
    __: bool,
    pub normal: bool,

    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,

    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
    pub integrity_stream: bool,

    #[skip]
    __: bool,
    pub no_scrub_data: bool,
    pub recall_on_open: bool,
    pub pinned: bool,

    pub unpinned: bool,
    #[skip]
    __: bool,
    pub recall_on_data_access: bool,
    #[skip]
    __: B9,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct FileAccessMask {
    pub file_read_data: bool,
    pub file_write_data: bool,
    pub file_append_data: bool,
    pub file_read_ea: bool,

    pub file_write_ea: bool,
    pub file_execute: bool,
    pub file_delete_child: bool,
    pub file_read_attributes: bool,

    pub file_write_attributes: bool,
    #[skip]
    __: B7,

    pub delete: bool,
    pub read_control: bool,
    pub write_dac: bool,
    pub write_owner: bool,

    pub synchronize: bool,
    #[skip]
    __: B3,

    pub access_system_security: bool,
    pub maximum_allowed: bool,
    #[skip]
    __: B2,

    pub generic_all: bool,
    pub generic_execute: bool,
    pub generic_write: bool,
    pub generic_read: bool,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct DirAccessMask {
    pub file_list_directory: bool,
    pub file_add_file: bool,
    pub file_add_subdirectory: bool,
    pub file_read_ea: bool,

    pub file_write_ea: bool,
    pub file_traverse: bool,
    pub file_delete_child: bool,
    pub file_read_attributes: bool,

    pub file_write_attributes: bool,
    #[skip]
    __: B7,

    pub delete: bool,
    pub read_control: bool,
    pub write_dac: bool,
    pub write_owner: bool,

    pub synchronize: bool,
    #[skip]
    __: B3,

    pub access_system_security: bool,
    pub maximum_allowed: bool,
    #[skip]
    __: B2,

    pub generic_all: bool,
    pub generic_execute: bool,
    pub generic_write: bool,
    pub generic_read: bool,
}

impl From<FileAccessMask> for DirAccessMask {
    fn from(mask: FileAccessMask) -> Self {
        // The bits are the same, just the names are different.
        Self::from_bytes(mask.into_bytes())
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr = u8)]
pub enum FileInformationClass {
    DirectoryInformation = 0x01,
    FullDirectoryInformation = 0x02,
    IdFullDirectoryInformation = 0x26,
    BothDirectoryInformation = 0x03,
    IdBothDirectoryInformation = 0x25,
    NamesInformation = 0x0C,
    IdExtdDirectoryInformation = 0x3c,
    Id64ExtdDirectoryInformation = 0x4e,
    Id64ExtdBothDirectoryInformation = 0x4f,
    IdAllExtdDirectoryInformation = 0x50,
    IdAllExtdBothDirectoryInformation = 0x51,
    // reserved.
    InformationClassReserved = 0x64,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(import(c: FileInformationClass))]
#[brw(little)]
pub enum DirectoryInfoVector {
    #[br(pre_assert(c == FileInformationClass::IdBothDirectoryInformation))]
    IdBothDirectoryInformation(IdBothDirectoryInfoVector),
}

impl DirectoryInfoVector {
    pub fn parse(payload: &[u8], class: FileInformationClass) -> Result<Self, binrw::Error> {
        let mut cursor = Cursor::new(payload);
        Self::read_args(&mut cursor, (class,))
    }
}

impl DirectoryInfoVector {
    pub const SUPPORTED_CLASSES: [FileInformationClass; 1] =
        [FileInformationClass::DirectoryInformation];
}

#[binrw::binrw]
#[derive(Debug)]
pub struct IdBothDirectoryInfoVector {
    #[br(parse_with = binrw::helpers::until_eof)]
    val: Vec<BothDirectoryInformationItem>,
}

impl Into<Vec<BothDirectoryInformationItem>> for IdBothDirectoryInfoVector {
    fn into(self) -> Vec<BothDirectoryInformationItem> {
        self.val
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct BothDirectoryInformationItem {
    #[bw(calc = PosMarker::default())]
    _next_entry_offset: PosMarker<u32>,
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32, // bytes
    pub ea_size: u32,
    pub short_name_length: u8,
    #[bw(calc = 0)]
    #[br(assert(_reserved1 == 0))]
    _reserved1: u8,
    pub short_name: [u16; 12], // 8.3
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u16,
    pub fild_id: u64,
    #[br(args(_file_name_length as u64))]
    pub file_name: SizedWideString,
    // Seek to next item if exists.
    #[br(seek_before = _next_entry_offset.seek_relative(true))]
    #[bw(calc = ())]
    _seek_next_if_exists: (),
}

#[binrw::binrw]
#[bw(import(has_next: bool))]
pub struct FileNotifyInformation {
    #[br(assert(next_entry_offset.value % 4 == 0))]
    next_entry_offset: PosMarker<u32>,
    action: NotifyAction,
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args(file_name_length.into()))]
    file_name: SizedWideString,

    // Handle next entry.
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(has_next))]
    #[bw(align_before = 4)]
    #[bw(write_with = PosMarker::write_roff, args(next_entry_offset))]
    _seek_next: (),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NotifyAction {
    Added = 0x1,
    Removed = 0x2,
    Modified = 0x3,
    RenamedOldName = 0x4,
    RenamedNewName = 0x5,
    AddedStream = 0x6,
    RemovedStream = 0x7,
    ModifiedStream = 0x8,
    RemovedByDelete = 0x9,
    IdNotTunnelled = 0xa,
    TunnelledIdCollision = 0xb,
}

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(has_next: bool))]
pub struct FileGetEaInformation {
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    // ea_name_length is the STRING LENGTH of ea_name -- excluding the null terminator!
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[br(map_stream = |s| s.take_seek(ea_name_length as u64))]
    pub ea_name: NullString,

    // Seek to next item if exists.
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(has_next))]
    #[bw(write_with = PosMarker::write_roff, args(&next_entry_offset))]
    pub _seek_next_if_exists: (),
}

impl FileGetEaInformation {
    pub fn new(ea_name: &str) -> Self {
        Self {
            ea_name: NullString::from(ea_name),
            _seek_next_if_exists: (),
        }
    }

    /// A [binrw::writer] function to write a list of [FileGetEaInformation] items.
    /// It makes sure that next_entry_offset is properly set, and should always be used
    /// to write a list of [FileGetEaInformation] items.
    #[binrw::writer(writer, endian)]
    pub fn write_list(value: &Vec<Self>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            let has_next = i < value.len() - 1;
            item.write_options(writer, endian, (has_next,))?;
        }
        Ok(())
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum FileInfoClass {
    AccessInformation = 8,
    AlignmentInformation = 17,
    AllInformation = 18,
    AlternateNameInformation = 21,
    AttributeTagInformation = 35,
    BasicInformation = 4,
    CompressionInformation = 28,
    EaInformation = 7,
    FullEaInformation = 15,
    IdInformation = 59,
    InternalInformation = 6,
    ModeInformation = 16,
    NetworkOpenInformation = 34,
    NormalizedNameInformation = 48,
    PipeInformation = 23,
    PipeLocalInformation = 24,
    PipeRemoteInformation = 25,
    PositionInformation = 14,
    StandardInformation = 5,
    StreamInformation = 22,
}
