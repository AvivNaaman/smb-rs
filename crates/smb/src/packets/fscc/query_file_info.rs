use std::ops::Deref;

use binrw::{NullString, io::TakeSeekExt, prelude::*};

use crate::{
    file_info_classes,
    packets::binrw_util::{
        helpers::Boolean,
        prelude::{FileTime, SizedWideString},
    },
};

use super::{
    ChainedItem, ChainedItemList, FileAccessMask, FileAttributes, FileBasicInformation,
    FileFullEaInformationCommon, FileModeInformation, FileNameInformation, FilePipeInformation,
    FilePositionInformation,
};

file_info_classes! {
    pub QueryFileInfo {
        pub Access = 8,
        pub Alignment = 17,
        pub All = 18,
        pub AlternateName = 21,
        pub AttributeTag = 35,
        pub Basic = 4,
        pub Compression = 28,
        pub Ea = 7,
        pub FullEa = 15,
        pub Id = 59,
        pub Internal = 6,
        pub Mode = 16,
        pub NetworkOpen = 34,
        pub NormalizedName = 48,
        pub Pipe = 23,
        pub PipeLocal = 24,
        pub PipeRemote  = 25,
        pub Position = 14,
        pub Standard = 5,
        pub Stream = 22,
    }, Read
}

/// For internal use in-module - for file_info_classes! macro.
/// Use [QueryFileFullEaInformation], or [super::SetFileFullEaInformation] instead.
type FileFullEaInformation = FileFullEaInformationCommon;

/// A [FileFullEaInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989)
/// structure to be used when querying for extended attributes. You may use [super::SetFileFullEaInformation] for setting.
pub type QueryFileFullEaInformation = FileFullEaInformation;

pub type FileStreamInformation = ChainedItemList<FileStreamInformationInner>;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAccessInformation {
    pub access_flags: FileAccessMask,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAllInformation {
    pub basic: FileBasicInformation,
    pub standard: FileStandardInformation,
    pub internal: FileInternalInformation,
    pub ea: FileEaInformation,
    pub access: FileAccessInformation,
    pub position: FilePositionInformation,
    pub mode: FileModeInformation,
    pub alignment: FileAlignmentInformation,
    pub name: FileNameInformation,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum FileAlignmentInformation {
    Byte = 0,
    Word = 1,
    Long = 3,
    Quad = 7,
    Octa = 0xf,
    _32Byte = 0x1f,
    _64Byte = 0x3f,
    _128Byte = 0x7f,
    _256Byte = 0xff,
    _512Byte = 0x1ff,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAlternateNameInformation {
    inner: FileNameInformation,
}

impl Deref for FileAlternateNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAttributeTagInformation {
    pub file_attributes: u32,
    pub reparse_tag: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileCompressionInformation {
    pub compressed_file_size: u64,
    pub compression_format: FileCompressionFormat,
    pub compression_unit: u8,
    pub chunk_shift: u8,
    pub cluster_shift: u8,

    #[bw(calc = [0; 3])]
    _reserved: [u8; 3],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum FileCompressionFormat {
    None = 0,
    Lznt1 = 2,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileEaInformation {
    pub ea_size: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileIdInformation {
    pub volume_serial_number: u64,
    pub file_id: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileInternalInformation {
    pub index_number: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    _reserved: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNormalizedNameInformation {
    inner: FileNameInformation,
}

impl Deref for FileNormalizedNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeLocalInformation {
    pub named_pipe_type: NamedPipeType,
    pub named_pipe_configuration: NamedPipeConfiguration,
    pub maximum_instances: u32,
    pub current_instances: u32,
    pub inbound_quota: u32,
    pub outbound_quota: u32,
    pub write_quota: u32,
    pub named_pipe_state: NamedPipeState,
    pub named_pipe_end: NamedPipeEnd,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeType {
    ByteStream = 0,
    Message = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeConfiguration {
    Inbound = 0,
    Outbound = 1,
    FullDuplex = 2,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeState {
    Disconnected = 1,
    Listening = 2,
    Connected = 3,
    Closing = 4,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeEnd {
    Client = 0,
    Server = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeRemoteInformation {
    pub collect_data_time: FileTime,
    pub maximum_collection_count: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileStandardInformation {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: Boolean,
    pub directory: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileStreamInformationInner {
    #[bw(try_calc = stream_name.size().try_into())]
    stream_name_length: u32,
    pub stream_size: u64,
    pub stream_allocation_size: u64,
    #[br(args(stream_name_length as u64))]
    pub stream_name: SizedWideString,
}

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(has_next: bool))]
pub struct FileGetEaInformationInner {
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[br(map_stream = |s| s.take_seek(ea_name_length as u64))]
    pub ea_name: NullString,
}

pub type FileGetEaInformation = ChainedItem<FileGetEaInformationInner>;
