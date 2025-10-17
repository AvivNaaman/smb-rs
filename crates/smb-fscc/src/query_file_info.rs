//! File Information Classes for getting file information.
//!
//! This module mostly exports [QueryFileInfo] enum, and all structs that can be used with it.
//!
//! [MS-FSCC 2.4](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1>)

use std::ops::Deref;

use binrw::{NullString, io::TakeSeekExt, prelude::*};

use super::{
    ChainedItemList, FileAccessMask, FileAttributes, FileBasicInformation, FileFullEaInformation,
    FileModeInformation, FileNameInformation, FilePipeInformation, FilePositionInformation,
};
use crate::{ReparseTag, file_info_classes};
use smb_dtyp::binrw_util::prelude::*;

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

/// A [FileFullEaInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989)
/// structure to be used when querying for extended attributes. You may use [super::SetFileFullEaInformation] for setting.
pub type QueryFileFullEaInformation = FileFullEaInformation;

pub type FileStreamInformation = ChainedItemList<FileStreamInformationInner>;

/// This information class is used to query the access rights of a file that were granted when the file was opened.
///
/// [MS-FSCC 2.4.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/01cf43d2-deb3-40d3-a39b-9e68693d7c90>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAccessInformation {
    /// Contains values that specify the access rights that were granted when the file was opened.
    pub access_flags: FileAccessMask,
}

/// This information class is used to query a collection of file information structures.
///
/// [MS-FSCC 2.4.2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/95f3056a-ebc1-4f5d-b938-3f68a44677a6>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAllInformation {
    /// Basic file information including timestamps and attributes.
    pub basic: FileBasicInformation,
    /// Standard file information about allocation size and file size.
    pub standard: FileStandardInformation,
    /// Internal file information including the file index number.
    pub internal: FileInternalInformation,
    /// Extended attribute information for the file.
    pub ea: FileEaInformation,
    /// Access rights information for the file.
    pub access: FileAccessInformation,
    /// Current file position information.
    pub position: FilePositionInformation,
    /// File mode information.
    pub mode: FileModeInformation,
    /// Buffer alignment requirements for the underlying device.
    pub alignment: FileAlignmentInformation,
    /// File name information.
    pub name: FileNameInformation,
}

/// This information class is used to query the buffer alignment required by the underlying device.
///
/// [MS-FSCC 2.4.3](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/9b0b9971-85aa-4651-8438-f1c4298bcb0d>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum FileAlignmentInformation {
    /// Specifies that there are no alignment requirements for the device.
    Byte = 0,
    /// Specifies that data must be aligned on a 2-byte boundary.
    Word = 1,
    /// Specifies that data must be aligned on a 4-byte boundary.
    Long = 3,
    /// Specifies that data must be aligned on an 8-byte boundary.
    Quad = 7,
    /// Specifies that data must be aligned on a 16-byte boundary.
    Octa = 0xf,
    /// Specifies that data must be aligned on a 32-byte boundary.
    _32Byte = 0x1f,
    /// Specifies that data must be aligned on a 64-byte boundary.
    _64Byte = 0x3f,
    /// Specifies that data must be aligned on a 128-byte boundary.
    _128Byte = 0x7f,
    /// Specifies that data must be aligned on a 256-byte boundary.
    _256Byte = 0xff,
    /// Specifies that data must be aligned on a 512-byte boundary.
    _512Byte = 0x1ff,
}

/// This information class is used to query the alternate name (8.3 short name) of a file.
///
/// [MS-FSCC 2.4.5](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/cb90d9e0-695d-4418-8d89-a29e2ba9faf8>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAlternateNameInformation {
    /// The alternate name information, following the same structure as FileNameInformation.
    inner: FileNameInformation,
}

impl Deref for FileAlternateNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// This information class is used to query file attribute and reparse tag information for a file.
///
/// [MS-FSCC 2.4.6](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAttributeTagInformation {
    /// File attributes as a bitmask of flags.
    pub file_attributes: FileAttributes,
    /// The reparse point tag value. If the file is not a reparse point, this value is undefined and should not be used.
    pub reparse_tag: ReparseTag,
}

/// This information class is used to query compression information for a file.
///
/// [MS-FSCC 2.4.9](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0a7e50c4-2839-438e-aa6c-0da7d681a5a7>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileCompressionInformation {
    /// The size of the compressed file in bytes.
    pub compressed_file_size: u64,
    /// The compression format used for the file.
    pub compression_format: FileCompressionFormat,
    /// The compression unit size in bytes as a power of 2.
    pub compression_unit: u8,
    /// The compression chunk size in bytes as a power of 2.
    pub chunk_shift: u8,
    /// The cluster size in bytes as a power of 2.
    pub cluster_shift: u8,

    #[bw(calc = [0; 3])]
    _reserved: [u8; 3],
}

/// Compression format values for file compression.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum FileCompressionFormat {
    /// The file is not compressed.
    None = 0,
    /// The file is compressed using the LZNT1 compression algorithm.
    Lznt1 = 2,
}

/// This information class is used to query the size of the extended attributes (EA) for a file.
///
/// [MS-FSCC 2.4.13](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/db6cf109-ead8-441a-b29e-cb2032778b0f>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileEaInformation {
    /// The size in bytes of the extended attributes for the file.
    pub ea_size: u32,
}

/// This information class is used to query the file system's 8-byte file reference number for a file.
///
/// [MS-FSCC 2.4.26](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e4185a8a-ed8d-4f98-ab55-ca34dc8916e6>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileIdInformation {
    /// The serial number of the volume containing the file.
    pub volume_serial_number: u64,
    /// A 128-bit file identifier that uniquely identifies a file within the file system.
    pub file_id: u128,
}

/// This information class is used to query the file system's 8-byte file reference number for a file.
///
/// [MS-FSCC 2.4.27](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/7d796611-2fa5-41ac-8178-b6fea3a017b3>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileInternalInformation {
    /// An 8-byte file reference number for the file. This number is generated and assigned to the file by the file system.
    pub index_number: u64,
}

/// This information class is used to query network file open information for a file.
///
/// [MS-FSCC 2.4.34](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/26d261db-58d1-4513-a548-074448cbb146>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    /// The time when the file was created.
    pub creation_time: FileTime,
    /// The time when the file was last accessed.
    pub last_access_time: FileTime,
    /// The time when data was last written to the file.
    pub last_write_time: FileTime,
    /// The time when the file was last changed.
    pub change_time: FileTime,
    /// The number of bytes that are allocated for the file.
    pub allocation_size: u64,
    /// The end of file location as a byte offset from the start of the file.
    pub end_of_file: u64,
    /// The file attributes.
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    _reserved: u32,
}

/// This information class is used to query the normalized name of a file.
/// A normalized name is an absolute pathname where each short name component has been replaced with the corresponding long name component,
/// and each name component uses the exact letter casing stored on disk
///
/// [MS-FSCC 2.4.36](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/20bcadba-808c-4880-b757-4af93e41edf6>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNormalizedNameInformation {
    /// The normalized name information, following the same structure as FileNameInformation.
    inner: FileNameInformation,
}

impl Deref for FileNormalizedNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// This information class is used to query information associated with a named pipe that is not specific to one end of the pipe or another.
///
/// [MS-FSCC 2.4.38](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/de9abdc7-b974-4ec3-a4dc-42853777f412>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeLocalInformation {
    /// The type of named pipe.
    pub named_pipe_type: NamedPipeType,
    /// The named pipe configuration.
    pub named_pipe_configuration: NamedPipeConfiguration,
    /// The maximum number of instances that can be created for this pipe.
    pub maximum_instances: u32,
    /// The number of current named pipe instances.
    pub current_instances: u32,
    /// The inbound quota in bytes.
    pub inbound_quota: u32,
    /// The outbound quota in bytes.
    pub outbound_quota: u32,
    /// The write quota in bytes.
    pub write_quota: u32,
    /// The named pipe state.
    pub named_pipe_state: NamedPipeState,
    /// Specifies whether the named pipe handle is for the client or server end of a named pipe.
    pub named_pipe_end: NamedPipeEnd,
}

/// Named pipe type values.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeType {
    /// The pipe is a byte-stream pipe.
    ByteStream = 0,
    /// The pipe is a message pipe.
    Message = 1,
}

/// Named pipe configuration values.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeConfiguration {
    /// The flow of data in the pipe goes from client to server only.
    Inbound = 0,
    /// The flow of data in the pipe goes from server to client only.
    Outbound = 1,
    /// The pipe is bidirectional; both server and client can read from and write to the pipe.
    FullDuplex = 2,
}

/// Named pipe state values.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeState {
    /// The pipe is disconnected.
    Disconnected = 1,
    /// The pipe is waiting for a client to connect.
    Listening = 2,
    /// The pipe is connected to a client.
    Connected = 3,
    /// The pipe is in the process of being closed.
    Closing = 4,
}

/// Named pipe end values.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeEnd {
    /// The handle is for the client end of the named pipe.
    Client = 0,
    /// The handle is for the server end of the named pipe.
    Server = 1,
}

/// This information class is used to query information that is associated with the remote end of a named pipe.
///
/// [MS-FSCC 2.4.39](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4319b135-4472-482f-a0a3-6cc3a856c6b6>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeRemoteInformation {
    /// The time at which the data is collected.
    pub collect_data_time: FileTime,
    /// The maximum size, in bytes, of data that will be collected before transmission to the remote end of the named pipe.
    pub maximum_collection_count: u32,
}

/// This information class is used to query standard information for a file.
///
/// [MS-FSCC 2.4.47](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileStandardInformation {
    /// The number of bytes that are allocated for the file.
    pub allocation_size: u64,
    /// The end of file location as a byte offset from the start of the file.
    pub end_of_file: u64,
    /// The number of non-deleted hard links to this file.
    pub number_of_links: u32,
    /// Set to TRUE if the file has been marked for deletion.
    pub delete_pending: Boolean,
    /// Set to TRUE if the file is a directory.
    pub directory: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

/// This information class is used to enumerate the data streams for a file.
///
/// [MS-FSCC 2.4.49](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f8762be6-3ab9-411e-a7d6-5cc68f70c78d>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileStreamInformationInner {
    #[bw(try_calc = stream_name.size().try_into())]
    stream_name_length: u32,
    /// The size, in bytes, of the stream.
    pub stream_size: u64,
    /// The number of bytes that are allocated for the stream.
    pub stream_allocation_size: u64,
    /// The name of the stream in Unicode.
    #[br(args { size: SizedStringSize::bytes(stream_name_length)})]
    pub stream_name: SizedWideString,
}

/// This information class is used to query extended attributes for a file.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(has_next: bool))]
pub struct FileGetEaInformation {
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    /// The name of the extended attribute.
    #[br(map_stream = |s| s.take_seek(ea_name_length as u64))]
    pub ea_name: NullString,
}

impl FileGetEaInformation {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            ea_name: NullString::from(name.into()),
        }
    }
}
