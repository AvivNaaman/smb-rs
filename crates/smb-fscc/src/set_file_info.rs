use std::ops::Deref;

use crate::file_info_classes;

use smb_dtyp::binrw_util::prelude::{Boolean, SizedWideString};

use super::{
    FileBasicInformation, FileFullEaInformationCommon, FileModeInformation, FileNameInformation,
    FilePipeInformation, FilePositionInformation,
};

file_info_classes! {
    pub SetFileInfo {
        pub Allocation = 19,
        pub Basic = 4,
        pub Disposition = 13,
        pub EndOfFile = 20,
        pub FullEa = 15,
        pub Link = 11,
        pub Mode = 16,
        pub Pipe = 23,
        pub Position = 14,
        pub Rename = 10,
        pub ShortName = 40,
        pub ValidDataLength = 39,
    }, Write
}

// This is a wrapper around `FileFullEaInformationCommon` to implement `BinWrite` WITH NO ARGUMENTS for it.
// This should ONLY be used when WRITING FOR SINGLE FILE INFRORMATION ENTRY!
/// A [FileFullEaInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989)
/// structure to be used when setting for extended attributes. You may use [super::QueryFileFullEaInformation] for querying.
#[derive(BinRead, Debug, PartialEq, Eq)]
pub struct SetFileFullEaInformation(FileFullEaInformationCommon);

/// For internal use only - for file_info_classes! macro.
/// Use [SetFileFullEaInformation] instead, or [super::QueryFileFullEaInformation] for querying.
type FileFullEaInformation = SetFileFullEaInformation;

impl BinWrite for SetFileFullEaInformation {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        // last = true.
        self.0.write_options(writer, endian, (true,))
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileEndOfFileInformation {
    pub end_of_file: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileDispositionInformation {
    /// **Note:** Default is TRUE
    pub delete_pending: Boolean,
}

impl Default for FileDispositionInformation {
    fn default() -> Self {
        Self {
            delete_pending: true.into(),
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileRenameInformation2 {
    pub replace_if_exists: Boolean,
    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    _reserved2: u16,
    #[bw(calc = 0)]
    _reserved3: u32,
    pub root_directory: u64,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    #[br(args(_file_name_length as u64))]
    pub file_name: SizedWideString,
}
type FileRenameInformation = FileRenameInformation2;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAllocationInformation {
    pub allocation_size: u64,
}

/// 2.4.27.2 - FileLinkInformation for SMB2 protocol
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileLinkInformation {
    pub replace_if_exists: Boolean,
    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    _reserved2: u16,
    #[bw(calc = 0)]
    _reserved3: u32,
    // "For network operations, this value must be zero"
    #[bw(calc = 0)]
    #[br(assert(root_directory == 0))]
    root_directory: u64,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    #[br(args(_file_name_length as u64))]
    pub file_name: SizedWideString,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileShortNameInformation {
    inner: FileNameInformation,
}

impl Deref for FileShortNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileValidDataLengthInformation {
    pub valid_data_length: u64,
}
