use binrw::{NullString, prelude::*};
use modular_bitfield::prelude::*;

use crate::packets::binrw_util::prelude::{FileTime, SizedWideString};

use super::{ChainedItem, FileAttributes};

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileBasicInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFullEaInformationInner {
    pub flags: u8,
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[bw(calc = match ea_value {
        Some(v) => v.len() as u16,
        None => 0
    })]
    ea_value_length: u16,
    #[br(assert(ea_name.len() == ea_name_length as usize))]
    pub ea_name: NullString,
    #[br(if(ea_value_length > 0))]
    #[br(count = ea_value_length)]
    pub ea_value: Option<Vec<u8>>,
}

pub type FileFullEaInformationCommon = ChainedItem<FileFullEaInformationInner>;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FileModeInformation {
    #[skip]
    __: bool,
    pub write_through: bool,
    pub sequential_access: bool,
    pub no_intermediate_buffering: bool,

    pub syncronous_io_alert: bool,
    pub syncronous_io_non_alert: bool,
    #[skip]
    __: B6,

    pub delete_on_close: bool,
    #[skip]
    __: B19,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeInformation {
    pub read_mode: PipeReadMode,
    pub completion_mode: PipeCompletionMode,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum PipeReadMode {
    Stream = 0,
    Message = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum PipeCompletionMode {
    Queue = 0,
    Complete = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePositionInformation {
    pub current_byte_offset: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNameInformation {
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args(file_name_length as u64))]
    pub file_name: SizedWideString,
}

/// [MS-FSCC 2.1.2.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4>):
/// Each reparse point has a reparse tag.
/// The reparse tag uniquely identifies the owner of that reparse point.
/// The owner is the implementer of the file system filter driver associated with a reparse tag.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
#[brw(repr(u32))]
pub enum ReparseTag {
    /// Reserved reparse tag value.
    ReservedZero = 0x00000000,

    /// Reserved reparse tag value.
    ReservedOne = 0x00000001,

    /// Reserved reparse tag value.
    ReservedTwo = 0x00000002,

    /// Used for mount point support, specified in section 2.1.2.5.
    MountPoint = 0xA0000003,

    /// Obsolete. Used by legacy Hierarchical Storage Manager Product.
    HSM = 0xC0000004,

    /// Home server drive extender.<3>
    DriveExtender = 0x80000005,

    /// Obsolete. Used by legacy Hierarchical Storage Manager Product.
    HSM2 = 0x80000006,

    /// Used by single-instance storage (SIS) filter driver. Server-side interpretation only, not meaningful over the wire.
    SIS = 0x80000007,

    /// Used by the WIM Mount filter. Server-side interpretation only, not meaningful over the wire.
    WIM = 0x80000008,

    /// Obsolete. Used by Clustered Shared Volumes (CSV) version 1 in Windows Server 2008 R2 operating system. Server-side interpretation only, not meaningful over the wire.
    CSV = 0x80000009,

    /// Used by the DFS filter. The DFS is described in the Distributed File System (DFS): Referral Protocol Specification [MS-DFSC]. Server-side interpretation only, not meaningful over the wire.
    DFS = 0x8000000A,

    /// Used by filter manager test harness.<4>
    FilterManager = 0x8000000B,

    /// Used for symbolic link support. See section 2.1.2.4.
    Symlink = 0xA000000C,

    /// Used by Microsoft Internet Information Services (IIS) caching. Server-side interpretation only, not meaningful over the wire.
    IISCache = 0xA0000010,

    /// Used by the DFS filter. The DFS is described in [MS-DFSC]. Server-side interpretation only, not meaningful over the wire.
    DFSR = 0x80000012,

    /// Used by the Data Deduplication (Dedup) filter. Server-side interpretation only, not meaningful over the wire.
    Dedup = 0x80000013,

    /// Not used.
    Appxstrm = 0xC0000014,

    /// Used by the Network File System (NFS) component. Server-side interpretation only, not meaningful over the wire.
    NFS = 0x80000014,

    /// Obsolete. Used by Windows Shell for legacy placeholder files in Windows 8.1. Server-side interpretation only, not meaningful over the wire.
    FilePlaceholder = 0x80000015,

    /// Used by the Dynamic File filter. Server-side interpretation only, not meaningful over the wire.
    DFM = 0x80000016,

    /// Used by the Windows Overlay filter, for either WIMBoot or single-file compression. Server-side interpretation only, not meaningful over the wire.
    WOF = 0x80000017,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WCI = 0x80000018,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    Wci1 = 0x90001018,

    /// Used by NPFS to indicate a named pipe symbolic link from a server silo into the host silo. Server-side interpretation only, not meaningful over the wire.
    GlobalReparse = 0xA0000019,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as Microsoft OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud = 0x9000001A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud1 = 0x9000101A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud2 = 0x9000201A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud3 = 0x9000301A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud4 = 0x9000401A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud5 = 0x9000501A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud6 = 0x9000601A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud7 = 0x9000701A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud8 = 0x9000801A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud9 = 0x9000901A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudA = 0x9000A01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudB = 0x9000B01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudC = 0x9000C01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudD = 0x9000D01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudE = 0x9000E01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudF = 0x9000F01A,

    /// Used by Universal Windows Platform (UWP) packages to encode information that allows the application to be launched by CreateProcess. Server-side interpretation only, not meaningful over the wire.
    Appexeclink = 0x8000001B,

    /// Used by the Windows Projected File System filter, for files managed by a user mode provider such as VFS for Git. Server-side interpretation only, not meaningful over the wire.
    Projfs = 0x9000001C,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX symbolic link. Server-side interpretation only, not meaningful over the wire.
    LxSymlink = 0xA000001D,

    /// Used by the Azure File Sync (AFS) filter. Server-side interpretation only, not meaningful over the wire.
    StorageSync = 0x8000001E,

    /// Used by the Azure File Sync (AFS) filter for folder. Server-side interpretation only, not meaningful over the wire.
    StorageSyncFolder = 0x90000027,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WciTombstone = 0xA000001F,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    Unhandled = 0x80000020,

    /// Not used.
    Onedrive = 0x80000021,

    /// Used by the Windows Projected File System filter, for files managed by a user mode provider such as VFS for Git. Server-side interpretation only, not meaningful over the wire.
    ProjfsTombstone = 0xA0000022,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX domain socket. Server-side interpretation only, not meaningful over the wire.
    AfUnix = 0x80000023,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX FIFO (named pipe). Server-side interpretation only, not meaningful over the wire.
    LxFifo = 0x80000024,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX character special file. Server-side interpretation only, not meaningful over the wire.
    LxChr = 0x80000025,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX block special file. Server-side interpretation only, not meaningful over the wire.
    LxBlk = 0x80000026,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WciLink = 0xA0000027,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WciLink1 = 0xA0001027,
}
