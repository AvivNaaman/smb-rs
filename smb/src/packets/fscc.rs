//! File System Control Codes (MS-FSCC)
//!
//! The FSCC types are widely used in SMB messages.
use crate::access_mask;
use binrw::{io::TakeSeekExt, meta::ReadEndian, prelude::*};
use modular_bitfield::prelude::*;

use super::{binrw_util::prelude::*, security::SID};
pub mod chained_item;
pub mod common_info;
pub mod directory_info;
pub mod filesystem_info;
pub mod query_file_info;
pub mod set_file_info;

pub use chained_item::{ChainedItem, ChainedItemList};
pub use common_info::*;
pub use directory_info::*;
pub use filesystem_info::*;
pub use query_file_info::*;
pub use set_file_info::*;

/// MS-FSCC 2.6
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq, Default)]
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

access_mask! {
pub struct FileAccessMask {
    file_read_data: bool,
    file_write_data: bool,
    file_append_data: bool,
    file_read_ea: bool,

    file_write_ea: bool,
    file_execute: bool,
    file_delete_child: bool,
    file_read_attributes: bool,

    file_write_attributes: bool,
    #[skip]
    __: B7,
}}

access_mask! {
pub struct DirAccessMask {
    list_directory: bool,
    add_file: bool,
    add_subdirectory: bool,
    read_ea: bool,

    write_ea: bool,
    traverse: bool,
    delete_child: bool,
    read_attributes: bool,

    write_attributes: bool,
    #[skip]
    __: B7,
}}

impl From<FileAccessMask> for DirAccessMask {
    fn from(mask: FileAccessMask) -> Self {
        // The bits are the same, just the names are different.
        Self::from_bytes(mask.into_bytes())
    }
}

impl Into<FileAccessMask> for DirAccessMask {
    fn into(self) -> FileAccessMask {
        // The bits are the same, just the names are different.
        FileAccessMask::from_bytes(self.into_bytes())
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(has_next: bool))]
pub struct FileNotifyInformationInner {
    pub action: NotifyAction,
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args(file_name_length.into()))]
    pub file_name: SizedWideString,
}

pub type FileNotifyInformation = ChainedItem<FileNotifyInformationInner>;

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

/// Trait for file information types.
/// This trait contains all types of all file info types and classes, specified in MS-FSCC.
///
/// It's role is to allow converting an instance of a file information type to a class,
/// and to provide the class type from the file information type.
pub trait FileInfoType:
    Sized + for<'a> BinRead<Args<'static> = (Self::Class,)> + ReadEndian + std::fmt::Debug
{
    /// The class of the file information.
    type Class;

    /// Get the class of the file information.
    fn class(&self) -> Self::Class;
}

/// A macro for generating a file class enums,
/// for both the file information class, and information value.
/// including a trait for the value types.
#[macro_export]
macro_rules! file_info_classes {
    ($svis:vis $name:ident {
        $($vis:vis $field_name:ident = $cid:literal,)+
    }, $brw_ty:ty) => {
        #[allow(unused_imports)]
        use binrw::prelude::*;
        paste::paste! {
            // Trait to be implemented for all the included value types.
            pub trait [<$name Value>] :
                TryFrom<$name, Error = crate::Error>
                + Send + 'static
                + Into<$name>
                + for <'a> [<Bin $brw_ty>]<Args<'a> = ()> {
                const CLASS_ID: [<$name Class>];
            }

            // Enum for Class IDs
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq, Clone, Copy)]
            #[brw(repr(u8))]
            $svis enum [<$name Class>] {
                $(
                    $vis [<$field_name Information>] = $cid,
                )*
            }

            // Enum for class values
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq)]
            #[brw(little)]
            #[br(import(c: [<$name Class>]))]
            $svis enum $name {
                $(
                    #[br(pre_assert(matches!(c, [<$name Class>]::[<$field_name Information>])))]
                    [<$field_name Information>]([<File $field_name Information>]),
                )*
            }

            impl std::fmt::Display for [<$name Class>] {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        $(
                            [<$name Class>]::[<$field_name Information>] => write!(f, stringify!([<$field_name Information>])),
                        )*
                    }
                }
            }

            impl crate::packets::fscc::FileInfoType for $name {
                type Class = [<$name Class>];
                fn class(&self) -> Self::Class {
                    match self {
                        $(
                            $name::[<$field_name Information>](_) => [<$name Class>]::[<$field_name Information>],
                        )*
                    }
                }
            }

            $(
                impl Into<$name> for [<File $field_name Information>] {
                    fn into(self) -> $name {
                        $name::[<$field_name Information>](self)
                    }
                }

                impl TryFrom<$name> for [<File $field_name Information>] {
                    type Error = crate::Error;

                    fn try_from(value: $name) -> Result<Self, Self::Error> {
                        pub use crate::packets::fscc::FileInfoType;
                        match value {
                            $name::[<$field_name Information>](v) => Ok(v),
                            _ => Err(crate::Error::UnexpectedInformationType(<Self as [<$name Value>]>::CLASS_ID as u8, value.class() as u8)),
                        }
                    }
                }

                impl [<$name Value>] for [<File $field_name Information>] {
                    const CLASS_ID: [<$name Class>] = [<$name Class>]::[<$field_name Information>];
                }
            )*
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct FileQuotaInformationInner {
    #[bw(calc = PosMarker::default())]
    sid_length: PosMarker<u32>,
    pub change_time: FileTime,
    pub quota_used: u64,
    pub quota_threshold: u64,
    pub quota_limit: u64,
    #[br(map_stream = |s| s.take_seek(sid_length.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&sid_length))]
    pub sid: SID,
}

pub type FileQuotaInformation = ChainedItem<FileQuotaInformationInner>;

#[binrw::binrw]
#[derive(Debug)]
pub struct FileGetQuotaInformationInner {
    #[bw(calc = PosMarker::default())]
    sid_length: PosMarker<u32>,
    #[br(map_stream = |s| s.take_seek(sid_length.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&sid_length))]
    pub sid: SID,
}

pub type FileGetQuotaInformation = ChainedItem<FileGetQuotaInformationInner>;
