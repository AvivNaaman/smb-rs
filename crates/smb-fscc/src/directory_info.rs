use binrw::prelude::*;

use crate::file_info_classes;
use smb_dtyp::binrw_util::prelude::*;

use super::{ChainedItem, FileAttributes, ReparseTag};

file_info_classes! {
    pub QueryDirectoryInfo {
        pub Directory = 0x01,
        pub FullDirectory = 0x02,
        pub IdFullDirectory = 0x26,
        pub BothDirectory = 0x03,
        pub IdBothDirectory = 0x25,
        pub Names = 0x0c,
        pub IdExtdDirectory = 0x3c,

        pub Id64ExtdDirectory = 0x4e,
        pub Id64ExtdBothDirectory = 0x4f,
        pub IdAllExtdDirectory = 0x50,
        pub IdAllExtdBothDirectory = 0x51,
    }, Read
}

macro_rules! query_dir_type {
    (
        $svis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $vis:vis $field_name:ident : $field_ty:ty,
            )*
        }
    ) => {
        paste::paste! {
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq)]
            $svis struct [<$name Inner>] {
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

                #[br(if(!file_attributes.reparse_point()))]
                // ea_size and reparse_tag are the same field, parsed differently, based on attributes.
                #[bw(assert(reparse_tag.is_some() != ea_size.is_some()))]
                pub ea_size: Option<u32>,
                #[br(if(file_attributes.reparse_point()))]
                // Must set file_attributes.reparse_point() to true for this to be some.
                #[bw(assert(reparse_tag.is_some() == file_attributes.reparse_point()))]
                pub reparse_tag: Option<ReparseTag>,

                $(
                    $(#[$field_meta])*
                    $vis $field_name: $field_ty,
                )*

                #[br(args(_file_name_length as u64))]
                pub file_name: SizedWideString,
            }

            $svis type $name = ChainedItem<[<$name Inner>]>;
        }
    };
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileDirectoryInformationInner {
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    #[br(args(_file_name_length as u64))]
    pub file_name: SizedWideString,
}
pub type FileDirectoryInformation = ChainedItem<FileDirectoryInformationInner>;

query_dir_type! {
    pub struct FileFullDirectoryInformation {}
}

query_dir_type! {
    pub struct FileId64ExtdBothDirectoryInformation {
        pub reparse_point_tag: u32,
        pub file_id: u64,
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        pub short_name: [u16; 24], // 8.3
        #[bw(calc = 0)]
        _reserved2: u16,
    }
}

query_dir_type! {
    pub struct FileId64ExtdDirectoryInformation {
        pub reparse_point_tag: u32,
        pub file_id: u64,
    }
}

query_dir_type! {
    pub struct FileIdAllExtdBothDirectoryInformation {
        pub reparse_point_tag: u32,
        pub file_id: u64,
        pub file_id_128: u128,
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        pub short_name: [u16; 24], // 8.3
    }
}

query_dir_type! {
    pub struct FileIdAllExtdDirectoryInformation {
        pub reparse_point_tag: u32,
        pub file_id: u64,
        pub file_id_128: u128,
    }
}

query_dir_type! {
    pub struct FileIdBothDirectoryInformation {
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        pub short_name: [u16; 12], // 8.3
        #[bw(calc = 0)]
        _reserved2: u16,
        pub fild_id: u64,
    }
}

query_dir_type! {
    pub struct FileIdExtdDirectoryInformation {
        pub reparse_point_tag: u32,
        pub file_id: u128,
    }
}

query_dir_type! {
    pub struct FileIdFullDirectoryInformation {
        #[bw(calc = 0)]
        _reserved: u32,
        pub file_id: u64,
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNamesInformationInner {
    pub file_index: u32,
    #[bw(try_calc = file_name.size().try_into())]
    pub file_name_length: u32,
    #[br(args(file_name_length as u64))]
    pub file_name: SizedWideString,
}

query_dir_type! {
    pub struct FileBothDirectoryInformation {
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        pub short_name: [u16; 24], // 8.3
    }
}

pub type FileNamesInformation = ChainedItem<FileNamesInformationInner>;
