//! File Information Classes for directory enumeration.
//!
//! This module mostly exports the [`QueryDirectoryInfo`] enum, which contains all directory information types,
//! and all the structs for each information type.
//!
//! [MS-FSCC 2.4](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1>)

use binrw::prelude::*;

use crate::info_classes::file_info_classes;
use smb_dtyp::binrw_util::{fixed_string::FixedWideString, prelude::*};

use super::{FileAttributes, ReparseTag};

// Note: here, the information types should be wrapped around [`ChainedItemList<T>`]`.

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

impl QueryDirectoryInfo {
    /// All directory information structures must be aligned to 8-byte boundaries.
    pub const CHAINED_ALIGNMENT: u32 = 8;
}

/// Since most of the directory information types are very similar (or at least share a lot of fields in their beginning),
/// we use this macro to reduce code duplication when defining them.
macro_rules! query_dir_type {
    (
    $(#[$meta:meta])*
        $svis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $vis:vis $field_name:ident : $field_ty:ty,
            )*
        }
    ) => {
        pastey::paste! {
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq)]
            $(#[$meta])*
            ///
            /// > Note: This should be wrapped in [`ChainedItemList<T>`] to represent a list of these structures.
            $svis struct $name {
                /// The byte offset of the file within the parent directory. This member is undefined for file systems, such as NTFS, in which the position of a file within the parent directory is not fixed and can be changed at any time to maintain sort order.
                pub file_index: u32,
                /// The time when the file was created.
                pub creation_time: FileTime,
                /// The time when the file was last accessed.
                pub last_access_time: FileTime,
                /// The time when data was last written to the file.
                pub last_write_time: FileTime,
                /// The time when the file was last changed.
                pub change_time: FileTime,
                /// The absolute new end-of-file position as a byte offset from the start of the file.
                pub end_of_file: u64,
                /// The number of bytes allocated for the file.
                pub allocation_size: u64,
                /// The file attributes.
                pub file_attributes: FileAttributes,
                #[bw(try_calc = file_name.size().try_into())]
                _file_name_length: u32, // bytes

                #[br(if(!file_attributes.reparse_point()))]
                // ea_size and reparse_tag are the same field, parsed differently, based on attributes.
                #[bw(assert(reparse_tag.is_some() != ea_size.is_some()))]
                /// The size of the extended attributes for the file.
                pub ea_size: Option<u32>,
                #[br(if(file_attributes.reparse_point()))]
                // Must set file_attributes.reparse_point() to true for this to be some.
                #[bw(assert(reparse_tag.is_some() == file_attributes.reparse_point()))]
                /// The reparse point tag. If the file is not a reparse point, this value is 0.
                pub reparse_tag: Option<ReparseTag>,

                $(
                    $(#[$field_meta])*
                    $vis $field_name: $field_ty,
                )*

                /// The name of the file.
                 #[br(args { size: SizedStringSize::bytes(_file_name_length)})]
                pub file_name: SizedWideString,
            }
        }
    };
}

/// Fixed-size wide string for 8.3 filenames.
type FileName83 = FixedWideString<12>; // 8.3 => 8+1+3 = 12

/// Query detailed information for the files in a directory.
///
/// [MS-FSCC 2.4.10](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b38bf518-9057-4c88-9ddd-5e2d3976a64b>)
///
/// This should be wrapped in [`ChainedItemList<T>`] to represent a list of these structures.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileDirectoryInformation {
    /// The byte offset of the file within the parent directory. This member is undefined for file systems, such as NTFS, in which the position of a file within the parent directory is not fixed and can be changed at any time to maintain sort order.
    pub file_index: u32,
    /// The time when the file was created.
    pub creation_time: FileTime,
    /// The time when the file was last accessed.
    pub last_access_time: FileTime,
    /// The time when data was last written to the file.
    pub last_write_time: FileTime,
    /// The time when the file was last changed.
    pub change_time: FileTime,
    /// The absolute new end-of-file position as a byte offset from the start of the file.
    pub end_of_file: u64,
    /// The number of bytes allocated for the file.
    pub allocation_size: u64,
    /// The file attributes.
    pub file_attributes: FileAttributes,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    /// The name of the file.
    #[br(args { size: SizedStringSize::bytes(_file_name_length)})]
    pub file_name: SizedWideString,
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.17](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/46021e52-29b1-475c-b6d3-fe5497d23277>)
    pub struct FileFullDirectoryInformation {}
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.18](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b3a27a50-454f-4f8f-b8ea-decfedc5c454>)
    pub struct FileId64ExtdBothDirectoryInformation {
        /// The reparse point tag. If the file is not a reparse point, this value is 0.
        pub reparse_point_tag: u32,
        /// The file ID.
        pub file_id: u64,
        /// The length, in bytes, of the short name string.
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        /// The short (8.3) name of the file.
        pub short_name: FileName83, // 8.3
        #[bw(calc = 0)]
        _reserved2: u16,
    }
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.19](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/174921dd-9be2-42ed-8220-58c310b1b916>)
    pub struct FileId64ExtdDirectoryInformation {
        /// The reparse point tag. If the file is not a reparse point, this value is 0.
        pub reparse_point_tag: u32,
        /// The file ID.
        pub file_id: u64,
    }
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.20](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/1dbb9619-873e-4834-af01-849dcce87d7d>)
    pub struct FileIdAllExtdBothDirectoryInformation {
        /// The reparse point tag. If the file is not a reparse point, this value is 0.
        pub reparse_point_tag: u32,
        /// The file ID.
        pub file_id: u64,
        /// The 128-bit file identifier for the file.
        pub file_id_128: u128,
        /// The length, in bytes, of the short name string.
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        /// The short (8.3) name of the file.
        pub short_name: FileName83, // 8.3
    }
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.21](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/02991a71-6610-4127-93ef-76b8ea80fef6>)
    pub struct FileIdAllExtdDirectoryInformation {
        /// The reparse point tag. If the file is not a reparse point, this value is 0.
        pub reparse_point_tag: u32,
        /// The file ID.
        pub file_id: u64,
        /// The 128-bit file identifier for the file.
        pub file_id_128: u128,
    }
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.22](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/1e144bff-c056-45aa-bd29-c13d214ee2ba>)
    pub struct FileIdBothDirectoryInformation {
        /// The length, in bytes, of the short name string.
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        /// The short (8.3) name of the file.
        pub short_name: FileName83, // 8.3
        #[bw(calc = 0)]
        _reserved2: u16,
        /// The file ID.
        pub file_id: u64,
    }
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.23](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/36172f0b-8dce-435a-8748-859978d632f8>)
    pub struct FileIdExtdDirectoryInformation {
        /// The reparse point tag. If the file is not a reparse point, this value is 0.
        pub reparse_point_tag: u32,
        /// The 128-bit file identifier for the file.
        pub file_id: u128,
    }
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.24](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ab8e7558-899c-4be1-a7c5-3a9ae8ab76a0>)
    pub struct FileIdFullDirectoryInformation {
        #[bw(calc = 0)]
        _reserved: u32,
        /// The file ID.
        pub file_id: u64,
    }
}

/// Query the names of the files in a directory.
///
/// [MS-FSCC 2.4.33](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a289f7a8-83d2-4927-8c88-b2d328dde5a5>)
///
/// This should be wrapped in [`ChainedItemList<T>`] to represent a list of these structures.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNamesInformation {
    /// The byte offset of the file within the parent directory. This member is undefined for file systems, such as NTFS, in which the position of a file within the parent directory is not fixed and can be changed at any time to maintain sort order.
    pub file_index: u32,
    #[bw(try_calc = file_name.size().try_into())]
    pub file_name_length: u32,
    /// The name of the file.
    #[br(args { size: SizedStringSize::bytes(file_name_length) })]
    pub file_name: SizedWideString,
}

query_dir_type! {
    /// Query detailed information for the files in a directory.
    ///
    /// [MS-FSCC 2.4.8](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/270df317-9ba5-4ccb-ba00-8d22be139bc5>)
    pub struct FileBothDirectoryInformation {
        /// The length, in bytes, of the short name string.
        pub short_name_length: u8,
        #[bw(calc = 0)]
        _reserved1: u8,
        /// The short (8.3) name of the file.
        pub short_name: FileName83, // 8.3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainedItemList;
    use smb_tests::test_binrw;
    use time::macros::datetime;

    // A test for `FileIdBothDirectoryInformation` exists in `smv-msg` crate (for `QueryDirectoryRequest`).
    // pub Directory = 0x01,
    //     pub FullDirectory = 0x02,
    //     pub IdFullDirectory = 0x26,
    //     pub BothDirectory = 0x03,
    //     pub Names = 0x0c,
    //     pub IdExtdDirectory = 0x3c,

    //     pub Id64ExtdDirectory = 0x4e,
    //     pub Id64ExtdBothDirectory = 0x4f,
    //     pub IdAllExtdDirectory = 0x50,

    type DirectoryIdAllExtdBothList = ChainedItemList<
        FileIdAllExtdBothDirectoryInformation,
        { QueryDirectoryInfo::CHAINED_ALIGNMENT },
    >;

    // Some might think I'm more of a POSIX guy, since I use mac,
    // but tbh, I actually love windows, especially legacy edge DLLs,
    // which are the content of this test directory listing dump!
    test_binrw! {
        DirectoryIdAllExtdBothList: DirectoryIdAllExtdBothList::from(vec![
            FileIdAllExtdBothDirectoryInformation {
                file_index: 0,
                 creation_time: datetime!(2025-06-19 10:22:45.5282237).into(),
                 last_access_time: datetime!(2025-06-19 10:23:34.0915427).into(),
                 last_write_time: datetime!(2025-06-19 10:23:34.0915427).into(),
                 change_time: datetime!(2025-06-19 10:23:34.3246503).into(),
                 end_of_file: 0,
                 allocation_size: 0,
                 file_attributes: FileAttributes::new().with_directory(true),
                 ea_size: Some(0),
                 reparse_tag: None,
                 reparse_point_tag: 0,
                 file_id: 2814749767159075,
                 file_id_128: 2814749767159075,
                 short_name_length: 0,
                 short_name: FileName83::default(),
                 file_name: ".".into() },

            FileIdAllExtdBothDirectoryInformation {
                file_index: 0,
                 creation_time: datetime!(2025-04-04 22:18:11.7121314).into(),
                 last_access_time: datetime!(2025-10-13 17:58:05.9388514).into(),
                 last_write_time: datetime!(2025-10-13 17:58:05.9388514).into(),
                 change_time: datetime!(2025-10-13 17:58:05.9388514).into(),
                 end_of_file: 0,
                 allocation_size: 0,
                 file_attributes: FileAttributes::new().with_directory(true),
                 ea_size: Some(0),
                 reparse_tag: None,
                 reparse_point_tag: 0,
                 file_id: 1970324836975477,
                 file_id_128: 1970324836975477,
                 short_name_length: 0,
                 short_name: FileName83::default(),
                 file_name: "..".into() },

            FileIdAllExtdBothDirectoryInformation {
                file_index: 0,
                creation_time: datetime!(2025-06-19 10:22:45.6273816).into(),
                last_access_time: datetime!(2025-06-19 10:22:50.4411921).into(),
                last_write_time: datetime!(2025-04-04 23:07:27.4722084).into(),
                change_time: datetime!(2025-06-19 10:22:50.4411921).into(),
                 end_of_file: 16_757_760,
                 allocation_size: 16760832,
                 file_attributes: FileAttributes::new().with_archive(true),
                 ea_size: Some(128),
                 reparse_tag: None,
                 reparse_point_tag: 0,
                 file_id: 0x6900000000cd5a,
                 file_id_128: 0x6900000000cd5a,
                 short_name_length: 0,
                 short_name: FileName83::default(),
                 file_name: "BingMaps.dll".into() },

            FileIdAllExtdBothDirectoryInformation {
                file_index: 0,

                creation_time: datetime!(2025-06-19 10:22:50.8778222).into() ,
                last_access_time: datetime!(2025-06-19 10:22:54.6758575).into(),
                last_write_time: datetime!(2025-04-13 23:00:30.4054831).into(),
                change_time: datetime!(2025-06-19 10:22:54.6758575).into(),

                 end_of_file: 51_103_232,
                 allocation_size: 51105792,
                 file_attributes: FileAttributes::new().with_archive(true),
                 ea_size: Some(120),
                 reparse_tag: None,
                 reparse_point_tag: 0,
                 file_id: 0x3300000000cd68,
                 file_id_128: 0x3300000000cd68,
                 short_name_length: 0,
                 short_name: FileName83::default(),
                 file_name: "edgehtml.dll".into() },

            FileIdAllExtdBothDirectoryInformation {
                file_index: 0,
                creation_time: datetime!(2025-06-19 10:23:09.8691232).into(),
                last_access_time: datetime!(2025-06-19 10:23:14.1817596).into(),
                last_write_time: datetime!(2025-04-13 23:00:31.9102213).into(),
                change_time: datetime!(2025-06-19 10:23:14.1817596).into(),
                 end_of_file: 42_358_272,
                 allocation_size: 42360832,
                 file_attributes: FileAttributes::new().with_archive(true),
                 ea_size: Some(120),
                 reparse_tag: None,
                 reparse_point_tag: 0,
                 file_id: 0x1000000000ce21,
                 file_id_128: 0x1000000000ce21,
                 short_name_length: 0,
                 short_name: FileName83::default(),
                 file_name: "mshtml.dll".into() }
        ]) => "80000000000000003d22211904e1db01e34e133604e1db01e34e133604e1db01a7e0363604e1db01000000000000000000000000000000001000000002000000000000000000000023cd000000000a0023cd000000000a00000000000000000000000000000000000000000000000000000000000000000000002e0000000000800000000000000022fdbb73afa5db0162f647ed6a3cdc0162f647ed6a3cdc0162f647ed6a3cdc01000000000000000000000000000000001000000004000000000000000000000075030000000007007503000000000700000000000000000000000000000000000000000000000000000000000000000000002e002e00000098000000000000009843301904e1db0111cb0e1c04e1db01242f8155b6a5db0111cb0e1c04e1db0100b4ff000000000000c0ff0000000000200000001800000080000000000000005acd0000000069005acd00000000690000000000000000000000000000000000000000000000000000000000000000000000420069006e0067004d006100700073002e0064006c006c000000000000009800000000000000ee6a511c04e1db01aff3941e04e1db012f9aa1dac7acdb01aff3941e04e1db0100c60b030000000000d00b03000000002000000018000000780000000000000068cd00000000330068cd000000003300000000000000000000000000000000000000000000000000000000000000000000006500640067006500680074006d006c002e0064006c006c000000000000000000000000000000a042a32704e1db01fc50352a04e1db01053587dbc7acdb01fc50352a04e1db01005686020000000000608602000000002000000014000000780000000000000021ce00000000100021ce000000001000000000000000000000000000000000000000000000000000000000000000000000006d007300680074006d006c002e0064006c006c00"
    }
}
