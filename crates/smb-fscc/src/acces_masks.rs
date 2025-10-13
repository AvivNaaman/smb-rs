//! Access masks definitions.

use modular_bitfield::prelude::*;
use smb_dtyp::access_mask;

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

impl From<DirAccessMask> for FileAccessMask {
    fn from(val: DirAccessMask) -> Self {
        // The bits are the same, just the names are different.
        FileAccessMask::from_bytes(val.into_bytes())
    }
}
