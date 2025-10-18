//! Access masks definitions.

use modular_bitfield::prelude::*;
use smb_dtyp::access_mask;

access_mask! {
    /// File Access Mask
    ///
    /// This is actually taken from the SMB2 protocol, but the bits are the same as
    /// the ones used in FSCC for files.
    /// In the SMB2 protocol, it also applied to pipes and printers.
    ///
    /// See [MS-SMB2 2.2.13.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/77b36d0f-6016-458a-a7a0-0f4a72ae1534) - File_Pipe_Printer_Access_Mask
pub struct FileAccessMask {
    /// The right to read data from the file.
    file_read_data: bool,
    /// The right to write data into the file beyond the end of the file.
    file_write_data: bool,
    /// The right to append data into the file.
    file_append_data: bool,
    /// The right to read the extended attributes of the file.
    file_read_ea: bool,

    /// The right to write or change the extended attributes to the file.
    file_write_ea: bool,
    /// The right to execute the file.
    file_execute: bool,
    /// The right to delete entries within a directory.
    file_delete_child: bool,
    /// The right to read the attributes of the file.
    file_read_attributes: bool,

    /// The right to change the attributes of the file.
    file_write_attributes: bool,
    #[skip]
    __: B7,
}}

access_mask! {
    /// Directory Access Mask
    ///
    /// This is actually taken from the SMB2 protocol, but the bits are the same as
    /// the ones used in FSCC for directories.
    ///
    /// See [MS-SMB2 2.2.13.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0a5934b1-80f1-4da0-b1bf-5e021c309b71) - Directory_Access_Mask
    pub struct DirAccessMask {
        /// The right to enumerate the contents of the directory.
        list_directory: bool,
        /// The right to create a file under the directory.
        add_file: bool,
        /// The right to add a sub-directory under the directory.
        add_subdirectory: bool,
        /// The right to read the extended attributes of the directory.
        read_ea: bool,

        /// The right to write or change the extended attributes of the directory.
        write_ea: bool,
        /// The right to traverse this directory if the server enforces traversal checking.
        traverse: bool,
        /// The right to delete the files and directories within this directory.
        delete_child: bool,
        /// The right to read the attributes of the directory.
        read_attributes: bool,

        /// The right to change the attributes of the directory.
        write_attributes: bool,
        #[skip]
        __: B7,
    }
}

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
