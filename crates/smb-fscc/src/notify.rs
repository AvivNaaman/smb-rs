//! Directory Change Notifications
//!
//! [MS-FSCC 2.7](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/8e8b7296-fb56-42d7-bfec-3fc1f59d5fa0>)

use smb_dtyp::binrw_util::prelude::*;

/// FILE_NOTIFY_INFORMATION - [MS-FSCC 2.7.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9>)
///
/// This structure is similar to the references struct, excluding the NextEntryOffset field. Use [`ChainedItemList<FileNotifyInformation>`] to represent a list of these structures.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(has_next: bool))]
pub struct FileNotifyInformation {
    pub action: NotifyAction,
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args { size: SizedStringSize::Bytes(file_name_length.into())})]
    pub file_name: SizedWideString,
}

/// See [`FileNotifyInformation`]
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NotifyAction {
    /// The file was renamed, and FileName contains the new name.
    /// This notification is only sent when the rename operation changes the directory the file resides in.
    /// The client will also receive a FILE_ACTION_REMOVED notification.
    /// This notification will not be received if the file is renamed within a directory.
    Added = 0x1,

    /// The file was renamed, and FileName contains the old name.
    /// This notification is only sent when the rename operation changes the directory the file resides in.
    /// The client will also receive a FILE_ACTION_ADDED notification.
    /// This notification will not be received if the file is renamed within a directory.
    Removed = 0x2,

    /// The file was modified. This can be a change to the data or attributes of the file.
    Modified = 0x3,

    /// The file was renamed, and FileName contains the old name.
    /// This notification is only sent when the rename operation does not change the directory the file resides in.
    /// The client will also receive a FILE_ACTION_RENAMED_NEW_NAME notification. This notification will not be received if the file is renamed to a different directory.
    RenamedOldName = 0x4,

    /// The file was renamed, and FileName contains the new name.
    /// This notification is only sent when the rename operation does not change the directory the file resides in.
    /// The client will also receive a FILE_ACTION_RENAMED_OLD_NAME notification. This notification will not be received if the file is renamed to a different directory.
    RenamedNewName = 0x5,

    /// The file was added to a named stream.
    AddedStream = 0x6,

    /// The file was removed from the named stream.
    RemovedStream = 0x7,

    /// The file was modified. This can be a change to the data or attributes of the file.
    ModifiedStream = 0x8,

    /// An object ID was removed because the file the object ID referred to was deleted.
    ///
    /// This notification is only sent when the directory being monitored is the special directory "\$Extend\$ObjId:$O:$INDEX_ALLOCATION".
    RemovedByDelete = 0x9,

    /// An attempt to tunnel object ID information to a file being created or renamed failed because the object ID is in use by another file on the same volume.
    ///
    /// This notification is only sent when the directory being monitored is the special directory "\$Extend\$ObjId:$O:$INDEX_ALLOCATION".
    IdNotTunnelled = 0xa,

    /// An attempt to tunnel object ID information to a file being renamed failed because the file already has an object ID.
    ///
    /// This notification is only sent when the directory being monitored is the special directory "\$Extend\$ObjId:$O:$INDEX_ALLOCATION".
    TunnelledIdCollision = 0xb,
}
