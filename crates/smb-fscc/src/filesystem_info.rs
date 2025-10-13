use crate::file_info_classes;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::{Guid, binrw_util::prelude::*};

file_info_classes! {
    pub QueryFileSystemInfo {
        pub FsAttribute = 5,
        pub FsControl = 6,
        pub FsDevice = 4,
        pub FsFullSize = 7,
        pub FsObjectId = 8,
        pub FsSectorSize = 11,
        pub FsSize = 3,
        pub FsVolume = 1,
    }, Read
}

file_info_classes! {
    pub SetFileSystemInfo {
        pub FsControl = 6,
        pub FsObjectId = 8,
    }, Write
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsAttributeInformation {
    pub attributes: FileSystemAttributes,
    pub maximum_component_name_length: u32,
    #[bw(calc = file_system_name.len() as u32)]
    pub file_system_name_length: u32,
    #[br(args(file_system_name_length as u64))]
    pub file_system_name: SizedWideString,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FileSystemAttributes {
    pub case_sensitive_search: bool,
    pub case_preserved_names: bool,
    pub unicode_on_disk: bool,
    pub persistent_acls: bool,
    pub file_compression: bool,
    pub volume_quotas: bool,
    pub supports_sparse_files: bool,
    pub supports_reparse_points: bool,
    pub supports_remote_storage: bool,
    #[skip]
    __: B6,
    pub volume_is_compressed: bool,
    pub supports_object_ids: bool,
    pub supports_encryption: bool,
    pub named_streams: bool,
    pub read_only_volume: bool,
    pub sequential_write_once: bool,
    pub supports_transactions: bool,
    pub supports_hard_links: bool,
    pub supports_extended_attributes: bool,
    pub supports_open_by_file_id: bool,
    pub supports_usn_journal: bool,
    pub support_integrity_streams: bool,
    pub supports_block_refcounting: bool,
    pub supports_sparse_vdl: bool,
    #[skip]
    __: B3,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsControlInformation {
    pub free_space_start_filtering: u64,
    pub free_space_threshold: u64,
    pub free_space_stop_filtering: u64,
    pub default_quota_threshold: u64,
    pub default_quota_limit: u64,
    pub file_system_control_flags: FileSystemControlFlags,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsDeviceInformation {
    pub device_type: FsDeviceType,
    pub characteristics: FsDeviceCharacteristics,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u32))]
pub enum FsDeviceType {
    CdRom = 2,
    Disk = 7,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FsDeviceCharacteristics {
    /// Indicates that the storage device supports removable media.
    /// Notice that this characteristic indicates removable media, not a removable device.
    /// For example, drivers for JAZ drive devices specify this characteristic, but drivers for PCMCIA flash disks do not.
    pub removable_media: bool,
    pub read_only: bool,
    pub floppy_diskette: bool,
    pub write_once_media: bool,

    /// Indicates that the volume is for a remote file system like SMB or CIFS.
    pub remote: bool,
    pub device_is_mounted: bool,
    /// Indicates that the volume does not directly reside on storage media but resides on some other type of media (memory for example).
    pub virtual_volume: bool,
    #[skip]
    __: bool,

    pub secure_open: bool,
    #[skip]
    __: B3,

    pub ts: bool,
    pub webda: bool,
    #[skip]
    __: B3,

    pub allow_appcontainer_traversal: bool,
    pub portable: bool,
    #[skip]
    __: B13,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct FileSystemControlFlags {
    pub quota_track: bool,
    pub quota_enforce: bool,
    pub content_indexing_disabled: bool,
    #[skip]
    __: bool,

    pub log_quota_threshold: bool,
    pub log_quota_limit: bool,
    pub log_volume_threshold: bool,
    pub log_volume_limit: bool,

    pub quotas_incomplete: bool,
    pub quotas_rebuilding: bool,
    #[skip]
    __: B22,
}

/// This information class is used to query sector size information for a file system volume.
///
/// [MS-FSCC 2.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/63768db7-9012-4209-8cca-00781e7322f5)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsFullSizeInformation {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsObjectIdInformation {
    pub object_id: Guid,
    pub extended_info: [u8; 48],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsSectorSizeInformation {
    pub logical_bytes_per_sector: u32,
    pub physical_bytes_per_sector: u32,
    pub physical_bytes_per_sector_for_performance: u32,
    pub effective_physical_bytes_per_sector_for_atomicity: u32,
    pub flags: SectorSizeInfoFlags,
    pub byte_offset_for_sector_alignment: u32,
    pub byte_offset_for_partition_alignment: u32,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SectorSizeInfoFlags {
    pub aligned_device: bool,
    pub partition_aligned_on_device: bool,
    pub no_seek_penalty: bool,
    pub trim_enabled: bool,
    #[skip]
    __: B28,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsSizeInformation {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsVolumeInformation {
    pub volume_creation_time: FileTime,
    pub volume_serial_number: u32,
    #[bw(calc = volume_label.len() as u32)]
    pub volume_label_length: u32,
    pub supports_objects: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u8,
    #[br(args(volume_label_length as u64))]
    pub volume_label: SizedWideString,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_dtyp::make_guid;
    use smb_tests::test_binrw_read;
    use time::macros::datetime;

    test_binrw_read! {
        FileFsVolumeInformation {
            volume_creation_time: datetime!(2025-10-13 12:35:04.593237).into(),
            volume_serial_number: 0x529d2cf4,
            volume_label: "MyShare".into(),
            supports_objects: false.into(),
        }: [0x52, 0x51, 0x19, 0xcd, 0x3d, 0x3c, 0xdc, 0x1, 0xf4, 0x2c, 0x9d, 0x52, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x0, 0x79, 0x0, 0x53, 0x0, 0x68, 0x0, 0x61, 0x0, 0x72, 0x0, 0x65, 0x0]
    }

    test_binrw_read! {
        FileFsSizeInformation {
            total_allocation_units: 61202244,
            available_allocation_units: 45713576,
            sectors_per_allocation_unit: 2,
            bytes_per_sector: 512,
        }: [0x44, 0xdf, 0xa5, 0x3, 0x0, 0x0, 0x0, 0x0, 0xa8, 0x88, 0xb9, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0]
    }

    test_binrw_read! {
        FileFsFullSizeInformation {
            total_allocation_units: 0x03a5df44,
            actual_available_allocation_units: 0x02b98894,
            caller_available_allocation_units: 0x02b98894,
            sectors_per_allocation_unit: 2,
            bytes_per_sector: 512,
        }: [0x44, 0xdf, 0xa5, 0x3, 0x0, 0x0, 0x0, 0x0, 0x94, 0x88, 0xb9, 0x2, 0x0, 0x0, 0x0, 0x0, 0x94, 0x88, 0xb9, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0]
    }

    test_binrw_read! {
        FileFsDeviceInformation {
            device_type: FsDeviceType::Disk,
            characteristics: FsDeviceCharacteristics::new().with_device_is_mounted(true),
        }: [0x07, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]
    }

    test_binrw_read! {
        FileFsAttributeInformation {
            attributes: FileSystemAttributes::new()
                .with_case_sensitive_search(true)
                .with_case_preserved_names(true)
                .with_unicode_on_disk(true)
                .with_persistent_acls(true)
                .with_volume_quotas(true)
                .with_supports_sparse_files(true)
                .with_supports_object_ids(true)
                .with_named_streams(true),
            maximum_component_name_length: 255,
            file_system_name: "NTFS".into(),
        }: [0x6f, 0x0, 0x5, 0x0, 0xff, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x4e, 0x0, 0x54, 0x0, 0x46, 0x0, 0x53, 0x0]
    }

    test_binrw_read! {
        FileFsSectorSizeInformation {
            logical_bytes_per_sector: 512,
            physical_bytes_per_sector: 512,
            physical_bytes_per_sector_for_performance: 512,
            effective_physical_bytes_per_sector_for_atomicity: 512,
            flags: SectorSizeInfoFlags::new()
                .with_aligned_device(true)
                .with_partition_aligned_on_device(true),
            byte_offset_for_sector_alignment: 0,
            byte_offset_for_partition_alignment: 0,
        }: [0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    }

    test_binrw_read! {
        FileFsObjectIdInformation {
            object_id: make_guid!("ed3e2170-2733-48b3-e5c0-bd5334f85a37"),
            extended_info: [0x61, 0x42, 0x6d, 0x53, 0x0, 0x6, 0x14, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x34, 0x2e, 0x32, 0x30, 0x2e,
                            0x36, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        }: [0x70, 0x21, 0x3e, 0xed, 0x33, 0x27, 0xb3, 0x48, 0xe5, 0xc0, 0xbd, 0x53, 0x34, 0xf8, 0x5a, 0x37, 0x61, 0x42, 0x6d, 0x53, 0x0, 0x6, 0x14, 0x4, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x34, 0x2e, 0x32, 0x30, 0x2e, 0x36, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    }
}
