use crate::{
    file_info_classes,
    packets::{binrw_util::prelude::*, guid::Guid},
};
use binrw::prelude::*;
use modular_bitfield::prelude::*;

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
    pub removable_media: bool,
    pub read_only: bool,
    pub floppy_diskette: bool,
    pub write_once_media: bool,

    pub remote: bool,
    pub device_is_mounted: bool,
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
    pub volume_label_length: u32,
    pub supports_objects: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u8,
    #[br(args(volume_label_length as u64))]
    pub volume_label: SizedWideString,
}
