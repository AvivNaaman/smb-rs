//! Create & Close (files) requests and responses.

use std::fmt::{Debug, Display};
use std::io::{Cursor, SeekFrom};

use super::header::Status;
use super::*;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::SecurityDescriptor;
use smb_dtyp::{Guid, binrw_util::prelude::*};
use smb_fscc::*;

/// 2.2.14.1: SMB2_FILEID
#[binrw::binrw]
#[derive(PartialEq, Eq, Clone, Copy, Default)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    pub const EMPTY: FileId = FileId {
        persistent: 0,
        volatile: 0,
    };
    /// A file ID that is used to indicate that the file ID is not valid,
    /// with setting all bits to 1 - {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}.
    pub const FULL: FileId = FileId {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };
}

impl From<[u8; 16]> for FileId {
    fn from(data: [u8; 16]) -> Self {
        let mut cursor = Cursor::new(data);
        Self::read_le(&mut cursor).unwrap()
    }
}

impl From<Guid> for FileId {
    fn from(guid: Guid) -> Self {
        let mut cursor = Cursor::new(Vec::new());
        guid.write_le(&mut cursor).unwrap();
        <Self as From<[u8; 16]>>::from(cursor.into_inner().try_into().unwrap())
    }
}

impl Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{:x}|{:x}}}", self.persistent, self.volatile)
    }
}

impl Debug for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileId({})", self)
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct CreateRequest {
    #[bw(calc = 57)]
    #[br(assert(_structure_size == 57))]
    _structure_size: u16,
    #[bw(calc = 0)] // reserved
    #[br(assert(_security_flags == 0))]
    _security_flags: u8,
    pub requested_oplock_level: OplockLevel,
    pub impersonation_level: ImpersonationLevel,
    #[bw(calc = 0)]
    #[br(assert(_smb_create_flags == 0))]
    _smb_create_flags: u64,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u64,
    pub desired_access: FileAccessMask,
    pub file_attributes: FileAttributes,
    pub share_access: ShareAccessFlags,
    pub create_disposition: CreateDisposition,
    pub create_options: CreateOptions,
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(try_calc = name.size().try_into())]
    name_length: u16, // bytes
    #[bw(calc = PosMarker::default())]
    _create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _create_contexts_length: PosMarker<u32>,

    #[brw(align_before = 8)]
    #[bw(write_with = PosMarker::write_aoff, args(&_name_offset))]
    #[br(args(name_length as u64))]
    pub name: SizedWideString,

    /// Use the `CreateContextReqData::first_...` function family to get the first context of a specific type.
    #[brw(align_before = 8)]
    #[br(map_stream = |s| s.take_seek(_create_contexts_length.value.into()))]
    #[bw(write_with = PosMarker::write_roff_size, args(&_create_contexts_offset, &_create_contexts_length))]
    pub contexts: ChainedItemList<ReqCreateContext, 8>,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u32))]
pub enum ImpersonationLevel {
    Anonymous = 0x0,
    Identification = 0x1,
    Impersonation = 0x2,
    Delegate = 0x3,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[brw(repr(u32))]
pub enum CreateDisposition {
    Superseded = 0x0,
    #[default]
    Open = 0x1,
    Create = 0x2,
    OpenIf = 0x3,
    Overwrite = 0x4,
    OverwriteIf = 0x5,
}

#[bitfield]
#[derive(BinWrite, BinRead, Default, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CreateOptions {
    pub directory_file: bool,
    pub write_through: bool,
    pub sequential_only: bool,
    pub no_intermediate_buffering: bool,

    pub synchronous_io_alert: bool,
    pub synchronous_io_nonalert: bool,
    pub non_directory_file: bool,
    #[skip]
    __: bool,

    pub complete_if_oplocked: bool,
    pub no_ea_knowledge: bool,
    pub open_remote_instance: bool,
    pub random_access: bool,

    pub delete_on_close: bool,
    pub open_by_file_id: bool,
    pub open_for_backup_intent: bool,
    pub no_compression: bool,

    pub open_requiring_oplock: bool,
    pub disallow_exclusive: bool,
    #[skip]
    __: B2,

    pub reserve_opfilter: bool,
    pub open_reparse_point: bool,
    pub open_no_recall: bool,
    pub open_for_free_space_query: bool,

    #[skip]
    __: B8,
}

// share_access 4 byte flags:
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ShareAccessFlags {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    #[skip]
    __: B29,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct CreateResponse {
    #[bw(calc = 89)]
    #[br(assert(_structure_size == 89))]
    _structure_size: u16,
    pub oplock_level: OplockLevel,
    pub flags: CreateResponseFlags,
    pub create_action: CreateAction,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,
    pub file_id: FileId,
    // assert it's 8-aligned
    #[br(assert(create_contexts_offset.value & 0x7 == 0))]
    #[bw(calc = PosMarker::default())]
    create_contexts_offset: PosMarker<u32>, // from smb header start
    #[bw(calc = PosMarker::default())]
    create_contexts_length: PosMarker<u32>, // bytes

    /// Use the `CreateContextRespData::first_...` function family to get the first context of a specific type.
    #[br(seek_before = SeekFrom::Start(create_contexts_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(create_contexts_length.value.into()))]
    #[bw(write_with = PosMarker::write_roff_size, args(&create_contexts_offset, &create_contexts_length))]
    pub create_contexts: ChainedItemList<RespCreateContext, 8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CreateResponseFlags {
    pub reparsepoint: bool,
    #[skip]
    __: B7,
}

// CreateAction
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum CreateAction {
    Superseded = 0x0,
    Opened = 0x1,
    Created = 0x2,
    Overwritten = 0x3,
}

/// This is meant to be used within a [`ChainedItemList`] or [`ChainedItem<T>`]!
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(is_last: bool))]
#[allow(clippy::manual_non_exhaustive)]
pub struct CreateContext<T>
where
    for<'a> T: BinRead<Args<'a> = (&'a Vec<u8>,)> + BinWrite<Args<'static> = ()>,
{
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(name.len()).unwrap())]
    name_length: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = PosMarker::default())]
    _data_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    _data_length: PosMarker<u32>,

    #[brw(align_before = 8)]
    #[br(count = name_length)]
    #[bw(write_with = PosMarker::write_roff_plus, args(&_name_offset, CHAINED_ITEM_PREFIX_SIZE as u64))]
    pub name: Vec<u8>,

    #[brw(align_before = 8)]
    #[bw(write_with = PosMarker::write_roff_size_b_plus, args(&_data_offset, &_data_length, &_name_offset, CHAINED_ITEM_PREFIX_SIZE as u64))]
    #[br(map_stream = |s| s.take_seek(_data_length.value.into()), args(&name))]
    pub data: T,
}

macro_rules! create_context_half {
    (
        $struct_name:ident {
            $(
                $context_type:ident : $req_type:ty,
            )+
        }
    ) => {
    paste::paste! {

pub trait [<CreateContextData $struct_name Value>] : Into<CreateContext<[<CreateContext $struct_name Data>]>> {
    const CONTEXT_NAME: &'static [u8];
}

#[doc = concat!("The `", stringify!($struct_name), "` Create Context data enum. This contains all the possible context types for ", stringify!($struct_name))]
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(name: &Vec<u8>))]
pub enum [<CreateContext $struct_name Data>] {
    $(
        #[br(pre_assert(name.as_slice() == CreateContextType::[<$context_type:upper>].name()))]
        [<$context_type:camel $struct_name>]($req_type),
    )+
}

impl [<CreateContext $struct_name Data>] {
    pub fn name(&self) -> &'static [u8] {
        match self {
            $(
                Self::[<$context_type:camel $struct_name>](_) => CreateContextType::[<$context_type:upper _NAME>],
            )+
        }
    }

    $(
        pub fn [<as_ $context_type:snake>](&self) -> Option<&$req_type> {
            match self {
                Self::[<$context_type:camel $struct_name>](a) => Some(a),
                _ => None,
            }
        }

        pub fn [<first_ $context_type:snake>](val: &Vec<CreateContext<Self>>) -> Option<&$req_type> {
            for ctx in val {
                if let Self::[<$context_type:camel $struct_name>](a) = &ctx.data {
                    return Some(a);
                }
            }
            None
        }
    )+
}

$(
    impl [<CreateContextData $struct_name Value>] for $req_type {
        const CONTEXT_NAME: &'static [u8] = CreateContextType::[<$context_type:upper _NAME>];
    }

    impl From<$req_type> for CreateContext<[<CreateContext $struct_name Data>]> {
        fn from(req: $req_type) -> Self {
            CreateContext::<[<CreateContext $struct_name Data>]> {
                name: <$req_type as [<CreateContextData $struct_name Value>]>::CONTEXT_NAME.to_vec(),
                data: [<CreateContext $struct_name Data>]::[<$context_type:camel $struct_name>](req),
            }
        }
    }

    impl TryInto<$req_type> for CreateContext<[<CreateContext $struct_name Data>]> {
        type Error = crate::SmbMsgError;
        fn try_into(self) -> crate::Result<$req_type> {
            match self.data {
                [<CreateContext $struct_name Data>]::[<$context_type:camel $struct_name>](a) => Ok(a),
                _ => Err(crate::SmbMsgError::UnexpectedContent {
                    expected: stringify!($req_type),
                    actual: "", // self.data.name(), TODO: Fix this by making name() a string.
                }),
            }
        }
    }
)+

pub type [<$struct_name CreateContext>] = CreateContext<[<CreateContext $struct_name Data>]>;
        }
    }
}

macro_rules! make_create_context {
    (
        $($context_type:ident : $class_name:literal, $req_type:ident, $res_type:ident, )+
    ) => {
        paste::paste!{

pub enum CreateContextType {
    $(
        [<$context_type:upper>],
    )+
}

impl CreateContextType {
    $(
        pub const [<$context_type:upper _NAME>]: &[u8] = $class_name;
    )+

    pub fn from_name(name: &[u8]) -> Option<CreateContextType> {
        match name {
            $(
                Self::[<$context_type:upper _NAME>] => Some(Self::[<$context_type:upper>]),
            )+
            _ => None,
        }
    }

    pub fn name(&self) -> &[u8] {
        match self {
            $(
                Self::[<$context_type:upper>] => Self::[<$context_type:upper _NAME>],
            )+
        }
    }
}
        }

        create_context_half! {
            Req {
                $($context_type: $req_type,)+
            }
        }

        create_context_half! {
            Resp {
                $($context_type: $res_type,)+
            }
        }
    }
}

make_create_context!(
    exta: b"ExtA", EaBuffer, EaBuffer,
    secd: b"SecD", SdBuffer, SdBuffer,
    dhnq: b"DHnQ", DurableHandleRequest, DurableHandleResponse,
    dhnc: b"DHNc", DurableHandleReconnect, DurableHandleReconnect,
    alsi: b"AlSi", AllocationSize, AllocationSize,
    mxac: b"MxAc", QueryMaximalAccessRequest,  QueryMaximalAccessResponse,
    twrp: b"TWrp", TimewarpToken, TimewarpToken,
    qfid: b"QFid", QueryOnDiskIdReq,  QueryOnDiskIdResp,
    rqls: b"RqLs", RequestLease, RequestLease, // v1+2
    dh2q: b"DH2Q", DurableHandleRequestV2, DH2QResp,
    dh2c: b"DH2C", DurableHandleReconnectV2, DurableHandleReconnectV2,
    appinstid: b"\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74", AppInstanceId, AppInstanceId,
    appinstver: b"\xB9\x82\xD0\xB7\x3B\x56\x07\x4F\xA0\x7B\x52\x4A\x81\x16\xA0\x10", AppInstanceVersion, AppInstanceVersion,
    svhdxopendev: b"\x9C\xCB\xCF\x9E\x04\xC1\xE6\x43\x98\x0E\x15\x8D\xA1\xF6\xEC\x83", SvhdxOpenDeviceContext, SvhdxOpenDeviceContext,
);

macro_rules! empty_req {
    ($name:ident) => {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name;
    };
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct EaBuffer {
    #[br(parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = FileFullEaInformationCommon::write_chained)]
    info: Vec<FileFullEaInformationCommon>,
}

pub type SdBuffer = SecurityDescriptor;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DurableHandleRequest {
    #[bw(calc = 0)]
    #[br(assert(durable_request == 0))]
    durable_request: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DurableHandleResponse {
    #[bw(calc = 0)]
    _reserved: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DurableHandleReconnect {
    pub durable_request: FileId,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct QueryMaximalAccessRequest {
    pub timestamp: Option<FileTime>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AllocationSize {
    pub allocation_size: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TimewarpToken {
    pub tiemstamp: FileTime,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum RequestLease {
    RqLsReqv1(RequestLeaseV1),
    RqLsReqv2(RequestLeaseV2),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct RequestLeaseV1 {
    pub lease_key: u128,
    pub lease_state: LeaseState,
    #[bw(calc = 0)]
    #[br(assert(lease_flags == 0))]
    lease_flags: u32,
    #[bw(calc = 0)]
    #[br(assert(lease_duration == 0))]
    lease_duration: u64,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct RequestLeaseV2 {
    pub lease_key: u128,
    pub lease_state: LeaseState,
    #[br(assert(lease_flags == 0 || lease_flags == 4))]
    pub lease_flags: u32,
    #[bw(calc = 0)]
    #[br(assert(lease_duration == 0))]
    lease_duration: u64,
    pub parent_lease_key: u128,
    pub epoch: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

empty_req!(QueryOnDiskIdReq);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DurableHandleRequestV2 {
    pub timeout: u32,
    pub flags: DurableHandleV2Flags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u64,
    pub create_guid: Guid,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct DurableHandleV2Flags {
    #[skip]
    __: bool,
    pub persistent: bool, // 0x2
    #[skip]
    __: B30,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DurableHandleReconnectV2 {
    file_id: FileId,
    create_guid: Guid,
    flags: DurableHandleV2Flags,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AppInstanceId {
    #[bw(calc = 20)]
    #[br(assert(structure_size == 20))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub app_instance_id: Guid,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AppInstanceVersion {
    #[bw(calc = 24)]
    #[br(assert(structure_size == 24))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,
    pub app_instance_version_high: u64,
    pub app_instance_version_low: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum SvhdxOpenDeviceContext {
    V1(SvhdxOpenDeviceContextV1),
    V2(SvhdxOpenDeviceContextV2),
}

/// [MS-RSVD sections 2.2.4.12 and 2.2.4.32.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rsvd/6ec20c83-a6a7-49d5-ae60-72070f91d5e0)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SvhdxOpenDeviceContextV1 {
    pub version: u32,
    pub has_initiator_id: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved1 == 0))]
    reserved1: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    pub initiator_id: Guid,
    pub flags: u32,
    pub originator_flags: u32,
    pub open_request_id: u64,
    pub initiator_host_name_length: u16,
    pub initiator_host_name: [u16; 126 / 2],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SvhdxOpenDeviceContextV2 {
    pub version: u32,
    pub has_initiator_id: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved1 == 0))]
    reserved1: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    pub initiator_id: Guid,
    pub flags: u32,
    pub originator_flags: u32,
    pub open_request_id: u64,
    pub initiator_host_name_length: u16,
    pub initiator_host_name: [u16; 126 / 2],
    pub virtual_disk_properties_initialized: u32,
    pub server_service_version: u32,
    pub virtual_sector_size: u32,
    pub physical_sector_size: u32,
    pub virtual_size: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryMaximalAccessResponse {
    pub query_status: Status,
    pub maximal_access: FileAccessMask,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryOnDiskIdResp {
    pub file_id: u64,
    pub volume_id: u64,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DH2QResp {
    pub timeout: u32,
    pub flags: DurableHandleV2Flags,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct CloseRequest {
    #[bw(calc = 24)]
    #[br(assert(_structure_size == 24))]
    _structure_size: u16,
    #[bw(calc = CloseFlags::new().with_postquery_attrib(true))]
    #[br(assert(_flags == CloseFlags::new().with_postquery_attrib(true)))]
    _flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    pub file_id: FileId,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct CloseResponse {
    #[bw(calc = 60)]
    #[br(assert(_structure_size == 60))]
    _structure_size: u16,
    pub flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CloseFlags {
    pub postquery_attrib: bool,
    #[skip]
    __: B15,
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    #[test]
    pub fn test_create_request_written_correctly() {
        let file_name = "hello";
        let request = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::from_bytes(0x00100081u32.to_le_bytes()),
            file_attributes: FileAttributes::new(),
            share_access: ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true),
            create_disposition: CreateDisposition::Open,
            create_options: CreateOptions::new()
                .with_synchronous_io_nonalert(true)
                .with_disallow_exclusive(true),
            name: file_name.into(),
            contexts: vec![
                DurableHandleRequestV2 {
                    timeout: 0,
                    flags: DurableHandleV2Flags::new(),
                    create_guid: 0x821680290c007b8b11efc0a0c679a320u128.to_le_bytes().into(),
                }
                .into(),
                QueryMaximalAccessRequest::default().into(),
                QueryOnDiskIdReq.into(),
            ]
            .into(),
        };
        let data_without_header = encode_content(request.into());
        assert_eq!(
            data_without_header,
            vec![
                0x39, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x81, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x7, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x20, 0x0, 0x2, 0x0, 0x78, 0x0, 0xa, 0x0,
                0x88, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x68, 0x0, 0x65, 0x0, 0x6c, 0x0, 0x6c,
                0x0, 0x6f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x10, 0x0, 0x4,
                0x0, 0x0, 0x0, 0x18, 0x0, 0x20, 0x0, 0x0, 0x0, 0x44, 0x48, 0x32, 0x51, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x20, 0xa3, 0x79, 0xc6, 0xa0, 0xc0, 0xef, 0x11, 0x8b, 0x7b, 0x0, 0xc,
                0x29, 0x80, 0x16, 0x82, 0x18, 0x0, 0x0, 0x0, 0x10, 0x0, 0x4, 0x0, 0x0, 0x0, 0x18,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x78, 0x41, 0x63, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x10, 0x0, 0x4, 0x0, 0x0, 0x0, 0x18, 0x0, 0x0, 0x0, 0x0, 0x0, 0x51, 0x46,
                0x69, 0x64, 0x0, 0x0, 0x0, 0x0
            ]
        )
    }

    #[test]
    pub fn test_create_response_parsed_correctly() {
        let data: [u8; 240] = [
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x01, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x61, 0x00,
            0x00, 0x14, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x3c, 0x08, 0x38, 0x96, 0xae, 0x4b, 0xdb, 0x01, 0xc8, 0x55, 0x4b, 0x70,
            0x6b, 0x58, 0xdb, 0x01, 0x62, 0x0c, 0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x01, 0x62, 0x0c,
            0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x49, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x4d, 0x78, 0x41, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01,
            0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00,
            0x20, 0x00, 0x00, 0x00, 0x51, 0x46, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x2a, 0xe7,
            0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xd9, 0xcf, 0x17, 0xb0, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let m = decode_content(&data).content.to_create().unwrap();
        assert_eq!(
            m,
            CreateResponse {
                oplock_level: OplockLevel::None,
                flags: CreateResponseFlags::new(),
                create_action: CreateAction::Opened,
                creation_time: 133783827154208828.into(),
                last_access_time: 133797832406291912.into(),
                last_write_time: 133783939554544738.into(),
                change_time: 133783939554544738.into(),
                allocation_size: 0,
                endof_file: 0,
                file_attributes: FileAttributes::new().with_directory(true),
                file_id: 950737950337192747837452976457u128.to_le_bytes().into(),
                create_contexts: vec![
                    QueryMaximalAccessResponse {
                        query_status: Status::Success,
                        maximal_access: FileAccessMask::from_bytes(0x001f01ffu32.to_le_bytes()),
                    }
                    .into(),
                    QueryOnDiskIdResp {
                        file_id: 0x400000001e72a,
                        volume_id: 0xb017cfd9,
                    }
                    .into(),
                ]
                .into()
            }
        )
    }
}
