//! FSCTL codes and structs.
use binrw::{NullWideString, io::TakeSeekExt, prelude::*};
use modular_bitfield::prelude::*;
use smb_dtyp::binrw_util::prelude::*;

use crate::{Dialect, NegotiateSecurityMode};

use crate::dfsc::{ReqGetDfsReferral, ReqGetDfsReferralEx, RespGetDfsReferral};
use smb_dtyp::*;
use smb_fscc::*;

use super::common::IoctlRequestContent;
use crate::IoctlBuffer;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsctlCodes {
    DfsGetReferrals = 0x00060194,
    OffloadRead = 0x00094264,
    PipePeek = 0x0011400C,
    PipeWait = 0x00110018,
    PipeTransceive = 0x0011C017,
    SrvCopychunk = 0x001440F2,
    SrvEnumerateSnapshots = 0x00144064,
    SrvRequestResumeKey = 0x00140078,
    SrvReadHash = 0x001441bb,
    SrvCopychunkWrite = 0x001480F2,
    LmrRequestResiliency = 0x001401D4,
    QueryNetworkInterfaceInfo = 0x001401FC,
    SetReparsePoint = 0x000900A4,
    DfsGetReferralsEx = 0x000601B0,
    FileLevelTrim = 0x00098208,
    ValidateNegotiateInfo = 0x00140204,
    QueryAllocatedRanges = 0x000940CF,
}

/// The Length of source/dest keys in SrvCopyChunk* FSCTLs contents.
/// MS-SMB 2.2.31.1
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvCopychunkCopy {
    pub source_key: [u8; SrvCopychunkCopy::SRV_KEY_LENGTH],
    #[bw(try_calc = chunks.len().try_into())]
    chunk_count: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    #[br(count = chunk_count)]
    pub chunks: Vec<SrvCopychunkItem>,
}

impl SrvCopychunkCopy {
    pub const SRV_KEY_LENGTH: usize = 24;
    pub const SIZE: usize = Self::SRV_KEY_LENGTH + 4 + 4;
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvCopychunkItem {
    pub source_offset: u64,
    pub target_offset: u64,
    pub length: u32,
    #[bw(calc = 0)]
    _reserved: u32,
}

impl SrvCopychunkItem {
    pub const SIZE: usize = size_of::<u64>() * 2 + size_of::<u32>() * 2;
}

impl IoctlRequestContent for SrvCopychunkCopy {
    fn get_bin_size(&self) -> u32 {
        (Self::SIZE + self.chunks.len() * SrvCopychunkItem::SIZE) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvReadHashReq {
    /// Hash type MUST be 1 (SRV_HASH_TYPE_PEER_DIST)
    #[bw(calc = 1)]
    #[br(assert(hash_type == 1))]
    pub hash_type: u32,
    /// Hash version MUST be 1 or 2
    #[br(assert((1..=2).contains(&hash_version)))]
    #[bw(assert((1..=2).contains(hash_version)))]
    pub hash_version: u32,
    pub hash_retrieval_type: SrvHashRetrievalType,
}

impl IoctlRequestContent for SrvReadHashReq {
    fn get_bin_size(&self) -> u32 {
        size_of::<u32>() as u32 * 3
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum SrvHashRetrievalType {
    HashBased = 1,
    FileBased = 2,
}

/// Sent to request resiliency for a specified open file. This request is not valid for the SMB 2.0.2 dialect.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkResiliencyRequest {
    /// The requested time the server holds the file open after a disconnect before releasing it. This time is in milliseconds.
    pub timeout: u32,
    #[bw(calc = 0)]
    pub _reserved: u32,
}

impl IoctlRequestContent for NetworkResiliencyRequest {
    fn get_bin_size(&self) -> u32 {
        size_of::<u32>() as u32 * 2
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidateNegotiateInfoRequest {
    pub capabilities: u32,
    pub guid: Guid,
    pub security_mode: NegotiateSecurityMode,
    #[bw(try_calc = dialects.len().try_into())]
    dialect_count: u16,
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
}

impl IoctlRequestContent for ValidateNegotiateInfoRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>()
            + Guid::GUID_SIZE
            + 2
            + size_of::<u16>()
            + self.dialects.len() * size_of::<u16>()) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvSnapshotArray {
    pub number_of_snap_shots: u32,
    pub number_of_snap_shots_returned: u32,
    #[bw(calc = PosMarker::default())]
    pub snap_shot_array_size: PosMarker<u32>,
    #[br(parse_with = binrw::helpers::until_eof, map_stream = |s| s.take_seek(snap_shot_array_size.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&snap_shot_array_size))]
    pub snap_shots: Vec<NullWideString>,
}

/// A trait that helps parsing FSCTL responses by matching the FSCTL code.
pub trait FsctlResponseContent: for<'a> BinRead<Args<'a> = ()> + std::fmt::Debug {
    const FSCTL_CODES: &'static [FsctlCodes];
}

macro_rules! impl_fsctl_response {
    ($code:ident, $type:ty) => {
        impl FsctlResponseContent for $type {
            const FSCTL_CODES: &'static [FsctlCodes] = &[FsctlCodes::$code];
        }
    };
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvRequestResumeKey {
    pub resume_key: [u8; SrvCopychunkCopy::SRV_KEY_LENGTH],
    #[bw(calc = 0)]
    context_length: u32,
    /// This should always be set to empty, according to MS-SMB2 2.2.32.3
    #[br(count = context_length)]
    #[bw(assert(context.len() == context_length as usize))]
    pub context: Vec<u8>,
}

impl_fsctl_response!(SrvRequestResumeKey, SrvRequestResumeKey);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvCopychunkResponse {
    pub chunks_written: u32,
    pub chunk_bytes_written: u32,
    pub total_bytes_written: u32,
}

impl_fsctl_response!(SrvCopychunk, SrvCopychunkResponse);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvReadHashRes {
    /// Hash type MUST be 1 (SRV_HASH_TYPE_PEER_DIST)
    #[bw(calc = 1)]
    #[br(assert(hash_type == 1))]
    hash_type: u32,
    /// Hash version MUST be 1 or 2
    #[br(assert((1..=2).contains(&hash_version)))]
    #[bw(assert((1..=2).contains(hash_version)))]
    hash_version: u32,
    source_file_change_time: FileTime,
    source_file_size: u64,
    hash_blob_length: PosMarker<u32>,
    hash_blob_offset: PosMarker<u32>,
    dirty: u16,
    #[bw(try_calc = source_file_name.len().try_into())]
    source_file_name_length: u16,
    #[br(count = source_file_name_length)]
    source_file_name: Vec<u8>,
}

impl_fsctl_response!(SrvReadHash, SrvReadHashRes);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvHashRetrieveHashBased {
    pub offset: u64,
    #[bw(try_calc = blob.len().try_into())]
    buffer_length: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    /// TODO: Parse as Content Information File
    #[br(count = buffer_length)]
    blob: Vec<u8>,
}

impl_fsctl_response!(SrvReadHash, SrvHashRetrieveHashBased);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvHashRetrieveFileBased {
    pub file_data_offset: u64,
    pub file_data_length: u64,
    #[bw(try_calc = buffer.len().try_into())]
    buffer_length: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    /// TODO: Parse as Content Information File
    #[br(count = buffer_length)]
    pub buffer: Vec<u8>,
}

pub type NetworkInterfacesInfo = ChainedItemList<NetworkInterfaceInfo>;

impl_fsctl_response!(QueryNetworkInterfaceInfo, NetworkInterfacesInfo);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkInterfaceInfo {
    pub if_index: u32,
    pub capability: NetworkInterfaceCapability,
    #[bw(calc = 0)]
    _reserved: u32,
    pub link_speed: u64,
    // -- Inlined sockadd_storage for convenience and performance
    pub sockaddr: SocketAddrStorage,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NetworkInterfaceCapability {
    pub rss: bool,
    pub rdma: bool,
    #[skip]
    __: B30,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum SocketAddrStorage {
    V4(SocketAddrStorageV4),
    V6(SocketAddrStorageV6),
}

impl SocketAddrStorage {
    pub fn socket_addr(&self) -> SocketAddr {
        match self {
            SocketAddrStorage::V4(v4) => SocketAddr::V4(v4.to_addr()),
            SocketAddrStorage::V6(v6) => SocketAddr::V6(v6.to_addr()),
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\x02\x00"))] // InterNetwork
pub struct SocketAddrStorageV4 {
    pub port: u16,
    pub address: u32,
    #[bw(calc = [0; 128 - (2 + 2 + 4)])]
    _reserved: [u8; 128 - (2 + 2 + 4)],
}

impl SocketAddrStorageV4 {
    fn to_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(self.address.to_be()), self.port)
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\x17\x00"))] // InterNetworkV6
pub struct SocketAddrStorageV6 {
    pub port: u16,
    pub flow_info: u32,
    pub address: u128,
    pub scope_id: u32,
    #[bw(calc = [0; 128 - (2 + 2 + 4 + 16 + 4)])]
    _reserved: [u8; 128 - (2 + 2 + 4 + 16 + 4)],
}

impl SocketAddrStorageV6 {
    fn to_addr(&self) -> SocketAddrV6 {
        SocketAddrV6::new(
            Ipv6Addr::from(self.address.to_be()),
            self.port,
            self.flow_info,
            self.scope_id,
        )
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidateNegotiateInfoResponse {
    pub capabilities: u32,
    pub guid: Guid,
    pub security_mode: NegotiateSecurityMode,
    pub dialect: Dialect,
}

impl_fsctl_response!(ValidateNegotiateInfo, ValidateNegotiateInfoResponse);

// DFS get referrals FSCTLs.
impl FsctlResponseContent for RespGetDfsReferral {
    const FSCTL_CODES: &'static [FsctlCodes] =
        &[FsctlCodes::DfsGetReferrals, FsctlCodes::DfsGetReferralsEx];
}

impl IoctlRequestContent for ReqGetDfsReferral {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u16>() + (self.request_file_name.len() + 1) * size_of::<u16>()) as u32
    }
}

impl IoctlRequestContent for ReqGetDfsReferralEx {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u16>() * 2 + size_of::<u32>() + self.request_data.get_bin_size()) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryAllocRangesItem {
    pub offset: u64,
    pub len: u64,
}

impl IoctlRequestContent for QueryAllocRangesItem {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u64>() * 2) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct QueryAllocRangesResult {
    #[br(parse_with = binrw::helpers::until_eof)]
    values: Vec<QueryAllocRangesItem>,
}

impl Deref for QueryAllocRangesResult {
    type Target = Vec<QueryAllocRangesItem>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl From<Vec<QueryAllocRangesItem>> for QueryAllocRangesResult {
    fn from(value: Vec<QueryAllocRangesItem>) -> Self {
        Self { values: value }
    }
}

impl_fsctl_response!(QueryAllocatedRanges, QueryAllocRangesResult);

/// The FSCTL_PIPE_WAIT Request requests that the server wait until either a time-out interval elapses,
/// or an instance of the specified named pipe is available for connection.
///
/// [MS-FSCC 2.3.49](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f030a3b9-539c-4c7b-a893-86b795b9b711)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct PipeWaitRequest {
    /// specifies the maximum amount of time, in units of 100 milliseconds,
    /// that the function can wait for an instance of the named pipe to be available.
    pub timeout: u64,
    #[bw(calc = name.size() as u32)]
    name_length: u32,
    /// Whether the Timeout parameter will be ignored.
    /// FALSE Indicates that the server MUST wait forever. Any value in `timeout` must be ignored.
    pub timeout_specified: Boolean,
    #[bw(calc = 0)]
    _padding: u8,
    /// A Unicode string that contains the name of the named pipe. Name MUST not include the "\pipe\",
    /// so if the operation was on \\server\pipe\pipename, the name would be "pipename".
    #[br(args {size: SizedStringSize::bytes(name_length)})]
    pub name: SizedWideString,
}

impl IoctlRequestContent for PipeWaitRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u64>()
            + size_of::<u32>()
            + size_of::<Boolean>()
            + size_of::<u8>()
            + self.name.size() as usize) as u32
    }
}

/// Stores data for a reparse point.
///
/// [MS-FSCC 2.3.81](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc2b168-f177-4eec-a14b-25a51cbba2cf)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SetReparsePointRequest {
    /// Contains the reparse point tag that uniquely identifies the owner of the reparse point.
    #[bw(assert((reparse_tag & 0x80000000 == 0) == reparse_guid.is_some()))]
    pub reparse_tag: u32,
    #[bw(calc = reparse_data.len() as u32)]
    reparse_data_length: u32,
    /// Applicable only for reparse points that have a GUID.
    /// See [MS-FSCC 2.1.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a4d08374-0e92-43e2-8f88-88b94112f070)
    // Internal note: (HighBit(arseTag) == 0)Has
    #[br(if(reparse_tag & 0x80000000 == 0))]
    pub reparse_guid: Option<Guid>,
    /// Reparse-specific data for the reparse point
    #[br(count = reparse_data_length)]
    pub reparse_data: Vec<u8>,
}

impl IoctlRequestContent for SetReparsePointRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>()
            + size_of::<u32>()
            + self.reparse_guid.as_ref().map_or(0, |_| size_of::<Guid>())
            + self.reparse_data.len()) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileLevelTrimRequest {
    /// Reserved
    #[bw(calc = 0)]
    _key: u32,
    #[bw(calc = ranges.len() as u32)]
    num_ranges: u32,
    /// Array of ranges that describe the portions of the file that are to be trimmed.
    #[br(count = num_ranges)]
    pub ranges: Vec<FileLevelTrimRange>,
}

/// [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-file_level_trim_range)
///
/// Supports [`std::mem::size_of`].
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileLevelTrimRange {
    /// Offset, in bytes, from the start of the file for the range to be trimmed.
    pub offset: u64,
    /// Length, in bytes, for the range to be trimmed.
    pub length: u64,
}

impl IoctlRequestContent for FileLevelTrimRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>() + size_of::<u32>() + self.ranges.len() * size_of::<FileLevelTrimRange>())
            as u32
    }
}

/// [MS-FSCC 2.3.46](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6b6c8b8b-c5ac-4fa5-9182-619459fce7c7)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct PipePeekResponse {
    /// The current state of the pipe
    pub named_pipe_state: NamedPipeState,
    #[bw(calc = data.len() as u32)]
    /// The size, in bytes, of the data available to read from the pipe.
    read_data_available: u32,
    /// Specifies the number of messages available in the pipe if the pipe has been created as a message-type pipe. Otherwise, this field is 0
    pub number_of_messages: u32,
    /// Specifies the length of the first message available in the pipe if the pipe has been created as a message-type pipe. Otherwise, this field is 0.
    pub message_length: u32,
    /// The data from the pipe.
    #[br(count = read_data_available as u64)]
    pub data: Vec<u8>,
}

impl_fsctl_response!(PipePeek, PipePeekResponse);

/// [MS-SMB 2.2.7.2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/5a43eb29-50c8-46b6-8319-e793a11f6226)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvEnumerateSnapshotsResponse {
    /// The number of snapshots that the underlying object store contains of this file.
    pub number_of_snap_shots: u32,
    /// This value MUST be the number of snapshots that are returned in this response.
    /// If this value is less than NumberofSnapshots,
    /// then there are more snapshots than were able to fit in this response.
    pub number_of_snap_shots_returned: u32,
    /// The length, in bytes, of the SnapShotMultiSZ field.
    #[bw(calc = PosMarker::default())]
    snap_shot_array_size: PosMarker<u32>,
    /// A list of snapshots, described as strings, that take on the following form: @GMT-YYYY.MM.DD-HH.MM.SS
    #[br(map_stream = |s| s.take_seek(snap_shot_array_size.value as u64))]
    pub snap_shots: MultiSz,
}

impl_fsctl_response!(SrvEnumerateSnapshots, SrvEnumerateSnapshotsResponse);

/// [MS-FSCC 2.3.14](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b949a580-d8db-439b-a791-17ddc7565c4b)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileLevelTrimResponse {
    /// The number of input ranges that were processed.
    pub num_ranges_processed: u32,
}

impl_fsctl_response!(FileLevelTrim, FileLevelTrimResponse);

/// [MS-FSCC 2.3.41](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5d41cf62-9ebc-4f62-b7d7-0d085552b6dd)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct OffloadReadRequest {
    #[bw(calc = 0x20)]
    #[br(assert(_size == 0x20))]
    _size: u32,
    /// The flags to be set for this operation. Currently, no flags are defined.
    pub flags: u32,
    /// Time to Live (TTL) value in milliseconds for the generated Token. A value of 0 indicates a default TTL interval.
    pub token_time_to_live: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    /// the file offset, in bytes, of the start of a range of bytes in a file from which to generate the Token.
    /// MUST be aligned to a logical sector boundary on the volume.
    pub file_offset: u64,
    /// the requested range of the file from which to generate the Token.
    /// MUST be aligned to a logical sector boundary on the volume
    pub copy_length: u64,
}

impl IoctlRequestContent for OffloadReadRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>() * 4 + size_of::<u64>() * 2) as u32
    }
}

/// [MS-FSCC 2.3.42](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b98a8325-e6ec-464a-bc1b-8216b74f5828)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct OffloadReadResponse {
    #[bw(calc = 528)]
    #[br(assert(_size == 528))]
    _size: u32,

    // Note: this is a reduction of the flags field.
    /// The data beyond the current range is logically equivalent to zero.
    pub all_zero_beyond_current_range: Boolean,
    _padding: u8,
    _padding2: u16,

    /// contains the amount, in bytes, of data that the Token logically represents.
    /// This value indicates a contiguous region of the file from the beginning of the requested offset in the input.
    /// This value can be smaller than the CopyLength field specified in the request data element,
    /// which indicates that less data was logically represented (logically read) with the Token than was requested.
    pub transfer_length: u64,

    /// The generated Token to be used as a representation of the data contained within the portion of the file specified in the input request.
    /// The contents of this field MUST NOT be modified during subsequent operations.
    pub token: [u8; 512], // TODO: Parse as STORAGE_OFFLOAD_TOKEN
}

impl_fsctl_response!(OffloadRead, OffloadReadResponse);

/// This macro wraps an existing type into a newtype that implements the `IoctlRequestContent` trait.
/// It also provides a constructor and implements `From` and `Deref` traits for the new type.
///
/// It's made so we can easily create new types for ioctl requests without repeating boilerplate code,
/// and prevents collisions with existing types in the `IoctlReqData` enum.
macro_rules! make_newtype {
    ($vis:vis $name:ident($inner:ty)) => {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name(pub $inner);

        impl $name {
            pub fn new(inner: $inner) -> Self {
                Self(inner)
            }
        }

        impl From<$inner> for $name {
            fn from(inner: $inner) -> Self {
                Self(inner)
            }
        }

        impl Deref for $name {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

macro_rules! make_req_newtype {
    ($vis:vis $name:ident($inner:ty)) => {
        make_newtype!($vis $name($inner));
        impl IoctlRequestContent for $name {
            fn get_bin_size(&self) -> u32 {
                self.0.get_bin_size()
            }
        }
    }
}

macro_rules! make_res_newtype {
    ($fsctl:ident: $vis:vis $name:ident($inner:ty)) => {
        make_newtype!($vis $name($inner));
        impl FsctlResponseContent for $name {
            const FSCTL_CODES: &'static [FsctlCodes] = &[FsctlCodes::$fsctl];
        }
    }
}

make_req_newtype!(pub PipePeekRequest(()));
make_req_newtype!(pub SrvEnumerateSnapshotsRequest(()));
make_req_newtype!(pub SrvRequestResumeKeyRequest(()));
make_req_newtype!(pub QueryNetworkInterfaceInfoRequest(()));
make_req_newtype!(pub PipeTransceiveRequest(IoctlBuffer));
make_req_newtype!(pub SrvCopyChunkCopyWrite(SrvCopychunkCopy));

make_res_newtype!(
    PipeWait: pub PipeWaitResponse(())
);
make_res_newtype!(
    PipeTransceive: pub PipeTransceiveResponse(IoctlBuffer)
);
make_res_newtype!(
    SetReparsePoint: pub SetReparsePointResponse(())
);

make_res_newtype!(
    LmrRequestResiliency: pub LmrRequestResiliencyResponse(())
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fsctl_request_offload_write() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let req = OffloadReadRequest {
            flags: 0,
            token_time_to_live: 0,
            file_offset: 0,
            copy_length: 10485760,
        };
        req.write_le(&mut cursor).unwrap();
        assert_eq!(cursor.position(), req.get_bin_size() as u64);
        assert_eq!(
            cursor.into_inner(),
            [
                0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0
            ]
        );
    }

    #[test]
    fn test_fsctl_request_resumekey_read() {
        let data = [
            0x2d, 0x3, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x27, 0x11, 0x6a, 0x26, 0x30, 0xd2, 0xdb,
            0x1, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let mut cursor = std::io::Cursor::new(data);
        let req: SrvRequestResumeKey = SrvRequestResumeKey::read_le(&mut cursor).unwrap();
        assert_eq!(
            req,
            SrvRequestResumeKey {
                resume_key: [
                    0x2d, 0x3, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x27, 0x11, 0x6a, 0x26, 0x30, 0xd2,
                    0xdb, 0x1, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                ],
                context: vec![],
            }
        );
    }

    #[test]
    fn test_fsctl_copychunk_write() {
        let mut chunks = vec![];
        const CHUNK_SIZE: u32 = 1048576; // 1 MiB
        const TOTAL_SIZE: u32 = 10417096;
        let block_num = u32::div_ceil(TOTAL_SIZE, CHUNK_SIZE);
        for i in 0..block_num {
            chunks.push(SrvCopychunkItem {
                source_offset: (i * CHUNK_SIZE) as u64,
                target_offset: (i * CHUNK_SIZE) as u64,
                length: if i == block_num - 1 {
                    TOTAL_SIZE % CHUNK_SIZE
                } else {
                    CHUNK_SIZE
                },
            });
        }
        let req = SrvCopychunkCopy {
            source_key: [
                0x2d, 0x3, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x27, 0x11, 0x6a, 0x26, 0x30, 0xd2, 0xdb,
                0x1, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
            chunks,
        };
        let mut cursor = std::io::Cursor::new(Vec::new());
        req.write_le(&mut cursor).unwrap();
        assert_eq!(cursor.position(), req.get_bin_size() as u64);
        assert_eq!(
            cursor.into_inner(),
            [
                0x2d, 0x3, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x27, 0x11, 0x6a, 0x26, 0x30, 0xd2, 0xdb,
                0x1, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x90, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x90, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc8, 0xf3, 0xe, 0x0, 0x0, 0x0, 0x0,
                0x0
            ]
        )
    }

    #[test]
    fn test_fsctl_copychunk_reponse_read() {
        let data = [
            0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc8, 0xf3, 0x9e, 0x0,
        ];
        let mut cursor = std::io::Cursor::new(data);
        let res: SrvCopychunkResponse = SrvCopychunkResponse::read_le(&mut cursor).unwrap();
        assert_eq!(
            res,
            SrvCopychunkResponse {
                chunks_written: 10,
                chunk_bytes_written: 0,
                total_bytes_written: 10417096,
            }
        );
    }

    #[test]
    fn test_fsctl_query_alloc_ranges_resp() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd1, 0xb6, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut cursor = std::io::Cursor::new(data);
        let res = QueryAllocRangesResult::read_le(&mut cursor).unwrap();
        assert_eq!(
            res,
            QueryAllocRangesResult {
                values: vec![
                    QueryAllocRangesItem {
                        offset: 0,
                        len: 4096,
                    },
                    QueryAllocRangesItem {
                        offset: 8192,
                        len: 46801,
                    },
                ],
            }
        );
    }

    #[test]
    fn test_fsctl_query_network_interfaces_response_parse() {
        let data = [
            0x98, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xca, 0x9a, 0x3b, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0xac, 0x10, 0xcc, 0x84, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xca, 0x9a, 0x3b, 0x0, 0x0, 0x0, 0x0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfe,
            0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xc, 0x29, 0xff, 0xfe, 0x9f, 0x8b, 0xf3, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0,
        ];

        let mut cursor = std::io::Cursor::new(data);
        let res = NetworkInterfacesInfo::read_le(&mut cursor).unwrap();
        assert_eq!(
            NetworkInterfacesInfo::from(vec![
                NetworkInterfaceInfo {
                    if_index: 2,
                    capability: NetworkInterfaceCapability::new().with_rdma(true),
                    link_speed: 1000000000,
                    sockaddr: SocketAddrStorage::V4(SocketAddrStorageV4 {
                        port: 0,
                        address: 0xac10cc84u32.to_be(),
                    })
                },
                NetworkInterfaceInfo {
                    if_index: 2,
                    capability: NetworkInterfaceCapability::new().with_rdma(true),
                    link_speed: 1000000000,
                    sockaddr: SocketAddrStorage::V6(SocketAddrStorageV6 {
                        port: 0,
                        flow_info: 0,
                        address: 0xfe80000000000000020c29fffe9f8bf3u128.to_be(),
                        scope_id: 0,
                    })
                },
            ]),
            res
        );
    }
}
