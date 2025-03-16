use crate::packets::{
    binrw_util::prelude::*,
    security::{ClaimSecurityAttributeRelativeV1, ACL, SID},
};
use binrw::prelude::*;
use binrw::{io::TakeSeekExt, NullWideString};
use modular_bitfield::prelude::*;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeConnectRequestFlags {
    pub cluster_reconnect: bool,
    pub redirect_to_owner: bool,
    pub extension_present: bool,
    #[skip]
    __: B13,
}

/// Tree Connect Request
///
/// Supports both the base and extension variants.
/// - On read, uses extension iff `flags.extension_present()` - parses just like the server intends.
/// - On write, uses extension iff `tree_connect_contexts` is non-empty.
#[binrw::binrw]
#[derive(Debug)]
pub struct TreeConnectRequest {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    pub flags: TreeConnectRequestFlags,
    #[bw(calc = PosMarker::default())]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.size().try_into())]
    path_length: u16,

    // -- Extension --
    #[br(if(flags.extension_present()))]
    #[bw(calc = if tree_connect_contexts.len() > 0 { Some(PosMarker::default())} else {None})]
    tree_connect_context_offset: Option<PosMarker<u32>>,
    #[br(if(flags.extension_present()))]
    #[bw(if(tree_connect_contexts.len() > 0))]
    #[bw(calc = if tree_connect_contexts.len() > 0 { Some(tree_connect_contexts.len().try_into().unwrap()) } else {None})]
    tree_connect_context_count: Option<u16>,
    #[br(if(flags.extension_present()))]
    #[bw(if(tree_connect_contexts.len() > 0))]
    #[bw(calc = Some([0u8; 10]))]
    _reserved: Option<[u8; 10]>,
    // -- Extension End --
    // ------------------------------------------------
    // -- Base --
    #[brw(little)]
    #[br(args(path_length as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&_path_offset))]
    pub buffer: SizedWideString,

    // -- Extension --
    #[br(if(flags.extension_present()))]
    #[br(seek_before = tree_connect_context_offset.unwrap().seek_relative(true))]
    #[br(count = tree_connect_context_count.unwrap())]
    #[bw(if(tree_connect_contexts.len() > 0))]
    #[bw(write_with = PosMarker::write_aoff_m, args(tree_connect_context_offset.as_ref()))]
    tree_connect_contexts: Vec<TreeConnectContext>,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeConnectContext {
    /// MS-SMB2 2.2.9.2: Must be set to SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID = 1.
    #[bw(calc = 1)]
    #[br(assert(context_type == 1))]
    context_type: u16,
    data_length: u16,
    reserved: u32,
    data: RemotedIdentityTreeConnect,
}

macro_rules! make_remoted_identity_connect{
    (
        $($field:ident: $value:ty),*
    ) => {
        paste::paste! {

#[binrw::binrw]
#[derive(Debug)]
pub struct RemotedIdentityTreeConnect {
    // MS-SMB2 2.2.9.2.1: Must be set to 0x1.
    #[bw(calc = PosMarker::new(1))]
    #[br(assert(_ticket_type.value == 1))]
    _ticket_type: PosMarker<u16>,
    ticket_size: u16,

    // Offsets
    $(
        #[bw(calc = PosMarker::default())]
        [<_$field _offset>]: PosMarker<u16>,
    )*

    // Values
    $(
        #[br(seek_before = _ticket_type.seek_from([<_$field _offset>].value as u64))]
        #[bw(write_with = PosMarker::write_roff_b, args(&[<_$field _offset>], &_ticket_type))]
        $field: $value,
    )*
}
        }
    }
}

make_remoted_identity_connect! {
    user: SidAttrData,
    user_name: NullWideString,
    domain: NullWideString,
    groups: SidArrayData,
    restricted_groups: SidArrayData,
    privileges: PrivilegeArrayData,
    primary_group: SidArrayData,
    owner: BlobData<SID>,
    default_dacl: BlobData<ACL>,
    device_groups: SidArrayData,
    user_claims: BlobData<ClaimSecurityAttributeRelativeV1>,
    device_claims: BlobData<ClaimSecurityAttributeRelativeV1>
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct BlobData<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    blob_size: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(blob_size.value as u64))]
    pub blob_data: T,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ArrayData<T>
where
    T: BinRead + BinWrite + 'static,
    for<'a> <T as BinRead>::Args<'a>: Default + Clone,
    for<'b> <T as BinWrite>::Args<'b>: Default + Clone,
{
    #[bw(try_calc = list.len().try_into())]
    lcount: u16,
    #[br(count = lcount)]
    pub list: Vec<T>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SidAttrData {
    pub sid_data: SID,
    pub attr: SidAttrSeGroup,
}

type SidArrayData = ArrayData<SidAttrData>;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SidAttrSeGroup {
    pub mandatory: bool,
    pub enabled_by_default: bool,
    pub group_enabled: bool,
    pub group_owner: bool,
    pub group_use_for_deny_only: bool,
    pub group_integrity: bool,
    pub group_integrity_enabled: bool,
    #[skip]
    __: B21,
    pub group_logon_id: B4,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct LuidAttrData {
    pub luid: u64,
    pub attr: LsaprLuidAttributes,
}

/// [MS-LSAD 2.2.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/03c834c0-f310-4e0c-832e-b6e7688364d1)
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaprLuidAttributes {
    pub default: bool,
    pub enabled: bool,
    #[skip]
    __: B30,
}

type PrivilegeData = BlobData<LuidAttrData>;

type PrivilegeArrayData = ArrayData<PrivilegeData>;

impl TreeConnectRequest {
    pub fn new(name: &String) -> TreeConnectRequest {
        TreeConnectRequest {
            flags: TreeConnectRequestFlags::new(),
            buffer: name.clone().into(),
            tree_connect_contexts: vec![],
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TreeConnectResponse {
    #[bw(calc = 16)]
    #[br(assert(_structure_size == 16))]
    _structure_size: u16,
    pub share_type: TreeConnectShareType,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u8,
    pub share_flags: TreeShareFlags,
    pub capabilities: TreeCapabilities,
    pub maximal_access: u32,
}

#[derive(BitfieldSpecifier, Debug, Clone, Copy)]
#[bits = 4]
pub enum TreeConnectShareFlagsCacheMode {
    Manual,
    Auto,
    Vdo,
    NoCache,
    All = 0xf,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeShareFlags {
    pub dfs: bool,
    pub dfs_root: bool,
    #[skip]
    __: B2,
    pub caching_mode: TreeConnectShareFlagsCacheMode,

    pub restrict_exclusive_opens: bool,
    pub force_shared_delete: bool,
    pub allow_namespace_caching: bool,
    pub access_based_directory_enum: bool,
    pub force_levelii_oplock: bool,
    pub enable_hash_v1: bool,
    pub enable_hash_v2: bool,
    pub encrypt_data: bool,

    #[skip]
    __: B2,
    pub identity_remoting: bool,
    #[skip]
    __: B1,
    pub compress_data: bool,
    pub isolated_transport: bool,
    #[skip]
    __: B10,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeCapabilities {
    #[skip]
    __: B3,
    pub dfs: bool,
    pub continuous_availability: bool,
    pub scaleout: bool,
    pub cluster: bool,
    pub asymmetric: bool,

    pub redirect_to_owner: bool,
    #[skip]
    __: B23,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum TreeConnectShareType {
    Disk = 0x1,
    Pipe = 0x2,
    Print = 0x3,
}

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct TreeDisconnectRequest {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeDisconnectResponse {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_tree_connect_req_write() {
        let result = encode_content(Content::TreeConnectRequest(TreeConnectRequest::new(
            &r"\\127.0.0.1\MyShare".into(),
        )));
        assert_eq!(
            result,
            [
                0x9, 0x0, 0x0, 0x0, 0x48, 0x0, 0x26, 0x0, 0x5c, 0x0, 0x5c, 0x0, 0x31, 0x0, 0x32,
                0x0, 0x37, 0x0, 0x2e, 0x0, 0x30, 0x0, 0x2e, 0x0, 0x30, 0x0, 0x2e, 0x0, 0x31, 0x0,
                0x5c, 0x0, 0x4d, 0x0, 0x79, 0x0, 0x53, 0x0, 0x68, 0x0, 0x61, 0x0, 0x72, 0x0, 0x65,
                0x0
            ]
        );
    }

    #[test]
    pub fn test_tree_connect_res_parse() {
        let mut cursor = Cursor::new(&[
            0x10, 0x0, 0x1, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x1, 0x1f, 0x0,
        ]);
        let content_parsed = TreeConnectResponse::read_le(&mut cursor).unwrap();
        assert_eq!(
            content_parsed,
            TreeConnectResponse {
                share_type: TreeConnectShareType::Disk,
                share_flags: TreeShareFlags::new().with_access_based_directory_enum(true),
                capabilities: TreeCapabilities::new(),
                maximal_access: 0x001f01ff,
            }
        )
    }
}
