//! Get/Set Info Request/Response

use crate::FileId;
use crate::query_info_data;
use binrw::{io::TakeSeekExt, prelude::*};
use modular_bitfield::prelude::*;
use smb_dtyp::{SID, SecurityDescriptor, binrw_util::prelude::*};
use std::io::{Cursor, SeekFrom};

use super::common::*;
use smb_fscc::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryInfoRequest {
    #[bw(calc = 41)]
    #[br(assert(_structure_size == 41))]
    _structure_size: u16,
    pub info_type: InfoType,
    #[brw(args(info_type))]
    pub info_class: QueryInfoClass,

    pub output_buffer_length: u32,
    #[bw(calc = PosMarker::default())]
    _input_buffer_offset: PosMarker<u16>,
    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u16,
    #[bw(calc = PosMarker::default())]
    input_buffer_length: PosMarker<u32>,
    pub additional_info: AdditionalInfo,
    pub flags: QueryInfoFlags,
    pub file_id: FileId,
    #[br(map_stream = |s| s.take_seek(input_buffer_length.value as u64))]
    #[br(args(&info_class, info_type))]
    #[bw(write_with = PosMarker::write_aoff_size_a, args(&_input_buffer_offset, &input_buffer_length, (info_class, *info_type)))]
    pub data: GetInfoRequestData,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(info_type: InfoType))]
#[bw(import(info_type: &InfoType))]
pub enum QueryInfoClass {
    #[br(pre_assert(matches!(info_type, InfoType::File)))]
    #[bw(assert(matches!(info_type, InfoType::File)))]
    File(QueryFileInfoClass),

    #[br(pre_assert(matches!(info_type, InfoType::FileSystem)))]
    #[bw(assert(matches!(info_type, InfoType::FileSystem)))]
    FileSystem(QueryFileSystemInfoClass),

    Empty(NullByte),
}

impl Default for QueryInfoClass {
    fn default() -> Self {
        QueryInfoClass::Empty(NullByte {})
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct NullByte {
    #[bw(calc = 0)]
    #[br(assert(_null == 0))]
    _null: u8,
}

impl AdditionalInfo {
    pub fn is_security(&self) -> bool {
        self.owner_security_information()
            || self.group_security_information()
            || self.dacl_security_information()
            || self.sacl_security_information()
            || self.label_security_information()
            || self.attribute_security_information()
            || self.scope_security_information()
            || self.backup_security_information()
    }
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct QueryInfoFlags {
    pub restart_scan: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    #[skip]
    __: B29,
}

/// This struct describes the payload to be added in the [QueryInfoRequest]
/// when asking for information about Quota or Extended Attributes.
/// In other cases, it is empty.
#[binrw::binrw]
#[derive(Debug)]
#[brw(import(file_info_class: &QueryInfoClass, query_info_type: InfoType))]
pub enum GetInfoRequestData {
    /// The query quota to perform.
    #[br(pre_assert(query_info_type == InfoType::Quota))]
    #[bw(assert(query_info_type == InfoType::Quota))]
    Quota(QueryQuotaInfo),

    /// Extended attributes information to query.
    #[br(pre_assert(matches!(file_info_class, QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)) && query_info_type == InfoType::File))]
    #[bw(assert(matches!(file_info_class, QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)) && query_info_type == InfoType::File))]
    EaInfo(GetEaInfoList),

    // Other cases have no data.
    #[br(pre_assert(query_info_type != InfoType::Quota && !(query_info_type == InfoType::File && matches!(file_info_class , QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)))))]
    None(()),
}

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryQuotaInfo {
    pub return_single: Boolean,
    pub restart_scan: Boolean,
    #[bw(calc = 0)]
    _reserved: u16,
    #[bw(calc = PosMarker::default())]
    sid_list_length: PosMarker<u32>, // type 1: list of FileGetQuotaInformation structs.
    #[bw(calc = PosMarker::default())]
    start_sid_length: PosMarker<u32>, // type 2: SIDs list
    #[bw(calc = PosMarker::default())]
    start_sid_offset: PosMarker<u32>,

    /// Option 1: list of FileGetQuotaInformation structs.
    #[br(if(sid_list_length.value > 0))]
    #[br(map_stream = |s| s.take_seek(sid_list_length.value as u64))]
    #[bw(if(get_quota_info_content.as_ref().is_some_and(|v| !v.is_empty())))]
    #[bw(write_with = PosMarker::write_size, args(&sid_list_length))]
    pub get_quota_info_content: Option<ChainedItemList<FileGetQuotaInformation>>,

    /// Option 2: SID (usually not used).
    #[br(if(start_sid_length.value > 0))]
    #[bw(if(sid.is_some()))]
    #[br(seek_before = SeekFrom::Current(start_sid_offset.value as i64))]
    #[bw(write_with = PosMarker::write_size, args(&start_sid_length))]
    #[brw(assert(get_quota_info_content.is_none() != sid.is_none()))]
    // offset is 0, the default anyway.
    pub sid: Option<SID>,
}

impl QueryQuotaInfo {
    /// Builds a new [`QueryQuotaInfo`] with a list of [`FileGetQuotaInformation`] structs.
    ///
    /// Option #1 under 2.2.37.1
    pub fn new(
        return_single: bool,
        restart_scan: bool,
        content: Vec<FileGetQuotaInformation>,
    ) -> Self {
        Self {
            return_single: return_single.into(),
            restart_scan: restart_scan.into(),
            get_quota_info_content: Some(content.into()),
            sid: None,
        }
    }

    /// Builds a new [`QueryQuotaInfo`] with a single SID.
    ///
    /// Option #2 under 2.2.37.1
    pub fn new_sid(return_single: bool, restart_scan: bool, sid: SID) -> Self {
        Self {
            return_single: return_single.into(),
            restart_scan: restart_scan.into(),
            get_quota_info_content: None,
            sid: Some(sid),
        }
    }
}

#[derive(BinRead, BinWrite, Debug)]
pub struct GetEaInfoList {
    pub values: ChainedItemList<FileGetEaInformation>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryInfoResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    #[bw(calc = PosMarker::default())]
    output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    output_buffer_length: PosMarker<u32>,
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length.value.into()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&output_buffer_offset, &output_buffer_length))]
    data: QueryInfoResponseData,
}

impl QueryInfoResponse {
    /// Call this method first when parsing an incoming query info response.
    /// It will parse the raw data into a [QueryInfoResponseData] struct, which has
    /// a variation for each information type: File, FileSystem, Security, Quota.
    /// This is done by calling the [QueryInfoResponseData::parse] method.
    pub fn parse(&self, info_type: InfoType) -> Result<QueryInfoData, binrw::Error> {
        self.data.parse(info_type)
    }
}

/// A helpers struct that contains the raw data of a query info response or a set info request,
/// and can be parsed using the [`QueryInfoResponseData::parse`] method, to a specific info type.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryInfoResponseData {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl QueryInfoResponseData {
    pub fn parse(&self, info_type: InfoType) -> Result<QueryInfoData, binrw::Error> {
        let mut cursor = Cursor::new(&self.data);
        QueryInfoData::read_args(&mut cursor, (info_type,))
    }
}

impl From<Vec<u8>> for QueryInfoResponseData {
    fn from(data: Vec<u8>) -> Self {
        QueryInfoResponseData { data }
    }
}

query_info_data! {
    QueryInfoData
    File: RawQueryInfoData<QueryFileInfo>,
    FileSystem: RawQueryInfoData<QueryFileSystemInfo>,
    Security: SecurityDescriptor,
    Quota: ChainedItemList<FileQuotaInformation>,
}

#[cfg(test)]
mod tests {

    use time::macros::datetime;

    use crate::*;
    use smb_dtyp::*;

    use super::*;

    #[test]
    pub fn test_query_info_req_short_write() {
        let data = encode_content(
            QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(QueryFileInfoClass::NetworkOpenInformation),
                output_buffer_length: 56,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new(),
                file_id: [
                    0x77, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xc5, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0,
                    0x0,
                ]
                .into(),
                data: GetInfoRequestData::None(()),
            }
            .into(),
        );
        assert_eq!(
            data,
            [
                0x29, 0x0, 0x1, 0x22, 0x38, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x77, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0,
                0xc5, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0
            ]
        )
    }

    #[test]
    pub fn test_query_info_ea_request() {
        let req = QueryInfoRequest {
            info_type: InfoType::File,
            info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
            additional_info: AdditionalInfo::new(),
            flags: QueryInfoFlags::new()
                .with_restart_scan(true)
                .with_return_single_entry(true),
            file_id: [
                0x7a, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xd1, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0,
            ]
            .into(),
            data: GetInfoRequestData::EaInfo(GetEaInfoList {
                values: vec![FileGetEaInformation::new("$MpEa_D262AC624451295")].into(),
            }),
            output_buffer_length: 554,
        };
        let content_data = encode_content(req.into());
        assert_eq!(
            content_data,
            [
                0x29, 0x0, 0x1, 0xf, 0x2a, 0x2, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x7a, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0,
                0xd1, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d,
                0x70, 0x45, 0x61, 0x5f, 0x44, 0x32, 0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34,
                0x35, 0x31, 0x32, 0x39, 0x35, 0x0
            ]
        )
    }

    #[test]
    pub fn test_query_security_request() {
        let res = encode_content(
            QueryInfoRequest {
                info_type: InfoType::Security,
                info_class: Default::default(),
                output_buffer_length: 0,
                additional_info: AdditionalInfo::new()
                    .with_owner_security_information(true)
                    .with_group_security_information(true)
                    .with_dacl_security_information(true)
                    .with_sacl_security_information(true),
                flags: QueryInfoFlags::new(),
                file_id: make_guid!("0000002b-000d-0000-3100-00000d000000").into(),
                data: GetInfoRequestData::None(()),
            }
            .into(),
        );
        assert_eq!(
            res,
            &[
                0x29, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2b, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0,
                0x31, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0,
            ]
        );
    }

    #[test]
    pub fn test_query_info_resp_parse_basic() {
        let parsed = decode_content(&[
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x1, 0x0,
            0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x69, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x77,
            0x53, 0x6f, 0xb5, 0x9c, 0x21, 0xa4, 0xcd, 0x99, 0x9b, 0xc0, 0x87, 0xb9, 0x6, 0x83,
            0xa3, 0x9, 0x0, 0x48, 0x0, 0x28, 0x0, 0x0, 0x0, 0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58,
            0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51,
            0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0,
        ]);
        let parsed = parsed.content.to_queryinfo().unwrap();
        assert_eq!(
            parsed,
            QueryInfoResponse {
                data: [
                    0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51,
                    0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1,
                    0xd, 0x51, 0x6b, 0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                ]
                .to_vec()
                .into(),
            }
        );
    }

    #[test]
    pub fn test_query_info_resp_parse_file() {
        let raw_data: QueryInfoResponseData = [
            0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb,
            0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b,
            0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]
        .to_vec()
        .into();
        assert_eq!(
            raw_data
                .parse(InfoType::File)
                .unwrap()
                .as_file()
                .unwrap()
                .parse(QueryFileInfoClass::BasicInformation)
                .unwrap(),
            QueryFileInfo::BasicInformation(FileBasicInformation {
                creation_time: datetime!(2024-12-27 14:22:48.792994700).into(),
                last_access_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                last_write_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                change_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                file_attributes: FileAttributes::new().with_archive(true)
            })
        )
    }

    #[test]
    fn test_query_info_resp_parse_stream_info() {
        let raw_data: QueryInfoResponseData = [
            0x48, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x5a, 0x00,
            0x6f, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x49, 0x00, 0x64, 0x00, 0x65, 0x00,
            0x6e, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00, 0x65, 0x00, 0x72, 0x00,
            0x3a, 0x00, 0x24, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0xd1, 0xd6, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00,
            0x3a, 0x00, 0x24, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00,
        ]
        .to_vec()
        .into();

        assert_eq!(
            raw_data
                .parse(InfoType::File)
                .unwrap()
                .as_file()
                .unwrap()
                .parse(QueryFileInfoClass::StreamInformation)
                .unwrap(),
            QueryFileInfo::StreamInformation(
                vec![
                    FileStreamInformationInner {
                        stream_size: 0x93,
                        stream_allocation_size: 0x1000,
                        stream_name: SizedWideString::from(":Zone.Identifier:$DATA"),
                    },
                    FileStreamInformationInner {
                        stream_size: 0xd6d1,
                        stream_allocation_size: 0xd000,
                        stream_name: SizedWideString::from("::$DATA"),
                    },
                ]
                .into()
            )
        )
    }
}
