//! SMB2 Set Info Request/Response messages.

use crate::{FileId, query_info_data};

use super::{NullByte, QueryQuotaInfo, common::*};
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use smb_dtyp::{SecurityDescriptor, binrw_util::prelude::*};
use smb_fscc::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SetInfoRequest {
    #[bw(calc = 33)]
    #[br(assert(_structure_size == 33))]
    _structure_size: u16,
    #[bw(calc = data.info_type())]
    pub info_type: InfoType,
    pub info_class: SetInfoClass,
    #[bw(calc = PosMarker::default())]
    buffer_length: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _buffer_offset: PosMarker<u16>,
    #[bw(calc = 0)]
    _reserved: u16,
    pub additional_information: AdditionalInfo,
    pub file_id: FileId,
    #[br(map_stream = |s| s.take_seek(buffer_length.value as u64))]
    #[br(args(info_type))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_buffer_offset, &buffer_length))]
    pub data: SetInfoData,
}

query_info_data! {
    SetInfoData
    File: RawSetInfoData<SetFileInfo>,
    FileSystem: RawSetInfoData<SetFileSystemInfo>,
    Security: SecurityDescriptor,
    Quota: QueryQuotaInfo,
}

/// A helper class for [SetInfoRequest] to contain the information
/// class to set. In cases of no class, it will be set to a null byte (0u8).
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum SetInfoClass {
    File(SetFileInfoClass),
    FileSystem(SetFileSystemInfoClass),
    Security(NullByte),
    Quota(NullByte),
}

impl From<SetFileInfoClass> for SetInfoClass {
    fn from(val: SetFileInfoClass) -> Self {
        SetInfoClass::File(val)
    }
}

impl From<SetFileSystemInfoClass> for SetInfoClass {
    fn from(val: SetFileSystemInfoClass) -> Self {
        SetInfoClass::FileSystem(val)
    }
}

impl SetInfoData {
    /// This is a helper function to convert the [SetInfoData] to
    /// a [SetInfoRequest].
    pub fn to_req(
        self,
        info_class: SetInfoClass,
        file_id: FileId,
        additional_info: AdditionalInfo,
    ) -> SetInfoRequest {
        // Validate the info class and data combination
        // to ensure they are compatible.
        match (&info_class, &self) {
            (SetInfoClass::File(_), SetInfoData::File(_)) => {}
            (SetInfoClass::FileSystem(_), SetInfoData::FileSystem(_)) => {}
            (SetInfoClass::Security(_), SetInfoData::Security(_)) => {}
            (SetInfoClass::Quota(_), SetInfoData::Quota(_)) => {}
            _ => panic!("Invalid info class and data combination"),
        }

        SetInfoRequest {
            info_class,
            additional_information: additional_info,
            file_id,
            data: self,
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SetInfoResponse {
    #[bw(calc = 2)]
    #[br(assert(_structure_size == 2))]
    _structure_size: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use smb_dtyp::*;

    #[test]
    fn test_set_info_request_write() {
        let set_info = SetFileInfo::RenameInformation(FileRenameInformation2 {
            replace_if_exists: false.into(),
            root_directory: 0,
            file_name: "hello\\myNewFile.txt".into(),
        });

        let cls = set_info.class();
        let req = SetInfoData::from(RawSetInfoData::<SetFileInfo>::from(set_info)).to_req(
            cls.into(),
            guid!("00000042-000e-0000-0500-10000e000000").into(),
            AdditionalInfo::new(),
        );
        let req_data = encode_content(req.into());
        assert_eq!(
            req_data,
            [
                0x21, 0x0, 0x1, 0xa, 0x3a, 0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x42, 0x0, 0x0, 0x0, 0xe, 0x0, 0x0, 0x0, 0x5, 0x0, 0x10, 0x0, 0xe, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x26, 0x0, 0x0, 0x0, 0x68, 0x0, 0x65, 0x0, 0x6c, 0x0, 0x6c, 0x0, 0x6f, 0x0, 0x5c,
                0x0, 0x6d, 0x0, 0x79, 0x0, 0x4e, 0x0, 0x65, 0x0, 0x77, 0x0, 0x46, 0x0, 0x69, 0x0,
                0x6c, 0x0, 0x65, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0
            ]
        );
    }

    #[test]
    fn test_set_info_response_parse() {
        let data = [0x2, 0x0, 0x0, 0x0];
        let response = SetInfoResponse::read_le(&mut std::io::Cursor::new(&data)).unwrap();
        assert_eq!(response, SetInfoResponse {});
    }
}
