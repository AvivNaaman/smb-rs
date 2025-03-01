use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::super::guid::Guid;
use super::fscc::*;
use crate::packets::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct ChangeNotifyRequest {
    #[bw(calc = 32)]
    #[br(assert(_structure_size == 32))]
    _structure_size: u16,
    flags: NotifyFlags,
    output_buffer_length: u32,
    file_id: Guid,
    completion_filter: NotifyFilter,
    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u32,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NotifyFlags {
    pub watch_tree: bool,
    #[skip]
    __: B15,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NotifyFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,

    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,

    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
    pub stream_write: bool,

    #[skip]
    __: B20,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ChangeNotifyResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    #[bw(calc = PosMarker::default())]
    _output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    _output_buffer_length: PosMarker<u32>,
    #[br(seek_before = SeekFrom::Start(_output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(_output_buffer_length.value.into()), parse_with = binrw::helpers::until_eof)]
    buffer: Vec<FileNotifyInformation>,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn change_notify_request_write() {
        let request = ChangeNotifyRequest {
            flags: NotifyFlags::new(),
            output_buffer_length: 2048,
            file_id: "000005d1-000c-0000-1900-00000c000000".parse().unwrap(),
            completion_filter: NotifyFilter::new()
                .with_file_name(true)
                .with_dir_name(true)
                .with_attributes(true)
                .with_last_write(true),
        };

        let mut cursor = Cursor::new(Vec::new());
        request.write_le(&mut cursor).unwrap();
        assert_eq!(
            cursor.into_inner(),
            [
                0x20, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0xd1, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0,
                0x19, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
            ]
        );
    }

    #[test]
    pub fn test_change_notify_response_pending_parse() {
        let data = [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let response = ChangeNotifyResponse::read_le(&mut Cursor::new(&data)).unwrap();
        assert_eq!(response, ChangeNotifyResponse { buffer: vec![] });
    }

    #[test]
    pub fn test_change_notify_response_with_data_parse() {
        let data = [
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0x0, 0x0, 0x0,
            0x33, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x56, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
            0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x25, 0x0, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0, 0x48,
            0x0, 0x34, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x14, 0x0, 0x0, 0x0,
            0x4e, 0x0, 0x65, 0x0, 0x77, 0x0, 0x20, 0x0, 0x66, 0x0, 0x6f, 0x0, 0x6c, 0x0, 0x64, 0x0,
            0x65, 0x0, 0x72, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x6a,
            0x0, 0x64, 0x0, 0x73, 0x0, 0x61, 0x0,
        ];

        let parsed = decode_content(&data);
        let notify_response = match parsed.content {
            Content::ChangeNotifyResponse(response) => response,
            _ => panic!("Unexpected response type"),
        };

        assert_eq!(
            notify_response,
            ChangeNotifyResponse {
                buffer: vec![
                    FileNotifyInformationInner {
                        action: NotifyAction::RenamedOldName,
                        file_name: "New folder".into()
                    }
                    .into(),
                    FileNotifyInformationInner {
                        action: NotifyAction::RenamedNewName,
                        file_name: "jdsa".into()
                    }
                    .into()
                ]
            }
        );
    }
}
