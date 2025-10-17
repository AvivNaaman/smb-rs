use smb_dtyp::make_guid;

use crate::pdu::DceRpcSyntaxId;

pub const NDR64_SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
    uuid: make_guid!("71710533-beba-4937-8319-b5dbef9ccc36"),
    version: 1,
};
