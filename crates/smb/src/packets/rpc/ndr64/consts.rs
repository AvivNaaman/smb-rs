use crate::{
    guid,
    packets::{guid::Guid, rpc::pdu::DceRpcSyntaxId},
};

pub const NDR64_SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
    uuid: guid!("71710533-beba-4937-8319-b5dbef9ccc36"),
    version: 1,
};
