use crate::packets::rpc::pdu::DceRpcSyntaxId;
use binrw::prelude::*;
use maybe_async::*;

pub trait RpcInterface<T>
where
    T: BoundRpcConnection,
{
    fn syntax_id() -> DceRpcSyntaxId;
    fn new(bound_pipe: T) -> Self;
}

pub trait RpcCall: for<'a> BinWrite<Args<'a> = ()> {
    const OPNUM: u16;
    type ResponseType: for<'b> BinRead<Args<'b> = ()>;
    fn serialize(&self) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(vec![]);
        self.write_le(&mut cursor).unwrap();
        cursor.into_inner()
    }

    fn deserialize(data: &[u8]) -> crate::Result<Self::ResponseType>
    where
        Self: Sized,
    {
        let mut cursor = std::io::Cursor::new(data);
        Self::ResponseType::read_le(&mut cursor).map_err(|e| crate::Error::from(e))
    }
}

#[maybe_async(AFIT)]
pub trait BoundRpcConnection {
    async fn send_receive<S>(&mut self, stub_input: S) -> crate::Result<S::ResponseType>
    where
        S: RpcCall,
    {
        let serialized_input = stub_input.serialize();
        let response = self.send_receive_raw(S::OPNUM, &serialized_input).await?;
        S::deserialize(&response)
    }

    async fn send_receive_raw(&mut self, opnum: u16, stub_input: &[u8]) -> crate::Result<Vec<u8>>;
}
