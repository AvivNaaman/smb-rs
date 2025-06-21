#![cfg(feature = "rdma")]

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::{
    connection::transport::{SmbTransport, SmbTransportRead},
    packets::smbd::{SmbdNegotiateRequest, SmbdNegotiateResponse},
};
use async_rdma::{ConnectionType, LocalMrReadAccess, LocalMrWriteAccess, Rdma, RdmaBuilder};
use binrw::prelude::*;

pub struct RdmaTransport {
    rdma: Rdma,
}

impl RdmaTransport {
    pub async fn new() -> crate::Result<Self> {
        log::info!("RdmaTransport connecting...");
        let rdma = RdmaBuilder::default()
            .set_conn_type(ConnectionType::RCCM)
            .set_raw(true)
            .cm_connect("172.16.204.132\0", "445\0")
            .await
            .unwrap();
        log::info!("RdmaTransport connected");
        Ok(Self { rdma })
    }

    pub async fn neogitate(&self) -> crate::Result<()> {
        let req = SmbdNegotiateRequest {
            credits_requested: 0x10,
            preferred_send_size: 0x400,
            max_receive_size: 0x400,
            max_fragmented_size: 128 * 1024 * 2,
        };

        let mut neg_req_data = self
            .rdma
            .alloc_local_mr(
                core::alloc::Layout::from_size_align(SmbdNegotiateRequest::ENCODED_SIZE, 1)
                    .unwrap(),
            )
            .unwrap();
        {
            let mut req_data = neg_req_data.as_mut_slice();
            let mut cursor = std::io::Cursor::new(req_data.as_mut());
            req.write(&mut cursor).unwrap();
        }

        log::info!("Sending negotiate request: {:?}", req);
        self.rdma.send_raw(&neg_req_data).await?;

        let neg_res_data = self
            .rdma
            .receive_raw(
                core::alloc::Layout::from_size_align(SmbdNegotiateResponse::ENCODED_SIZE, 1)
                    .unwrap(),
            )
            .await?;
        let mut cursor = std::io::Cursor::new(neg_res_data.as_slice().as_ref());
        let neg_res: SmbdNegotiateResponse = SmbdNegotiateResponse::read(&mut cursor).unwrap();
        if neg_res.status != crate::packets::smb2::Status::Success {
            return Err(crate::Error::InvalidMessage(
                "SMBD Negotiate failed".to_string(),
            ));
        }
        log::info!("Received negotiate response: {:?}", neg_res);

        Ok(())
    }
}
