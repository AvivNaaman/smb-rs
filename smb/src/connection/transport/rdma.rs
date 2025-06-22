#![cfg(feature = "rdma")]

use std::net::{Ipv4Addr, SocketAddrV4};

use super::{traits::*, TransportError};
use crate::sync_helpers::*;
use crate::{
    connection::transport::{SmbTransport, SmbTransportRead},
    packets::smbd::{BufferDescriptorV1, SmbdNegotiateRequest, SmbdNegotiateResponse},
};
use async_rdma::{ConnectionType, LocalMrReadAccess, LocalMrWriteAccess, Rdma, RdmaBuilder};
use binrw::prelude::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RdmaError {
    #[error("SMBD negotiation error: {0}")]
    NegotiateError(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Already connected")]
    AlreadyConnected,
}

type Result<T> = std::result::Result<T, RdmaError>;

pub struct RdmaTransport {
    rdma: OnceCell<Rdma>,
}

impl RdmaTransport {
    pub fn new() -> Self {
        RdmaTransport {
            rdma: OnceCell::new(),
        }
    }

    pub async fn connect_and_negotiate(&mut self) -> Result<()> {
        if self.rdma.get().is_some() {
            return Err(RdmaError::AlreadyConnected);
        }

        log::info!("RdmaTransport connecting...");
        let rdma = RdmaBuilder::default()
            .set_conn_type(ConnectionType::RCCM)
            .set_raw(true)
            .cm_connect("172.16.204.132\0", "445\0")
            .await
            .unwrap();
        log::info!("RdmaTransport connected");
        Self::negotiate_rdma(&rdma).await?;
        log::info!("RdmaTransport negotiated");
        self.rdma.set(rdma).unwrap();
        Ok(())
    }

    pub async fn negotiate_rdma(rdma: &Rdma) -> Result<()> {
        let req: SmbdNegotiateRequest = SmbdNegotiateRequest {
            credits_requested: 0x10,
            preferred_send_size: 0x400,
            max_receive_size: 0x400,
            max_fragmented_size: 128 * 1024 * 2,
        };

        let mut neg_req_data = rdma
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
        rdma.send_raw(&neg_req_data).await?;

        let neg_res_data = rdma
            .receive_raw(
                core::alloc::Layout::from_size_align(SmbdNegotiateResponse::ENCODED_SIZE, 1)
                    .unwrap(),
            )
            .await?;
        let mut cursor = std::io::Cursor::new(neg_res_data.as_slice().as_ref());
        let neg_res: SmbdNegotiateResponse = SmbdNegotiateResponse::read(&mut cursor).unwrap();
        if neg_res.status != crate::packets::smb2::Status::Success {
            return Err(RdmaError::NegotiateError(
                "Negotiation failed - non-success status".to_string(),
            ));
        }

        // TODO: Check and use params!
        log::info!("Received negotiate response: {:?}", neg_res);

        Ok(())
    }
}

impl SmbTransport for RdmaTransport {
    fn connect<'a>(
        &'a mut self,
        endpoint: &'a str,
    ) -> futures_core::future::BoxFuture<'a, super::error::Result<()>> {
        todo!()
    }

    fn default_port(&self) -> u16 {
        todo!()
    }

    fn split(
        self: Box<Self>,
    ) -> super::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        todo!()
    }
}

impl SmbTransportRead for RdmaTransport {
    fn receive_exact<'a>(
        &'a mut self,
        out_buf: &'a mut [u8],
    ) -> futures_core::future::BoxFuture<'a, super::error::Result<()>> {
        todo!()
    }
}

impl super::SmbTransportWrite for RdmaTransport {
    fn send_raw<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> futures_core::future::BoxFuture<'a, super::error::Result<()>> {
        todo!()
    }
}
