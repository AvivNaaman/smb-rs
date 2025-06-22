#![cfg(feature = "rdma")]

use std::alloc::Layout;
use std::sync::Arc;

use super::traits::*;
use crate::connection::transport::TransportError;
use crate::packets::smbd::SmbdDataTransferHeader;
use crate::sync_helpers::*;
use crate::{
    connection::transport::{SmbTransport, SmbTransportRead},
    packets::smbd::{SmbdNegotiateRequest, SmbdNegotiateResponse},
};
use async_rdma::{
    ConnectionType, LocalMr, LocalMrReadAccess, LocalMrWriteAccess, Rdma, RdmaBuilder,
};
use binrw::prelude::*;
use futures_util::FutureExt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RdmaError {
    #[error("SMBD negotiation error: {0}")]
    NegotiateError(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Already connected")]
    AlreadyConnected,
    #[error("Not connected")]
    NotConnected,
    #[error("Request data too large. Requested size: {0}, max size allowed: {1}")]
    RequestTooLarge(usize, usize),
    #[error("Failed to parse SMB message: {0}")]
    SmbdParseError(#[from] binrw::Error),
    #[error("Invalid endpoint format: {0}")]
    InvalidEndpoint(String),
}

type Result<T> = std::result::Result<T, RdmaError>;

#[derive(Debug)]
struct RdmaRunning {
    rdma: Arc<Rdma>,
    receive: mpsc::Receiver<LocalMr>,

    max_rw_size: u32,

    worker: JoinHandle<()>,
    cancel: CancellationToken,

    max_fragmented_size: u32,
}

#[derive(Debug)]
enum RdmaTransportState {
    Init,
    Running(RdmaRunning),
    Disconnected,
}

#[derive(Debug)]
pub struct RdmaTransport {
    state: RdmaTransportState,
}

impl RdmaTransport {
    pub fn new() -> Self {
        RdmaTransport {
            state: RdmaTransportState::Init,
        }
    }

    pub async fn stop(&mut self) -> std::result::Result<(), RdmaError> {
        unimplemented!()
    }

    #[inline]
    fn _get_running(&self) -> std::result::Result<&RdmaRunning, RdmaError> {
        match &self.state {
            RdmaTransportState::Running(r) => Ok(r),
            _ => Err(RdmaError::NotConnected),
        }
    }

    #[inline]
    fn _get_running_mut(&mut self) -> std::result::Result<&mut RdmaRunning, RdmaError> {
        match &mut self.state {
            RdmaTransportState::Running(ref mut r) => Ok(r),
            _ => Err(RdmaError::NotConnected),
        }
    }

    pub async fn connect_and_negotiate(&mut self, endpoint: &str) -> Result<()> {
        if !matches!(self.state, RdmaTransportState::Init) {
            return Err(RdmaError::AlreadyConnected);
        }

        let endpoint_parts: Vec<&str> = endpoint.split(':').collect();
        if endpoint_parts.len() != 2 {
            return Err(RdmaError::InvalidEndpoint(endpoint.to_string()));
        }
        let node = dbg!(endpoint_parts[0].to_owned()) + "\0";
        let service = "445\0";

        log::info!("RdmaTransport connecting...");
        let rdma = RdmaBuilder::default()
            .set_conn_type(ConnectionType::RCCM)
            .set_raw(true)
            .cm_connect(&node, &service)
            .await?;
        log::info!("RdmaTransport connected");
        let negotiate_result = Self::negotiate_rdma(&rdma).await?;
        log::info!("RdmaTransport negotiated");
        let rdma = Arc::new(rdma);
        let cancel = CancellationToken::new();

        let (tx, rx) = mpsc::channel(100);
        let worker = {
            let rdma = rdma.clone();
            let negotiate_result = negotiate_result.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                Self::_receive_worker(tx, rdma, negotiate_result, cancel).await;
            })
        };

        self.state = RdmaTransportState::Running(RdmaRunning {
            rdma: rdma.clone(),
            receive: rx,
            max_rw_size: negotiate_result.max_read_write_size,
            max_fragmented_size: negotiate_result.max_fragmented_size,
            worker,
            cancel,
        });

        Ok(())
    }

    /// (Internal)
    ///
    /// Negotitates SMBD over an opened RDMA connection.
    async fn negotiate_rdma(rdma: &Rdma) -> Result<SmbdNegotiateResponse> {
        let req: SmbdNegotiateRequest = SmbdNegotiateRequest {
            credits_requested: 0x10,
            preferred_send_size: 0x400,
            max_receive_size: 0x400,
            max_fragmented_size: 128 * 1024 * 2,
        };

        let mut neg_req_data = rdma.alloc_local_mr(
            core::alloc::Layout::from_size_align(SmbdNegotiateRequest::ENCODED_SIZE, 1).unwrap(),
        )?;
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
        let neg_res: SmbdNegotiateResponse = SmbdNegotiateResponse::read(&mut cursor)?;
        if neg_res.status != crate::packets::smb2::Status::Success {
            return Err(RdmaError::NegotiateError(
                "Negotiation failed - non-success status".to_string(),
            ));
        }

        // TODO: Check and use params!
        log::info!("Received negotiate response: {:?}", neg_res);

        Ok(neg_res)
    }

    /// (Internal)
    ///
    /// A worker that calls receive_raw on the RDMA connection for
    /// incoming data. Passes the received data to the specified channel.
    /// # Arguments
    /// * `tx` - The channel to send the received data to.
    /// * `rdma` - The RDMA connection to receive data from.
    /// * `negotiate_result` - The result of the RDMA negotiation, used
    ///   to determine the maximum read/write size.
    /// * `cancel` - A cancellation token to stop the worker when needed.
    async fn _receive_worker(
        tx: mpsc::Sender<LocalMr>,
        rdma: Arc<Rdma>,
        negotiate_result: SmbdNegotiateResponse,
        cancel: CancellationToken,
    ) {
        log::info!("RdmaTransport receive worker started");
        let receive_layout =
            Layout::from_size_align(negotiate_result.max_read_write_size as usize, 1).unwrap();
        loop {
            log::trace!("Waiting for RDMA data...");
            select! {
                mr_res = rdma.receive_raw(receive_layout) => {
                    match mr_res {
                        Ok(mr) => {
                            log::trace!("Received RDMA data: {:?}", mr);
                            if tx.send(mr).await.is_err() {
                                log::warn!("Receiver dropped, stopping worker");
                                break;
                            }
                            log::trace!("Sent RDMA data to receiver channel");
                        }
                        Err(e) => {
                            log::error!("Error receiving data: {:?}", e);
                            break;
                        }
                    }
                },
                _ = cancel.cancelled() => {
                    log::info!("RdmaTransport receive worker cancelled");
                    break;
                }
            }
        }
        log::info!("RdmaTransport receive worker stopped");
    }

    async fn _receive_fragmented_data(&mut self) -> std::result::Result<Vec<u8>, RdmaError> {
        let running = self._get_running_mut()?;

        let mut result = Vec::with_capacity(0);
        loop {
            let mr = select! {
                mr = running.receive.recv() => {
                    const BEGINNING: usize = 0;
                    match mr {
                        Some(mr) => mr,
                        None => return Err(RdmaError::NotConnected),
                    }
                }
                _ = running.cancel.cancelled() => {
                    return Err(RdmaError::NotConnected);
                }
            };

            let mr_data = mr.as_slice().as_ref();
            let mut cursor = std::io::Cursor::new(mr_data);
            let message = SmbdDataTransferHeader::read(&mut cursor)?;

            if result.capacity() == 0 {
                if message.data_length == 0 {
                    log::trace!("Received empty fragmented data, stopping receive loop.");
                    assert!(message.remaining_data_length == 0 && message.data_offset == 0);
                    return Ok(result);
                }

                // First receive only
                let expected_total_size = message.data_length + message.remaining_data_length;
                result.reserve_exact(expected_total_size as usize);
            }

            let data_length = message.data_length as usize;
            let offset_in_mr = message.data_offset as usize;

            if result.len() + data_length > running.max_fragmented_size as usize {
                return Err(RdmaError::RequestTooLarge(
                    data_length,
                    running.max_fragmented_size as usize,
                ));
            }
            if data_length > running.max_rw_size as usize {
                return Err(RdmaError::RequestTooLarge(
                    data_length,
                    running.max_rw_size as usize,
                ));
            }

            result.extend_from_slice(&mr_data[offset_in_mr..offset_in_mr + data_length]);

            if message.remaining_data_length == 0 {
                // If no more data is expected, we can stop receiving.
                log::trace!(
                    "Received all fragmented data - {} bytes, stopping receive loop.",
                    result.len()
                );
                break;
            } else {
                log::trace!(
                    "Received {} bytes of fragmented data, expecting more ({} bytes remaining).",
                    data_length,
                    message.remaining_data_length
                );
            }
        }

        Ok(result)
    }
}

impl SmbTransport for RdmaTransport {
    fn connect<'a>(
        &'a mut self,
        endpoint: &'a str,
    ) -> futures_core::future::BoxFuture<'a, super::error::Result<()>> {
        async move { Ok(self.connect_and_negotiate(endpoint).await?) }.boxed()
    }

    fn default_port(&self) -> u16 {
        todo!()
    }

    fn split(
        self: Box<Self>,
    ) -> super::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        match self.state {
            RdmaTransportState::Running(_) => Ok((self, self)),
            _ => Err(TransportError::NotConnected),
        }
    }
}

impl SmbTransportRead for RdmaTransport {
    fn receive_exact<'a>(
        &'a mut self,
        _out_buf: &'a mut [u8],
    ) -> futures_core::future::BoxFuture<'a, super::error::Result<()>> {
        unimplemented!(
            "RdmaTransport does not support receive_exact directly. Use receive instead."
        );
    }

    fn receive<'a>(
        &'a mut self,
    ) -> futures_core::future::BoxFuture<'a, super::error::Result<Vec<u8>>> {
        async { Ok(self._receive_fragmented_data().await?) }.boxed()
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
