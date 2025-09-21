use std::alloc::Layout;
use std::sync::Arc;

use super::error::*;
use super::smbd::{
    SmbdDataTransferFlags, SmbdDataTransferHeader, SmbdNegotiateRequest, SmbdNegotiateResponse,
};
use crate::traits::*;
use crate::{IoVec, error::TransportError};
use async_rdma::{
    ConnectionType, LocalMr, LocalMrReadAccess, LocalMrWriteAccess, Rdma, RdmaBuilder,
};
use binrw::prelude::*;
use futures_util::FutureExt;
use tokio::{select, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct RdmaRunningRo {
    receive: mpsc::Receiver<LocalMr>,

    max_rw_size: u32,

    worker: JoinHandle<()>,
    cancel: CancellationToken,

    max_fragmented_size: u32,
}

#[derive(Debug)]
struct RdmaRunningWo {
    rdma: Arc<Rdma>,
    max_rw_size: u32,
    max_fragmented_size: u32,
}

#[derive(Debug)]
enum RdmaTransportState {
    Init,
    RunningRw((RdmaRunningRo, RdmaRunningWo)),
    RunningWo(RdmaRunningWo),
    RunningRo(RdmaRunningRo),
    Disconnected,
}

#[derive(Debug)]
pub struct RdmaTransport {
    state: RdmaTransportState,
}

impl RdmaTransport {
    pub fn new(_timeout: std::time::Duration) -> Self {
        // TODO: use timeout
        RdmaTransport {
            state: RdmaTransportState::Init,
        }
    }

    pub async fn stop(&mut self) -> std::result::Result<(), RdmaError> {
        self.state = RdmaTransportState::Disconnected;
        // TODO: Properly stop the worker and cancel the receive channel.
        Ok(())
    }

    fn _get_read(&mut self) -> std::result::Result<&mut RdmaRunningRo, RdmaError> {
        match &mut self.state {
            RdmaTransportState::RunningRw((ro, _)) => Ok(ro),
            RdmaTransportState::RunningRo(ro) => Ok(ro),
            _ => Err(RdmaError::NotConnected),
        }
    }

    fn _get_write(&mut self) -> std::result::Result<&mut RdmaRunningWo, RdmaError> {
        match &mut self.state {
            RdmaTransportState::RunningWo(wo) => Ok(wo),
            RdmaTransportState::RunningRw((_, wo)) => Ok(wo),
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

        log::info!("RDMA connecting...");
        let rdma = RdmaBuilder::default()
            .set_conn_type(ConnectionType::RCCM)
            .set_raw(true)
            .cm_connect(&node, &service)
            .await?;
        log::info!("RDMA connected");
        let negotiate_result = Self::negotiate_rdma(&rdma).await?;
        log::info!("RDMA negotiated");
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

        self.state = RdmaTransportState::RunningRw((
            RdmaRunningRo {
                receive: rx,
                max_rw_size: negotiate_result.max_read_write_size,
                max_fragmented_size: negotiate_result.max_fragmented_size,
                worker,
                cancel,
            },
            RdmaRunningWo {
                rdma,
                max_rw_size: negotiate_result.max_read_write_size,
                max_fragmented_size: negotiate_result.max_fragmented_size,
            },
        ));

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

        log::debug!("Sending negotiate request: {:?}", req);
        rdma.send_raw(&neg_req_data).await?;

        let neg_res_data = rdma
            .receive_raw(
                core::alloc::Layout::from_size_align(SmbdNegotiateResponse::ENCODED_SIZE, 1)
                    .unwrap(),
            )
            .await?;
        let mut cursor = std::io::Cursor::new(neg_res_data.as_slice().as_ref());
        let neg_res: SmbdNegotiateResponse = SmbdNegotiateResponse::read(&mut cursor)?;
        if neg_res.status != smb_msg::Status::Success {
            return Err(RdmaError::NegotiateError(
                "Negotiation failed - non-success status".to_string(),
            ));
        }

        if neg_res.max_read_write_size <= SmbdDataTransferHeader::ENCODED_SIZE as u32 {
            return Err(RdmaError::NegotiateError(
                "Negotiation failed - max read/write size too small".to_string(),
            ));
        }

        // TODO: Check and use params!
        log::debug!("Received negotiate response: {:?}", neg_res);

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
        log::info!("RDMA receive worker started");
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
                    log::info!("RDMA receive worker cancelled");
                    break;
                }
            }
        }
        log::info!("RDMA receive worker stopped");
    }

    async fn _receive_fragmented_data(&mut self) -> std::result::Result<Vec<u8>, RdmaError> {
        let running = self._get_read()?;

        let mut result = Vec::with_capacity(0);
        loop {
            let mr = select! {
                mr = running.receive.recv() => {
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

    async fn _send_fragmented_data(
        &mut self,
        message: &IoVec,
    ) -> std::result::Result<(), RdmaError> {
        log::trace!(
            "RDMA _send_fragmented_data called with message length: {}",
            message.len()
        );
        let running = self._get_write()?;

        if message.len() > running.max_fragmented_size as usize {
            return Err(RdmaError::RequestTooLarge(
                message.len(),
                running.max_fragmented_size as usize,
            ));
        }

        let total_data_to_send = message.total_size() as u32;
        if total_data_to_send == 0 {
            log::trace!("Sending empty message, nothing to do.");
            return Ok(());
        }

        let mut data_sent: u32 = 0;
        let mut fragment_num = 0;

        let mut buf_iterator = message.iter();
        let mut current_buf = buf_iterator.next().unwrap();
        let mut current_buf_offset = 0usize;
        while data_sent < total_data_to_send {
            /// The offset must be 8-byte aligned.
            const OFFSET: u32 = (SmbdDataTransferHeader::ENCODED_SIZE as u32)
                .div_ceil(SmbdDataTransferHeader::DATA_ALIGNMENT)
                * SmbdDataTransferHeader::DATA_ALIGNMENT;

            let remaining = total_data_to_send - data_sent;
            let data_sending = remaining.min(running.max_rw_size - OFFSET);
            if data_sending == 0 {
                current_buf = buf_iterator.next().unwrap();
                current_buf_offset = 0;
                continue;
            }

            let header = SmbdDataTransferHeader {
                data_length: data_sending,
                remaining_data_length: remaining - data_sending,
                data_offset: OFFSET,
                flags: SmbdDataTransferFlags::new(),
                credits_requested: 1,
                credits_granted: 0x10,
            };

            let data_end = OFFSET as usize + data_sending as usize;
            let mut local_mr = running
                .rdma
                .alloc_local_mr(Layout::from_size_align(data_end, 1).unwrap())?;

            {
                let mut mr_data = local_mr.as_mut_slice();
                let mut cursor = std::io::Cursor::new(mr_data.as_mut());
                header.write(&mut cursor)?;

                mr_data[OFFSET as usize..data_end].copy_from_slice(
                    &current_buf[current_buf_offset as usize
                        ..current_buf_offset as usize + data_sending as usize],
                );

                log::trace!(
                    "Prepared fragment {fragment_num}: header: {:?}, data: {:?}",
                    header,
                    &mr_data[..data_end]
                );
            }

            running.rdma.send_raw(&local_mr).await?;

            log::trace!(
                "Sent fragment {fragment_num}: {} bytes, remaining: {}",
                data_sending,
                remaining - data_sending
            );

            data_sent += data_sending;
            current_buf_offset += data_sending as usize;
            fragment_num += 1;
        }

        Ok(())
    }
}

impl SmbTransport for RdmaTransport {
    fn connect<'a>(
        &'a mut self,
        endpoint: &'a str,
    ) -> futures_core::future::BoxFuture<'a, crate::error::Result<()>> {
        async move { Ok(self.connect_and_negotiate(endpoint).await?) }.boxed()
    }

    fn default_port(&self) -> u16 {
        todo!()
    }

    fn split(
        self: Box<Self>,
    ) -> crate::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        let (ro, wo) = match self.state {
            RdmaTransportState::RunningRw((ro, wo)) => (ro, wo),
            _ => return Err(TransportError::AlreadySplit),
        };
        Ok((
            Box::new(Self {
                state: RdmaTransportState::RunningRo(ro),
            }),
            Box::new(Self {
                state: RdmaTransportState::RunningWo(wo),
            }),
        ))
    }
}

impl SmbTransportRead for RdmaTransport {
    fn receive_exact<'a>(
        &'a mut self,
        _out_buf: &'a mut [u8],
    ) -> futures_core::future::BoxFuture<'a, crate::error::Result<()>> {
        unimplemented!("RDMA does not support receive_exact directly. Use receive instead.");
    }

    fn receive<'a>(
        &'a mut self,
    ) -> futures_core::future::BoxFuture<'a, crate::error::Result<Vec<u8>>> {
        async { Ok(self._receive_fragmented_data().await?) }.boxed()
    }
}

impl SmbTransportWrite for RdmaTransport {
    fn send_raw<'a>(
        &'a mut self,
        _buf: &'a [u8],
    ) -> futures_core::future::BoxFuture<'a, crate::error::Result<()>> {
        unimplemented!("RDMA does not support send_raw directly. Use send instead.");
    }

    fn send<'a>(
        &'a mut self,
        message: &'a IoVec,
    ) -> futures_core::future::BoxFuture<'a, crate::error::Result<()>> {
        async { Ok(self._send_fragmented_data(message).await?) }.boxed()
    }
}
