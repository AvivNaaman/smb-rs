use std::alloc::Layout;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU16;

use super::error::*;
use super::smbd::{
    SmbdDataTransferFlags, SmbdDataTransferHeader, SmbdNegotiateRequest, SmbdNegotiateResponse,
};
use crate::{IoVec, error::TransportError};
use crate::{RdmaType, traits::*};
use async_rdma::{
    ConnectionType, LocalMr, LocalMrReadAccess, LocalMrWriteAccess, Rdma, RdmaBuilder,
};
use binrw::prelude::*;
use futures_util::FutureExt;
use tokio::sync::Semaphore;
use tokio::{select, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct RdmaRunningRo {
    receive: mpsc::Receiver<LocalMr>,

    max_rw_size: u32,

    worker: JoinHandle<()>,
    cancel: CancellationToken,

    max_fragmented_recv_size: u32,

    credits: Arc<ClientCreditState>,
}

#[derive(Debug)]
struct RdmaRunningWo {
    rdma: Arc<Rdma>,
    max_rw_size: u32,
    max_send_size: usize,
    max_fragmented_recv_size: u32,

    credits: Arc<ClientCreditState>,
}

#[derive(Debug)]
struct ClientCreditState {
    send_credits: Semaphore,

    send_credits_target: u16,
    recv_credits_limit: u16,

    current_credit_requested: AtomicU16,
}

#[derive(Debug)]
enum RdmaTransportState {
    Init,
    RunningRw((RdmaRunningRo, RdmaRunningWo, SocketAddr)),
    RunningWo(RdmaRunningWo, SocketAddr),
    RunningRo(RdmaRunningRo, SocketAddr),
    Disconnected,
}

#[derive(Debug)]
pub struct RdmaTransport {
    state: RdmaTransportState,
    config: super::RdmaConfig,
}

impl RdmaTransport {
    pub const EXPORTED_DEFAULT_PORT: u16 = 0;

    pub fn new(config: &super::RdmaConfig, _timeout: std::time::Duration) -> Self {
        log::warn!(
            "Rdma transport is currently alpha-quality and may not work correctly. Do not use it for production applications!"
        );
        // TODO: use config+timeout
        RdmaTransport {
            state: RdmaTransportState::Init,
            config: config.clone(),
        }
    }

    pub async fn stop(&mut self) -> std::result::Result<(), RdmaError> {
        // Cancel worker and wait for it to finish
        match std::mem::replace(&mut self.state, RdmaTransportState::Disconnected) {
            RdmaTransportState::RunningRw((ro, _, _)) | RdmaTransportState::RunningRo(ro, _) => {
                ro.cancel.cancel();
                let _ = ro.worker.await;
            }
            _ => {}
        }
        Ok(())
    }

    fn _get_read(&mut self) -> std::result::Result<&mut RdmaRunningRo, RdmaError> {
        match &mut self.state {
            RdmaTransportState::RunningRw((ro, _, _)) => Ok(ro),
            RdmaTransportState::RunningRo(ro, _) => Ok(ro),
            _ => Err(RdmaError::NotConnected),
        }
    }

    fn _get_write(&mut self) -> std::result::Result<&mut RdmaRunningWo, RdmaError> {
        match &mut self.state {
            RdmaTransportState::RunningWo(wo, _) => Ok(wo),
            RdmaTransportState::RunningRw((_, wo, _)) => Ok(wo),
            _ => Err(RdmaError::NotConnected),
        }
    }

    /// When transporting SMB traffic on iWARP, to permit coexistence of TCP and iWARP SMB listeners, a
    /// mapping is standardized for the SMB Direct protocol, as follows:
    /// smbdirect | 5445 | [IANAPORT]
    pub const IWRAP_SMBDIRECT_PORT: u16 = 5445;

    /// when serving as a transport for SMB2, the following port assignment is used, as defined in [MS-SMB2]
    /// section 1.9.
    /// Microsoft-DS | 445 (0x01BD) | [IANAPORT]
    pub const DEFAULT_SMBDIRECT_PORT: u16 = crate::TcpTransport::DEFAULT_PORT;

    const SEND_CREDIT_TARGET: u16 = 255;
    const RECV_CREDIT_LIMIT: u16 = 255;
    const MAX_RECEIVE_SIZE: usize = 0x400;

    pub async fn connect_and_negotiate(&mut self, server_address: SocketAddr) -> Result<()> {
        if !matches!(self.state, RdmaTransportState::Init) {
            return Err(RdmaError::AlreadyConnected);
        }

        let server_address = if server_address.port() == Self::EXPORTED_DEFAULT_PORT {
            //
            let port = match self.config.rdma_type {
                RdmaType::RoCE | RdmaType::InfiniBand => Self::DEFAULT_SMBDIRECT_PORT,
                RdmaType::IWarp => Self::IWRAP_SMBDIRECT_PORT,
            };
            SocketAddr::new(server_address.ip(), port)
        } else {
            server_address
        };

        let node = server_address.ip().to_string() + "\0";
        let service = server_address.port().to_string() + "\0";

        log::debug!("RDMA connecting to {node}:{service}...");
        let rdma = RdmaBuilder::default()
            .set_conn_type(ConnectionType::RCCM)
            .set_raw(true)
            .set_mr_strategy(async_rdma::MRManageStrategy::Raw) // Jemalloc is buggy here :(
            .cm_connect(&node, &service)
            .await?;
        log::info!("RDMA connected");
        let max_send_size = 0x400;
        let negotiate_result = Self::negotiate_rdma(&rdma, max_send_size).await?;
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

        let credits = Arc::new(ClientCreditState {
            send_credits: Semaphore::new(negotiate_result.credits_granted as usize),
            send_credits_target: Self::SEND_CREDIT_TARGET,
            recv_credits_limit: Self::RECV_CREDIT_LIMIT,
            current_credit_requested: AtomicU16::new(negotiate_result.credits_requested),
        });

        self.state = RdmaTransportState::RunningRw((
            RdmaRunningRo {
                receive: rx,
                max_rw_size: negotiate_result.max_read_write_size,
                max_fragmented_recv_size: negotiate_result.max_fragmented_size,
                worker,
                cancel,
                credits: credits.clone(),
            },
            RdmaRunningWo {
                rdma,
                max_send_size: max_send_size as usize,
                max_rw_size: negotiate_result.max_read_write_size,
                max_fragmented_recv_size: negotiate_result.max_fragmented_size,
                credits,
            },
            server_address,
        ));

        log::debug!("RDMA transport state: {:?}", self.state);

        Ok(())
    }

    /// (Internal)
    ///
    /// Negotitates SMBD over an opened RDMA connection.
    async fn negotiate_rdma(
        rdma: &Rdma,
        preferred_send_size: u32,
    ) -> Result<SmbdNegotiateResponse> {
        let req: SmbdNegotiateRequest = SmbdNegotiateRequest {
            credits_requested: Self::SEND_CREDIT_TARGET,
            preferred_send_size,
            max_receive_size: Self::MAX_RECEIVE_SIZE as u32,
            max_fragmented_size: 128 * 1024 * 2,
        };

        let mut neg_req_data = rdma.alloc_local_mr(
            core::alloc::Layout::from_size_align(
                SmbdNegotiateRequest::ENCODED_SIZE,
                Self::MR_ALIGN_TO,
            )
            .unwrap(),
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
                core::alloc::Layout::from_size_align(
                    SmbdNegotiateResponse::ENCODED_SIZE,
                    Self::MR_ALIGN_TO,
                )
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

        // TODO: Make sure sizes are okay here properly, if not, fail negotiation.
        if neg_res.max_read_write_size.min(neg_res.max_receive_size) <= Self::IN_MR_OFFSET {
            return Err(RdmaError::NegotiateError(
                "Negotiation failed - max read/write size + max_receive_size too small".to_string(),
            ));
        }

        // TODO: Check and use params!
        log::debug!("Received negotiate response: {:?}", neg_res);

        Ok(neg_res)
    }

    const MR_ALIGN_TO: usize = 8;

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
        let receive_layout = Layout::from_size_align(
            negotiate_result.max_receive_size as usize,
            Self::MR_ALIGN_TO,
        )
        .unwrap();
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

            log::trace!(
                "Received RDMA message data (len={}): {mr_data:?}",
                mr_data.len()
            );

            let mut cursor = std::io::Cursor::new(mr_data);
            let message = SmbdDataTransferHeader::read(&mut cursor)?;

            log::trace!("Parsed RDMA message header: {:?}", message);

            if result.capacity() == 0 {
                if message.data_length == 0 {
                    log::trace!("Received empty fragmented data, stopping receive loop.");
                    assert!(message.remaining_data_length == 0 && message.data_offset == 0);
                    return Ok(result);
                }

                // First receive only
                let expected_total_size = message.data_length + message.remaining_data_length;
                if expected_total_size > running.max_fragmented_recv_size {
                    return Err(RdmaError::RequestTooLarge(
                        expected_total_size as usize,
                        running.max_fragmented_recv_size as usize,
                    ));
                }
                result.reserve_exact(expected_total_size as usize);
            }

            let data_length = message.data_length as usize;
            let offset_in_mr = message.data_offset as usize;

            if result.len() + data_length > running.max_fragmented_recv_size as usize {
                return Err(RdmaError::RequestTooLarge(
                    data_length,
                    running.max_fragmented_recv_size as usize,
                ));
            }
            if data_length > running.max_rw_size as usize {
                // TODO: this is wrong
                return Err(RdmaError::RequestTooLarge(
                    data_length,
                    running.max_rw_size as usize,
                ));
            }

            result.extend_from_slice(&mr_data[offset_in_mr..offset_in_mr + data_length]);

            // Update granted credits from the server
            running
                .credits
                .send_credits
                .add_permits(message.credits_granted as usize);

            // Update current requested credits
            running.credits.current_credit_requested.fetch_add(
                message.credits_requested,
                std::sync::atomic::Ordering::SeqCst,
            );

            log::debug!(
                "Server granted to client {} credits (total now: {}); server requested {} credits",
                message.credits_granted,
                running.credits.send_credits.available_permits(),
                message.credits_requested
            );

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

            log::trace!(
                "Dropping RDMA message local MR. Remaining data length: {}",
                message.remaining_data_length
            );
        }

        Ok(result)
    }

    const IN_MR_OFFSET: u32 = 24;
    async fn _send_fragmented_data(
        &mut self,
        message: &IoVec,
    ) -> std::result::Result<(), RdmaError> {
        log::trace!(
            "RDMA _send_fragmented_data called with message length: {}",
            message.len()
        );
        let running = self._get_write()?;

        if message.len() > running.max_fragmented_recv_size as usize {
            return Err(RdmaError::RequestTooLarge(
                message.len(),
                running.max_fragmented_recv_size as usize,
            ));
        }

        let mut total_data_sent: u32 = 0;
        let mut fragment_num = 0;

        let mut buf_iterator = message.iter();
        let mut current_buf = buf_iterator
            .next()
            .expect("Some data to send, but no buffers");

        let mut local_mr = running.rdma.alloc_local_mr(
            Layout::from_size_align(running.max_send_size, Self::MR_ALIGN_TO).unwrap(),
        )?;

        let mut current_buf_offset: u32 = 0;
        let total_data_to_send = message.total_size() as u32;
        while total_data_sent < total_data_to_send {
            let remaining = current_buf.len() as u32 - current_buf_offset;
            let data_sending: u32 = remaining
                .min(running.max_rw_size.min(running.max_send_size as u32) - Self::IN_MR_OFFSET);
            if data_sending == 0 {
                current_buf = buf_iterator
                    .next()
                    .expect("More data to send, but no more buffers");
                current_buf_offset = 0;
                continue;
            }

            let total_remaining = total_data_to_send - total_data_sent;
            let data_to_send = &current_buf
                [current_buf_offset as usize..(current_buf_offset + data_sending) as usize];

            log::trace!(
                "Rdma sending fragment #{fragment_num} (len={} remaining={} total_sent={} total={})",
                data_to_send.len(),
                total_remaining,
                total_data_sent,
                total_data_to_send
            );
            Self::_send_fragment(data_to_send, &mut local_mr, total_remaining, running).await?;

            total_data_sent += data_to_send.len() as u32;
            current_buf_offset += data_to_send.len() as u32;
            fragment_num += 1;
        }

        assert!(total_data_sent == total_data_to_send);

        Ok(())
    }

    async fn _send_fragment(
        data: &[u8],
        working_mr: &mut LocalMr,
        remaining: u32,
        running: &RdmaRunningWo,
    ) -> std::result::Result<(), RdmaError> {
        assert!(
            data.len() <= running.max_send_size - Self::IN_MR_OFFSET as usize,
            "Data length {} exceeds max send size {}",
            data.len(),
            running.max_send_size - Self::IN_MR_OFFSET as usize
        );
        assert!(remaining >= data.len() as u32);

        // Grant credits if needed
        // This method is assumed to be single-threaded -- i.e., there's no actual race here.
        // at worst, we might grant a bit less credits than we could have.
        let grant_credits = running
            .credits
            .current_credit_requested
            .load(std::sync::atomic::Ordering::SeqCst)
            .min(running.credits.recv_credits_limit);

        running
            .credits
            .current_credit_requested
            .fetch_sub(grant_credits, std::sync::atomic::Ordering::SeqCst);

        // Wait for credits before sending the response;
        running
            .credits
            .send_credits
            .acquire()
            .await
            .map_err(|_| RdmaError::Other("Failed to acquire send credit"))?
            .forget();
        // credits are added back in the receive flow, so forgetting here goes well.

        // We request target - current credits after this.
        let current_credits = running.credits.send_credits.available_permits() as u16;
        let credits_to_request = running.credits.send_credits_target
            - current_credits.min(running.credits.send_credits_target);

        log::debug!(
            "Send credits left: {current_credits}, requesting {credits_to_request} more credits; granting to server: {grant_credits} (server requested: {})",
            running
                .credits
                .current_credit_requested
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        let header = SmbdDataTransferHeader {
            data_length: data.len() as u32,
            remaining_data_length: remaining - data.len() as u32,
            data_offset: Self::IN_MR_OFFSET,
            flags: SmbdDataTransferFlags::new(),
            credits_requested: credits_to_request,
            credits_granted: grant_credits,
        };

        let data_end = Self::IN_MR_OFFSET + data.len() as u32;
        let data_end = data_end as usize;
        {
            let mut mr_data = working_mr.as_mut_slice();
            let mut cursor = std::io::Cursor::new(mr_data.as_mut());
            header.write(&mut cursor)?;

            mr_data[Self::IN_MR_OFFSET as usize..data_end].copy_from_slice(data);
        }

        running.rdma.send_raw(working_mr).await?;
        Ok(())
    }
}

impl SmbTransport for RdmaTransport {
    fn connect<'a>(
        &'a mut self,
        _server_name: &'a str,
        server_address: SocketAddr,
    ) -> futures_core::future::BoxFuture<'a, crate::error::Result<()>> {
        async move { Ok(self.connect_and_negotiate(server_address).await?) }.boxed()
    }

    fn default_port(&self) -> u16 {
        Self::DEFAULT_SMBDIRECT_PORT
    }

    fn split(
        self: Box<Self>,
    ) -> crate::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        let (ro, wo, address) = match self.state {
            RdmaTransportState::RunningRw(x) => x,
            _ => return Err(TransportError::AlreadySplit),
        };
        Ok((
            Box::new(Self {
                state: RdmaTransportState::RunningRo(ro, address),
                config: self.config.clone(),
            }),
            Box::new(Self {
                state: RdmaTransportState::RunningWo(wo, address),
                config: self.config,
            }),
        ))
    }

    fn remote_address(&self) -> crate::error::Result<SocketAddr> {
        match &self.state {
            RdmaTransportState::RunningRw((_, _, addr))
            | RdmaTransportState::RunningRo(_, addr)
            | RdmaTransportState::RunningWo(_, addr) => Ok(*addr),
            _ => Err(TransportError::NotConnected),
        }
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
