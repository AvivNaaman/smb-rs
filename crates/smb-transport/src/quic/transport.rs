//! QUIC transport implementation for SMB.
//!
//! This module uses the [quinn](https://docs.rs/quinn/latest/quinn/) crate to implement the QUIC transport protocol for SMB.
//! Therefore, it should only be used when async features are enabled.
#![cfg(feature = "quic")]

// quic => async
#[cfg(all(not(feature = "async"), feature = "quic"))]
compile_error!(
    "QUIC transport requires the async feature to be enabled. \
    Please enable the async feature in your Cargo.toml."
);

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use super::error::*;
use crate::{
    QuicConfig,
    traits::{SmbTransport, SmbTransportRead, SmbTransportWrite},
    utils::TransportUtils,
};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::select;

pub struct QuicTransport {
    recv_stream: Option<quinn::RecvStream>,
    send_stream: Option<quinn::SendStream>,

    endpoint: Endpoint,
    timeout: Duration,
}

const LOCALHOST_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

impl QuicTransport {
    pub fn new(quic_config: &QuicConfig, timeout: Duration) -> crate::error::Result<Self> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        let client_addr = quic_config.local_address.unwrap_or(LOCALHOST_V4);
        let mut endpoint = Endpoint::client(client_addr)?;
        endpoint.set_default_client_config(Self::make_client_config(quic_config)?);
        Ok(Self {
            recv_stream: None,
            send_stream: None,
            endpoint,
            timeout,
        })
    }

    fn _connect(
        &mut self,
        server_addr: SocketAddr,
        server_name: String,
    ) -> BoxFuture<'_, Result<()>> {
        async move {
            let connection = self.endpoint.connect(server_addr, &server_name)?;
            let (send, recv) = connection.await?.open_bi().await?;
            self.send_stream = Some(send);
            self.recv_stream = Some(recv);
            Ok(())
        }
        .boxed()
    }

    fn make_client_config(quic_config: &QuicConfig) -> Result<quinn::ClientConfig> {
        let mut quic_client_config = match &quic_config.cert_validation {
            super::config::QuicCertValidationOptions::PlatformVerifier => {
                rustls::ClientConfig::with_platform_verifier()?
            }
            super::config::QuicCertValidationOptions::CustomRootCerts(items) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in items {
                    match std::fs::read(cert) {
                        Ok(cert) => {
                            roots.add(CertificateDer::from(cert))?;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                            log::info!("local server certificate not found");
                        }
                        Err(e) => {
                            log::error!("failed to open local server certificate: {e}");
                        }
                    }
                }
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
        };
        quic_client_config.alpn_protocols = vec![b"smb".to_vec()];
        Ok(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(quic_client_config)?,
        )))
    }

    async fn inner_connect(
        &mut self,
        server_name: &str,
        server_address: SocketAddr,
    ) -> crate::error::Result<()> {
        let connection = self
            .endpoint
            .connect(server_address, server_name)
            .map_err(QuicError::from)?
            .await
            .map_err(|e| match e {
                quinn::ConnectionError::TimedOut => {
                    log::error!("Connection timed out after {:?}", self.timeout);
                    crate::TransportError::Timeout(self.timeout)
                }
                _ => {
                    log::error!("Failed to connect to {server}: {e}");
                    QuicError::ConnectionError(e).into()
                }
            })?;
        let (send, recv) = connection.open_bi().await.map_err(|e| {
            log::error!("Failed to open bidirectional stream: {e}");
            QuicError::ConnectionError(e)
        })?;
        self.send_stream = Some(send);
        self.recv_stream = Some(recv);
        Ok(())
    }

    pub fn can_read(&self) -> bool {
        self.recv_stream.is_some()
    }

    pub fn can_write(&self) -> bool {
        self.send_stream.is_some()
    }

    async fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        let send_stream = self.send_stream.as_mut().ok_or(QuicError::NotConnected)?;
        send_stream.write_all(buf).await?;
        Ok(())
    }

    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        let recv_stream = self.recv_stream.as_mut().ok_or(QuicError::NotConnected)?;
        recv_stream.read_exact(out_buf).await?;
        Ok(())
    }
}

impl SmbTransport for QuicTransport {
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        server_address: SocketAddr,
    ) -> BoxFuture<'a, crate::error::Result<()>> {
        let timeout = self.timeout;
        async move {
            select! {
                res = self.inner_connect(server_name, server_address) => {
                    res
                },
                _ = tokio::time::sleep(timeout) => {
                    log::debug!("QUIC Connection timed out after {:?}", timeout);
                    Err(crate::TransportError::Timeout(timeout))
                }
            }
        }
        .boxed()
    }

    fn split(
        mut self: Box<Self>,
    ) -> crate::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        if !self.can_read() || !self.can_write() {
            return Err(crate::TransportError::NotConnected);
        }
        let (recv_stream, send_stream) = (
            self.recv_stream.take().unwrap(),
            self.send_stream.take().unwrap(),
        );

        // TODO: Is this actually needed?
        let endpoint_clone = self.endpoint.clone();

        Ok((
            Box::new(Self {
                recv_stream: Some(recv_stream),
                send_stream: None,
                endpoint: self.endpoint,
                timeout: self.timeout,
            }),
            Box::new(Self {
                recv_stream: None,
                send_stream: Some(send_stream),
                endpoint: endpoint_clone,
                timeout: self.timeout,
            }),
        ))
    }

    fn default_port(&self) -> u16 {
        443
    }
}

impl SmbTransportWrite for QuicTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::error::Result<()>> {
        async { Ok(self.send_raw(buf).await?) }.boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        self.send_raw(buf)
    }
}

impl SmbTransportRead for QuicTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(
        &'a mut self,
        out_buf: &'a mut [u8],
    ) -> BoxFuture<'a, crate::error::Result<()>> {
        async { Ok(self.receive_exact(out_buf).await?) }.boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<Vec<u8>> {
        self.receive(out_buf)
    }
}
