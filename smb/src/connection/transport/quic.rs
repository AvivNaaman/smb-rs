#![cfg(feature = "quic")]
//! QUIC transport implementation for SMB.
//!
//! This module uses the [quinn](https://docs.rs/quinn/latest/quinn/) crate to implement the QUIC transport protocol for SMB.
//! Therefore, it should only be used when async features are enabled.

use std::sync::Arc;

use crate::connection::QuicConfig;

use super::{
    traits::{SmbTransport, SmbTransportRead, SmbTransportWrite},
    utils::TransportUtils,
};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustls::pki_types::CertificateDer;
use rustls_platform_verifier::ConfigVerifierExt;

pub struct QuicTransport {
    recv_stream: Option<quinn::RecvStream>,
    send_stream: Option<quinn::SendStream>,

    endpoint: Endpoint,
}

impl QuicTransport {
    pub fn new(quic_config: &QuicConfig) -> crate::Result<Self> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        let local_address = quic_config.local_address.as_deref().unwrap_or("0.0.0.0:0");
        let client_addr = TransportUtils::parse_socket_address(local_address)?;
        let mut endpoint = Endpoint::client(client_addr)?;
        endpoint.set_default_client_config(Self::make_client_config(quic_config)?);
        Ok(Self {
            recv_stream: None,
            send_stream: None,
            endpoint,
        })
    }

    fn make_client_config(quic_config: &QuicConfig) -> crate::Result<quinn::ClientConfig> {
        let mut quic_client_config = match &quic_config.cert_validation {
            crate::connection::QuicCertValidationOptions::PlatformVerifier => {
                rustls::ClientConfig::with_platform_verifier()
            }
            crate::connection::QuicCertValidationOptions::CustomRootCerts(items) => {
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

    pub fn can_read(&self) -> bool {
        self.recv_stream.is_some()
    }

    pub fn can_write(&self) -> bool {
        self.send_stream.is_some()
    }

    async fn send_raw(&mut self, buf: &[u8]) -> crate::Result<()> {
        let send_stream = self
            .send_stream
            .as_mut()
            .ok_or(crate::Error::NotConnected)?;
        send_stream.write_all(buf).await?;
        Ok(())
    }

    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()> {
        let recv_stream = self
            .recv_stream
            .as_mut()
            .ok_or(crate::Error::NotConnected)?;
        recv_stream.read_exact(out_buf).await?;
        Ok(())
    }
}

impl SmbTransport for QuicTransport {
    fn connect<'a>(&'a mut self, server: &'a str) -> BoxFuture<'a, crate::Result<()>> {
        async {
            let server_addr = TransportUtils::parse_socket_address(server)?;
            let server_name = TransportUtils::get_server_name(server)?;
            let connection = self.endpoint.connect(server_addr, &server_name)?;
            let (send, recv) = connection.await?.open_bi().await?;
            self.send_stream = Some(send);
            self.recv_stream = Some(recv);
            Ok(())
        }
        .boxed()
    }

    fn split(
        mut self: Box<Self>,
    ) -> crate::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        if !self.can_read() || !self.can_write() {
            return Err(crate::Error::InvalidState(
                "Cannot split a non-connected client.".into(),
            ));
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
            }),
            Box::new(Self {
                recv_stream: None,
                send_stream: Some(send_stream),
                endpoint: endpoint_clone,
            }),
        ))
    }

    fn default_port(&self) -> u16 {
        443
    }
}

impl SmbTransportWrite for QuicTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.send_raw(buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.send_raw(buf)
    }
}

impl SmbTransportRead for QuicTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.receive_exact(out_buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<Vec<u8>> {
        self.receive(out_buf)
    }
}
