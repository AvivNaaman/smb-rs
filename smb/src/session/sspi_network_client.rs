//!
//! MIT License
//!
//! Copyright (c) 2020 Devolutions/IronRDP
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
//!
//! This file was adapted from:
//! <https://github.com/Devolutions/IronRDP/blob/ac291423de6835df855e1b40c8da6b45ac0905d9/crates/ironrdp-tokio/src/reqwest.rs>
//!
//!
//! Modified by Aviv Naaman @AvivNaaman on 2025-08-08
//! This module is async-only, since [sspi] implements a synchronous network client.

#![cfg(all(feature = "async", feature = "kerberos"))]

use core::future::Future;
use core::net::{IpAddr, Ipv4Addr};
use core::pin::Pin;

use reqwest::Client;
use sspi::network_client::AsyncNetworkClient;
use sspi::{Error, ErrorKind};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};
use url::Url;

pub struct ReqwestNetworkClient {
    client: Option<Client>,
}

impl AsyncNetworkClient for ReqwestNetworkClient {
    fn send<'a>(
        &'a mut self,
        network_request: &'a sspi::generator::NetworkRequest,
    ) -> Pin<Box<dyn Future<Output = sspi::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(ReqwestNetworkClient::send(self, network_request))
    }
}

impl ReqwestNetworkClient {
    pub fn new() -> Self {
        Self { client: None }
    }
}

impl Default for ReqwestNetworkClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestNetworkClient {
    pub async fn send<'a>(
        &'a mut self,
        request: &'a sspi::generator::NetworkRequest,
    ) -> sspi::Result<Vec<u8>> {
        log::debug!("Sending SSPI network request to {}", request.url);
        match &request.protocol {
            sspi::network_client::NetworkProtocol::Tcp => {
                self.send_tcp(&request.url, &request.data).await
            }
            sspi::network_client::NetworkProtocol::Udp => {
                self.send_udp(&request.url, &request.data).await
            }
            sspi::network_client::NetworkProtocol::Http
            | sspi::network_client::NetworkProtocol::Https => {
                self.send_http(&request.url, &request.data).await
            }
        }
    }

    async fn send_tcp(&self, url: &Url, data: &[u8]) -> sspi::Result<Vec<u8>> {
        let addr = format!(
            "{}:{}",
            url.host_str().unwrap_or_default(),
            url.port().unwrap_or(88)
        );

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        stream
            .write_all(data)
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        let len = stream
            .read_u32()
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        let mut buf = vec![0; len as usize + 4];
        buf[0..4].copy_from_slice(&(len.to_be_bytes()));

        stream
            .read_exact(&mut buf[4..])
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        Ok(buf)
    }

    async fn send_udp(&self, url: &Url, data: &[u8]) -> sspi::Result<Vec<u8>> {
        let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        let addr = format!(
            "{}:{}",
            url.host_str().unwrap_or_default(),
            url.port().unwrap_or(88)
        );

        udp_socket
            .send_to(data, addr)
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        // 48 000 bytes: default maximum token len in Windows
        let mut buf = vec![0; 0xbb80];

        let n = udp_socket
            .recv(&mut buf)
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
        let buf = &buf[0..n];

        let mut reply_buf = Vec::with_capacity(n + 4);
        let n = u32::try_from(n)
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
        reply_buf.extend_from_slice(&n.to_be_bytes());
        reply_buf.extend_from_slice(buf);

        Ok(reply_buf)
    }

    async fn send_http(&mut self, url: &Url, data: &[u8]) -> sspi::Result<Vec<u8>> {
        let client = self.client.get_or_insert_with(Client::new);

        let response = client
            .post(url.clone())
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("failed to send KDC request over proxy: {e:?}"),
                )
            })?
            .error_for_status()
            .map_err(|e| {
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("KdcProxy: {e:?}"),
                )
            })?;

        let body = response.bytes().await.map_err(|e| {
            Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                format!("failed to receive KDC response: {e:?}"),
            )
        })?;

        // The type bytes::Bytes has a special From implementation for Vec<u8>.
        let body = Vec::from(body);

        Ok(body)
    }
}
