use std::{io::Cursor, net::SocketAddr, time::Duration};

use super::msg::*;
use crate::{TcpTransport, TransportError, traits::*};

use binrw::{BinRead, BinWrite};
#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
#[cfg(feature = "async")]
use futures_util::FutureExt;
use maybe_async::*;
pub struct NetBiosTransport {
    tcp: Box<dyn SmbTransport>,
}
use crate::error::Result;

impl NetBiosTransport {
    pub fn new(timeout: Duration) -> NetBiosTransport {
        NetBiosTransport {
            tcp: Box::new(TcpTransport::new(timeout)),
        }
    }

    /// Starts the underlying TCP connection, and sends NetBIOS session request and expects a session response.
    #[maybe_async]
    async fn do_connect(&mut self, server_name: &str, address: SocketAddr) -> Result<()> {
        log::debug!("Connecting to NetBIOS Session services TCP...");
        self.tcp.connect(server_name, address).await?;

        log::info!("Performing NetBIOS session setup...");
        self.netbios_session_setup().await?;

        log::debug!("NetBIOS session setup completed.");
        Ok(())
    }

    #[maybe_async]
    async fn netbios_session_setup(&mut self) -> Result<()> {
        let session_request = NBSessionRequest {
            called_name: NetBiosName::new("*SMBSERVER".to_string(), 0x20),
            calling_name: NetBiosName::new("SmbClient".to_string(), 0x0),
        };

        let mut req_buf = Vec::new();
        session_request.write(&mut Cursor::new(&mut req_buf))?;
        log::debug!("Sending NetBIOS session request");
        let mut header_cursor = Cursor::new([0u8; NBSSPacketHeader::SIZE]);
        let header = NBSSPacketHeader {
            ptype: NBSSPacketType::SessionRequest,
            flags: 0,
            length: req_buf.len() as u16,
        };
        header.write(&mut header_cursor)?;
        self.tcp
            .send_raw(header_cursor.into_inner().as_slice())
            .await?;
        self.tcp.send_raw(req_buf.as_slice()).await?;

        log::debug!("Waiting for NetBIOS session response");
        let header = self.netbios_receive_header().await?;
        let mut result_packet = Vec::with_capacity(header.length as usize);
        self.tcp.receive_exact(&mut result_packet).await?;

        let nbss_packet =
            NBSSTrailer::read_args(&mut Cursor::new(&result_packet), (header.ptype,))?;

        match nbss_packet {
            NBSSTrailer::PositiveSessionResponse(_) => {
                log::debug!("NetBIOS session request succeeded.");
            }
            x => {
                log::debug!("NetBIOS session request invalid with packet: {:?}", x);
                return Err(TransportError::InvalidMessage);
            }
        }

        Ok(())
    }

    #[maybe_async]
    async fn netbios_receive_header(&mut self) -> Result<NBSSPacketHeader> {
        let mut header = [0u8; NBSSPacketHeader::SIZE];
        self.tcp.receive_exact(&mut header).await?;

        let header = NBSSPacketHeader::read(&mut Cursor::new(&header))?;
        Ok(header)
    }
}

impl SmbTransport for NetBiosTransport {
    #[cfg(feature = "async")]
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        address: SocketAddr,
    ) -> futures_core::future::BoxFuture<'a, Result<()>> {
        self.do_connect(server_name, address).boxed()
    }

    #[cfg(not(feature = "async"))]
    fn connect(&mut self, server_name: &str, address: SocketAddr) -> Result<()> {
        self.do_connect(server_name, address)
    }

    fn default_port(&self) -> u16 {
        139
    }

    fn split(self: Box<Self>) -> Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        // SMB2 default transport (TCP) is actuall compatible with NetBIOS,
        // after setting up the session as performed in `connect()` above.
        // So we can just return the TCP transport as the read/write transport.
        // That's also why we don't need to override send/receive methods in trait impls below.
        self.tcp.split()
    }

    fn remote_address(&self) -> Result<std::net::SocketAddr> {
        self.tcp.remote_address()
    }
}

impl SmbTransportRead for NetBiosTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        self.tcp.receive_exact(out_buf)
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        self.tcp.receive_exact(out_buf)
    }

    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.tcp.set_read_timeout(timeout)
    }
}
impl SmbTransportWrite for NetBiosTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.tcp.send_raw(buf)
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        self.tcp.send_raw(buf)
    }
}
