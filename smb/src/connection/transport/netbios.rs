use std::{io::Cursor, time::Duration};

use super::{SmbTransport, SmbTransportRead, SmbTransportWrite, tcp::TcpTransport};
use crate::{
    Error,
    packets::netbios::{
        NBSSPacketHeader, NBSSPacketType, NBSSTrailer, NBSessionRequest, NetBiosName,
    },
};
use binrw::{BinRead, BinWrite};
#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
#[cfg(feature = "async")]
use futures_util::FutureExt;
use maybe_async::*;
pub(crate) struct NetBiosTransport {
    tcp: Box<dyn SmbTransport>,
}

impl NetBiosTransport {
    pub(crate) fn new(timeout: Duration) -> NetBiosTransport {
        NetBiosTransport {
            tcp: Box::new(TcpTransport::new(timeout)),
        }
    }

    /// Starts the underlying TCP connection, and sends NetBIOS session request and expects a session response.
    #[maybe_async]
    async fn do_connect(&mut self, endpoint: &str) -> crate::Result<()> {
        log::debug!("Connecting to NetBIOS Session services TCP...");
        self.tcp.connect(endpoint).await?;

        log::info!("Performing NetBIOS session setup...");
        self.netbios_session_setup().await?;

        log::debug!("NetBIOS session setup completed.");
        Ok(())
    }

    #[maybe_async]
    async fn netbios_session_setup(&mut self) -> crate::Result<()> {
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
                return Err(Error::InvalidState(format!(
                    "Unexpected NetBIOS session response: {x:?}",
                )));
            }
        }

        Ok(())
    }

    #[maybe_async]
    async fn netbios_receive_header(&mut self) -> crate::Result<NBSSPacketHeader> {
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
        endpoint: &'a str,
    ) -> futures_core::future::BoxFuture<'a, crate::Result<()>> {
        self.do_connect(endpoint).boxed()
    }

    #[cfg(not(feature = "async"))]
    fn connect(&mut self, endpoint: &str) -> crate::Result<()> {
        self.do_connect(endpoint)
    }

    fn default_port(&self) -> u16 {
        139
    }

    fn split(
        self: Box<Self>,
    ) -> crate::Result<(
        Box<dyn super::SmbTransportRead>,
        Box<dyn super::SmbTransportWrite>,
    )> {
        // SMB2 default transport (TCP) is actuall compatible with NetBIOS,
        // after setting up the session as performed in `connect()` above.
        // So we can just return the TCP transport as the read/write transport.
        // That's also why we don't need to override send/receive methods in trait impls below.
        self.tcp.split()
    }
}

impl SmbTransportRead for NetBiosTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.tcp.receive_exact(out_buf)
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()> {
        self.tcp.receive_exact(out_buf)
    }

    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> crate::Result<()> {
        self.tcp.set_read_timeout(timeout)
    }
}
impl SmbTransportWrite for NetBiosTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.tcp.send_raw(buf)
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.tcp.send_raw(buf)
    }
}
