use binrw::{BinRead, BinWrite};
#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
#[cfg(feature = "async")]
use futures_util::FutureExt;
use std::io::Cursor;

use smb_msg::SmbTcpMessageHeader;

#[allow(async_fn_in_trait)]
pub trait SmbTransport: Send + SmbTransportRead + SmbTransportWrite {
    #[cfg(feature = "async")]
    fn connect<'a>(&'a mut self, endpoint: &'a str) -> BoxFuture<'a, crate::Result<()>>;
    #[cfg(not(feature = "async"))]
    fn connect(&mut self, endpoint: &str) -> crate::Result<()>;

    fn default_port(&self) -> u16;

    /// Splits the transport into two separate transports:
    /// One for reading, and one for writing,
    /// given that the transport has both the reading and writing capabilities.
    fn split(
        self: Box<Self>,
    ) -> crate::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)>;
}

pub trait SmbTransportWrite: Send {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::Result<()>>;
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> crate::Result<()>;

    #[cfg(feature = "async")]
    fn send<'a>(&'a mut self, message: &'a [u8]) -> BoxFuture<'a, crate::Result<()>> {
        async {
            // Transport Header
            let header = SmbTcpMessageHeader {
                stream_protocol_length: message.len() as u32,
            };
            let mut header_buf = Vec::with_capacity(SmbTcpMessageHeader::SIZE);
            header.write(&mut Cursor::new(&mut header_buf))?;
            self.send_raw(&header_buf).await?;

            // Content - final response.
            self.send_raw(message).await
        }
        .boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send(&mut self, message: &[u8]) -> crate::Result<()> {
        // Transport Header
        let header = SmbTcpMessageHeader {
            stream_protocol_length: message.len() as u32,
        };
        let mut header_buf = Vec::with_capacity(SmbTcpMessageHeader::SIZE);
        header.write(&mut Cursor::new(&mut header_buf))?;
        self.send_raw(&header_buf)?;

        // Content - final response.
        self.send_raw(message)
    }
}

pub trait SmbTransportWriteExt: SmbTransportWrite {
    #[cfg(feature = "async")]
    /// Use this method to send a SMB message to the server.
    /// This sends the message itself, adding the transport header.
    fn send<'a>(&'a mut self, message: &'a [u8]) -> BoxFuture<'a, crate::Result<()>>;
    #[cfg(not(feature = "async"))]
    /// Use this method to send a SMB message to the server.
    /// This sends the message itself, adding the transport header.
    fn send(&mut self, message: &[u8]) -> crate::Result<()>;
}

pub trait SmbTransportRead: Send {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, crate::Result<()>>;
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()>;

    #[cfg(feature = "async")]
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, crate::Result<Vec<u8>>> {
        async {
            // Transport Header
            let mut header_data = [0; SmbTcpMessageHeader::SIZE];
            self.receive_exact(&mut header_data).await?;
            let header = SmbTcpMessageHeader::read(&mut Cursor::new(header_data))?;

            // Content - final response.
            let mut data = vec![0; header.stream_protocol_length as usize];
            self.receive_exact(&mut data).await?;

            log::trace!(
                "Received SMB message of {} bytes from server: {:?}",
                data.len(),
                data
            );

            Ok(data)
        }
        .boxed()
    }

    #[cfg(not(feature = "async"))]
    fn receive(&mut self) -> crate::Result<Vec<u8>> {
        // Transport Header
        let mut header_data = [0; SmbTcpMessageHeader::SIZE];
        self.receive_exact(&mut header_data)?;
        let header = SmbTcpMessageHeader::read(&mut Cursor::new(header_data))?;

        // Content - final response.
        let mut data = vec![0; header.stream_protocol_length as usize];
        self.receive_exact(&mut data)?;

        log::trace!(
            "Received SMB message of {} bytes from server: {:?}",
            data.len(),
            data
        );

        Ok(data)
    }

    /// For synchronous implementations, sets the read timeout for the connection.
    /// This is useful when polling for messages.
    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> crate::Result<()>;
}

pub trait SmbTransportReadExt: SmbTransportRead {
    #[cfg(feature = "async")]
    /// Use this method to receive a SMB message from the server.
    /// This returns the message itself, dropping the transport header.
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, crate::Result<Vec<u8>>>;
    #[cfg(not(feature = "async"))]
    /// Use this method to receive a SMB message from the server.
    /// This returns the message itself, dropping the transport header.
    fn receive(&mut self) -> crate::Result<Vec<u8>>;
}

impl SmbTransportReadExt for dyn SmbTransportRead + '_ {
    #[cfg(feature = "async")]
    #[inline]
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, crate::Result<Vec<u8>>> {
        self.receive()
    }
    #[cfg(not(feature = "async"))]
    #[inline]
    fn receive(&mut self) -> crate::Result<Vec<u8>> {
        self.receive()
    }
}

impl SmbTransportReadExt for dyn SmbTransport + '_ {
    #[cfg(feature = "async")]
    #[inline]
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, crate::Result<Vec<u8>>> {
        self.receive()
    }
    #[cfg(not(feature = "async"))]
    #[inline]
    fn receive(&mut self) -> crate::Result<Vec<u8>> {
        self.receive()
    }
}
