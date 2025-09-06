use super::{
    traits::{SmbTransport, SmbTransportRead, SmbTransportWrite},
    utils::TransportUtils,
};
use crate::error::*;

use std::net::SocketAddr;

#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
use maybe_async::*;
use std::time::Duration;

#[cfg(feature = "async")]
use futures_util::FutureExt;
#[cfg(not(feature = "async"))]
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, tcp},
    select,
};

use binrw::prelude::*;

#[cfg(feature = "async")]
type TcpRead = tcp::OwnedReadHalf;
#[cfg(feature = "async")]
type TcpWrite = tcp::OwnedWriteHalf;

#[cfg(not(feature = "async"))]
type TcpRead = TcpStream;
#[cfg(not(feature = "async"))]
type TcpWrite = TcpStream;
pub struct TcpTransport {
    reader: Option<TcpRead>,
    writer: Option<TcpWrite>,
    timeout: Duration,
}

impl TcpTransport {
    pub fn new(timeout: Duration) -> TcpTransport {
        TcpTransport {
            reader: None,
            writer: None,
            timeout,
        }
    }

    /// Connects to a NetBios server in the specified endpoint with a timeout.
    /// This is the threaded version of [connect](NetBiosClient::connect) -
    /// using the [std::net::TcpStream] as the underlying socket provider.
    #[cfg(not(feature = "async"))]
    fn connect_timeout(&mut self, endpoint: &SocketAddr) -> crate::Result<TcpStream> {
        if self.timeout == Duration::ZERO {
            log::debug!("Connecting to {endpoint}.");
            return TcpStream::connect(endpoint).map_err(Into::into);
        }

        log::debug!("Connecting to {endpoint} with timeout {:?}.", self.timeout);
        TcpStream::connect_timeout(endpoint, self.timeout).map_err(|e| match e.kind() {
            io::ErrorKind::TimedOut => {
                log::error!("Connection timed out after {:?}", self.timeout);
                Error::OperationTimeout(TimedOutTask::TcpConnect, self.timeout)
            }
            _ => {
                log::error!("Failed to connect to {endpoint}: {e}");
                e.into()
            }
        })
    }

    /// Connects to a NetBios server in the specified endpoint with a timeout.
    /// This is the async version of [connect](NetBiosClient::connect) -
    /// using the [tokio::net::TcpStream] as the underlying socket provider.
    #[cfg(feature = "async")]
    async fn connect_timeout(&mut self, endpoint: &SocketAddr) -> crate::Result<TcpStream> {
        if self.timeout == Duration::ZERO {
            log::debug!("Connecting to {endpoint}.",);
            return TcpStream::connect(&endpoint).await.map_err(Into::into);
        }

        select! {
            res = TcpStream::connect(&endpoint) => res.map_err(Into::into),
            _ = tokio::time::sleep(self.timeout) => Err(
                Error::OperationTimeout(
                    TimedOutTask::TcpConnect, self.timeout
                )
            ),
        }
    }

    /// Async implementation of split socket to read and write halves.
    #[cfg(feature = "async")]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let (r, w) = socket.into_split();
        (r, w)
    }

    /// Sync implementation of split socket to read and write halves.
    #[cfg(not(feature = "async"))]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let rsocket = socket.try_clone().unwrap();
        let wsocket = socket;

        (rsocket, wsocket)
    }

    /// For synchronous implementations, gets the read timeout for the connection.
    #[cfg(not(feature = "async"))]
    pub fn read_timeout(&self) -> crate::Result<Option<std::time::Duration>> {
        self.reader
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .read_timeout()
            .map_err(|e| e.into())
    }

    /// Maps a TCP error to a crate error.
    /// Connection aborts and unexpected EOFs are mapped to [Error::NotConnected].
    #[inline]
    fn map_tcp_error(e: io::Error) -> crate::Error {
        if e.kind() == io::ErrorKind::ConnectionAborted || e.kind() == io::ErrorKind::UnexpectedEof
        {
            log::error!("Got IO error: {e} -- Connection Error, notify NotConnected!");
            return crate::Error::NotConnected;
        }
        if e.kind() == io::ErrorKind::WouldBlock {
            log::trace!("Got IO error: {e} -- with ErrorKind::WouldBlock.");
        } else {
            log::error!("Got IO error: {e} -- Mapping to IO error.",);
        }
        e.into()
    }

    #[maybe_async]
    #[inline]
    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()> {
        let reader = self.reader.as_mut().ok_or(crate::Error::NotConnected)?;
        log::trace!("Reading {} bytes.", out_buf.len());
        reader
            .read_exact(out_buf)
            .await
            .map_err(Self::map_tcp_error)?;
        log::trace!("Read {} bytes OK.", out_buf.len());
        Ok(())
    }

    #[maybe_async::maybe_async]
    #[inline]
    async fn send_raw(&mut self, message: &[u8]) -> crate::Result<()> {
        log::trace!("Sending {} bytes.", message.len());
        let writer = self.writer.as_mut().ok_or(crate::Error::NotConnected)?;
        writer
            .write_all(message)
            .await
            .map_err(Self::map_tcp_error)?;
        Ok(())
    }

    #[maybe_async::maybe_async]
    #[inline]
    async fn do_connect(&mut self, endpoint: &str) -> crate::Result<()> {
        let endpoint = TransportUtils::parse_socket_address(endpoint)?;
        let socket = self.connect_timeout(&endpoint).await?;
        let (r, w) = Self::split_socket(socket);
        self.reader = Some(r);
        self.writer = Some(w);
        Ok(())
    }
}

impl SmbTransport for TcpTransport {
    #[cfg(feature = "async")]
    fn connect<'a>(&'a mut self, endpoint: &'a str) -> BoxFuture<'a, crate::Result<()>> {
        self.do_connect(endpoint).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn connect(&mut self, endpoint: &str) -> crate::Result<()> {
        self.do_connect(endpoint)
    }

    fn split(
        self: Box<Self>,
    ) -> crate::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        Ok((
            Box::new(Self {
                reader: self.reader,
                writer: None,
                timeout: self.timeout,
            }),
            Box::new(Self {
                reader: None,
                writer: self.writer,
                timeout: self.timeout,
            }),
        ))
    }

    fn default_port(&self) -> u16 {
        445
    }
}

impl SmbTransportWrite for TcpTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.send_raw(buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.send_raw(buf)
    }
}

impl SmbTransportRead for TcpTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.receive_exact(out_buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()> {
        self.receive_exact(out_buf)
    }

    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> crate::Result<()> {
        self.reader
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.into())
    }
}
