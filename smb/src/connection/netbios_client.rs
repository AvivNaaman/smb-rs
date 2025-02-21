use maybe_async::*;
use std::io::Cursor;

#[cfg(feature = "sync")]
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use binrw::prelude::*;

use crate::packets::netbios::{NetBiosMessageContent, NetBiosTcpMessage, NetBiosTcpMessageHeader};

/// A (very) simple NETBIOS client.
///
/// This client is NOT thread-safe, and should only be used for SMB wraaping.
///
/// Use [connect](NetBiosClient::connect), [send](NetBiosClient::send),
/// and [receive_bytes](NetBiosClient::recieve_bytes) to interact with a server.
#[derive(Debug)]
pub struct NetBiosClient {
    connection: Option<TcpStream>,
}

impl NetBiosClient {
    pub fn new() -> NetBiosClient {
        NetBiosClient { connection: None }
    }

    /// Connects to a NetBios server in the specified address.
    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> crate::Result<()> {
        self.connection = Some(TcpStream::connect(address).await?);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    #[cfg(feature = "sync")]
    pub fn disconnect(&mut self) {
        if let Some(connection) = self.connection.as_mut() {
            let _ = connection.shutdown(std::net::Shutdown::Both);
        }
        self.connection = None;
    }

    #[cfg(feature = "async")]
    pub async fn disconnect(&mut self) {
        if let Some(connection) = self.connection.as_mut() {
            let _ = connection.shutdown().await;
        }
        self.connection = None;
    }

    /// Sends a NetBios message.
    #[maybe_async]
    pub async fn send(&mut self, data: NetBiosMessageContent) -> crate::Result<()> {
        let raw_message = NetBiosTcpMessage::from_content(&data)?;
        Ok(self.send_raw(raw_message).await?)
    }

    /// Sends a raw byte array of a NetBios message.
    #[maybe_async]
    pub async fn send_raw(&mut self, data: NetBiosTcpMessage) -> crate::Result<()> {
        // TODO(?): assert data is a valid and not-too-large NetBios message.
        Self::write_all(
            self.connection.as_mut().ok_or(crate::Error::NotConnected)?,
            &data.to_bytes()?,
        )
        .await?;

        Ok(())
    }

    // Recieves and parses a NetBios message header, without parsing the message data.
    #[maybe_async]
    pub async fn recieve_bytes(&mut self) -> crate::Result<NetBiosTcpMessage> {
        let tcp = self.connection.as_mut().ok_or(crate::Error::NotConnected)?;

        // Recieve header.
        let mut header_data = vec![0; NetBiosTcpMessageHeader::SIZE];
        Self::read_exact(tcp, &mut header_data).await?;
        let header = NetBiosTcpMessageHeader::read(&mut Cursor::new(header_data))?;

        if header.stream_protocol_length.value > 2u32.pow(3 * 8) - 1 {
            return Err(crate::Error::InvalidMessage("Message too large.".into()));
        }

        // Recieve message data.
        let mut data = vec![0; header.stream_protocol_length.value as usize];
        Self::read_exact(tcp, &mut data).await?;

        Ok(NetBiosTcpMessage { content: data })
    }

    /// For synchronous implementations, sets the read timeout for the connection.
    /// This is useful when polling for messages.
    #[cfg(feature = "sync")]
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> crate::Result<()> {
        self.connection
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .set_read_timeout(timeout)
            .map_err(|e| e.into())
    }

    /// For synchronous implementations, gets the read timeout for the connection.
    #[cfg(feature = "sync")]
    pub fn read_timeout(&self) -> crate::Result<Option<std::time::Duration>> {
        self.connection
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .read_timeout()
            .map_err(|e| e.into())
    }

    /// Like an old regular read_exact, but with connection abort handling.
    #[maybe_async]
    async fn read_exact(tcp: &mut TcpStream, buf: &mut [u8]) -> crate::Result<()> {
        tcp.read_exact(buf).await.map_err(Self::map_tcp_error)?;
        Ok(())
    }

    /// Like an old regular write_all, but with connection abort handling.
    #[maybe_async]
    async fn write_all(tcp: &mut TcpStream, buf: &[u8]) -> crate::Result<()> {
        tcp.write_all(buf).await.map_err(Self::map_tcp_error)?;
        Ok(())
    }

    /// Maps a TCP error to a crate error.
    /// Connection aborts and unexpected EOFs are mapped to [Error::NotConnected].
    #[inline]
    fn map_tcp_error(e: io::Error) -> crate::Error {
        if e.kind() == io::ErrorKind::ConnectionAborted || e.kind() == io::ErrorKind::UnexpectedEof
        {
            crate::Error::NotConnected
        } else {
            e.into()
        }
    }

    /// Clones the client, returning a new client with the same connection.
    #[cfg(all(feature = "sync", not(feature = "single_threaded")))]
    pub(crate) fn try_clone(&self) -> crate::Result<NetBiosClient> {
        // TODO: If used for splitting read/write, call Shutdown::Read on the original connection and Shutdown::Write on the clone.
        Ok(NetBiosClient {
            connection: Some(
                self.connection
                    .as_ref()
                    .ok_or(crate::Error::NotConnected)?
                    .try_clone()?,
            ),
        })
    }
}
