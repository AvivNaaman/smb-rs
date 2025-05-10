use crate::{connection::preauth_hash::PreauthHashValue, packets::smb2::*};
use maybe_async::*;
use std::sync::Arc;

#[derive(Debug)]
pub struct OutgoingMessage {
    pub message: PlainMessage,

    /// Whether to finalize the preauth hash after sending this message.
    /// If this is set to true twice per connection, an error will be thrown.
    pub finalize_preauth_hash: bool,

    /// Ask the sender to compress the message before sending, if possible.
    pub compress: bool,
    /// Ask the sender to encrypt the message before sending, if possible.
    pub encrypt: bool,
    // Signing is set through message/header/flags/signed.
    /// Whether this request also expects a response.
    /// This value defaults to true.
    pub has_response: bool,
}

impl OutgoingMessage {
    pub fn new(content: Content) -> OutgoingMessage {
        OutgoingMessage {
            message: PlainMessage::new(content),
            finalize_preauth_hash: false,
            compress: true,
            encrypt: false,
            has_response: true,
        }
    }
}

#[derive(Debug)]
pub struct SendMessageResult {
    // The message ID for the sent message.
    pub msg_id: u64,
    // If finalized, this is set.
    pub preauth_hash: Option<PreauthHashValue>,
}

impl SendMessageResult {
    pub fn new(msg_id: u64, preauth_hash: Option<PreauthHashValue>) -> SendMessageResult {
        SendMessageResult {
            msg_id,
            preauth_hash,
        }
    }
}

#[derive(Debug)]
pub struct IncomingMessage {
    pub message: PlainMessage,
    /// The raw message received from the server, after applying transformations (e.g. decompression).
    pub raw: Vec<u8>,

    // How did the message arrive?
    pub form: MessageForm,
}

#[derive(Debug, Default)]
pub struct MessageForm {
    pub compressed: bool,
    pub encrypted: bool,
    pub signed: bool,
}

impl MessageForm {
    pub fn signed_or_encrypted(&self) -> bool {
        self.signed || self.encrypted
    }
}

/// Options for receiving a message.
///
/// Use a builder pattern to set the options:
/// ```
/// use smb::packets::smb2::*;
/// use smb::msg_handler::ReceiveOptions;
///
/// let options = ReceiveOptions::new()
///    .with_status(&[Status::Success])
///    .with_cmd(Some(Command::Negotiate));
/// ```
#[derive(Debug)]
pub struct ReceiveOptions<'a> {
    /// The expected status(es) of the received message.
    /// If the received message has a different status, an error will be returned.
    pub status: &'a [Status],

    /// If set, this command will be checked against the received command.
    /// If not set, no check will be performed.
    pub cmd: Option<Command>,

    /// When receiving a message, only messages with this msg_id will be returned.
    /// This is mostly used for async message handling, where the client is waiting for a specific message.
    pub msg_id: u64,

    /// Whether to allow (and wait for) async responses.
    /// If set to false, an async response from the server will trigger an error.
    /// If set to true, the handler will allow async messages to be received,
    /// and will make the caller wait until the final async response is received --
    /// the async response with status other than [`Status::Pending`].
    pub allow_async: bool,
    // TODO: Add a sync primitive to cancel the receive operation.
    // consider making an abstract Notify in sync_helpers and use it everywhere.
    // pub cancel: Notify
}

impl<'a> ReceiveOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_status(mut self, status: &'a [Status]) -> Self {
        self.status = status;
        self
    }

    pub fn with_cmd(mut self, cmd: Option<Command>) -> Self {
        self.cmd = cmd;
        self
    }

    pub fn with_msg_id_filter(mut self, msg_id: u64) -> Self {
        self.msg_id = msg_id;
        self
    }

    pub fn with_allow_async(mut self, allow_async: bool) -> Self {
        self.allow_async = allow_async;
        self
    }
}

impl<'a> Default for ReceiveOptions<'a> {
    fn default() -> Self {
        ReceiveOptions {
            status: &[Status::Success],
            cmd: None,
            msg_id: 0,
            allow_async: false,
        }
    }
}

/// Chain-of-responsibility pattern trait for handling SMB messages
/// outgoing from the client or incoming from the server.
#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)] // We need `async`-ed trait functions for the #[maybe_async] macro.
pub trait MessageHandler {
    /// Send a message to the server, returning the result.
    /// This must be implemented. Each handler in the chain must call the next handler,
    /// after possibly modifying the message.
    async fn sendo(&self, msg: OutgoingMessage) -> crate::Result<SendMessageResult>;

    /// Receive a message from the server, returning the result.
    /// This must be implemented, and must call the next handler in the chain,
    /// if there is one, using the provided `ReceiveOptions`.
    async fn recvo(&self, options: ReceiveOptions) -> crate::Result<IncomingMessage>;

    // -- Utility functions, accessible from references via Deref.
    #[maybe_async]
    async fn send(&self, msg: Content) -> crate::Result<SendMessageResult> {
        self.sendo(OutgoingMessage::new(msg)).await
    }

    #[maybe_async]
    async fn recv(&self, cmd: Command) -> crate::Result<IncomingMessage> {
        self.recvo(ReceiveOptions::new().with_cmd(Some(cmd))).await
    }

    #[maybe_async]
    async fn sendo_recvo(
        &self,
        msg: OutgoingMessage,
        mut options: ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        // Send the message and wait for the matching response.
        let send_result = self.sendo(msg).await?;
        options.msg_id = send_result.msg_id;
        self.recvo(options).await
    }

    #[maybe_async]
    async fn send_recvo(
        &self,
        msg: Content,
        options: ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        self.sendo_recvo(OutgoingMessage::new(msg), options).await
    }

    #[maybe_async]
    async fn sendo_recv(&self, msg: OutgoingMessage) -> crate::Result<IncomingMessage> {
        let cmd = msg.message.content.associated_cmd();
        let options = ReceiveOptions::new().with_cmd(Some(cmd));
        self.sendo_recvo(msg, options).await
    }

    #[maybe_async]
    async fn send_recv(&self, msg: Content) -> crate::Result<IncomingMessage> {
        self.sendo_recv(OutgoingMessage::new(msg)).await
    }
}

/// A templated shared reference to an SMB message handler.
///
/// Provides a more ergonomic way to interact with the handler.
/// Provided methods are:
/// - `send*`: Send a message content to the server.
/// - `receive*`: Receive a message from the server.
/// - `send*_receive*`: Send a message and receive a response.
/// - `*o`: Send a message and receive a response with custom options:
///     - `sendo`: Send a message with custom, low-level handler options.
///     - `recvo`: Receive a message with custom, low-level handler options.
pub struct HandlerReference<T: MessageHandler + ?Sized> {
    pub handler: Arc<T>,
}

impl<T: MessageHandler> HandlerReference<T> {
    pub fn new(handler: T) -> HandlerReference<T> {
        HandlerReference {
            handler: Arc::new(handler),
        }
    }
}

// Implement deref that returns the content of Arc<T> above (T)
impl<T: MessageHandler> std::ops::Deref for HandlerReference<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.handler
    }
}

// Clone:
impl<T: MessageHandler> Clone for HandlerReference<T> {
    fn clone(&self) -> Self {
        HandlerReference {
            handler: self.handler.clone(),
        }
    }
}
