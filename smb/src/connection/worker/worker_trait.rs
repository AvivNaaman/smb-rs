use std::sync::Arc;

use crate::sync_helpers::*;

use maybe_async::*;

use crate::{
    connection::{
        negotiation_state::NegotiateState, netbios_client::NetBiosClient, transformer::Transformer,
    },
    msg_handler::{IncomingMessage, OutgoingMessage, SendMessageResult},
    session::SessionState,
};

/// SMB2 connection worker.
///
/// Implementations of this trait are responsible for handling the connection to the server,
/// sending netbios messages from SMB2 messages, and redirecting correct messages when received,
/// if using async, to the correct pending task.
#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait Worker: Sized + std::fmt::Debug {
    /// Instantiates a new connection worker.
    async fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>>;
    /// Stops the worker, shutting down the connection.
    async fn stop(&self) -> crate::Result<()>;

    async fn send(self: &Self, msg: OutgoingMessage) -> crate::Result<SendMessageResult>;
    /// Receive a message from the server.
    /// This is a user function that will wait for the message to be received.
    async fn receive(self: &Self, msg_id: u64) -> crate::Result<IncomingMessage>;

    /// Get the transformer for this worker.
    fn transformer(&self) -> &Transformer;

    #[maybe_async]
    async fn negotaite_complete(&self, neg_state: &NegotiateState) {
        self.transformer().negotiated(neg_state).await.unwrap();
    }

    #[maybe_async]
    async fn session_started(&self, session: Arc<Mutex<SessionState>>) -> crate::Result<()> {
        self.transformer().session_started(session).await
    }

    #[maybe_async]
    async fn session_ended(&self, session_id: u64) -> crate::Result<()> {
        self.transformer().session_ended(session_id).await
    }
}
