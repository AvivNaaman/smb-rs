use crate::connection::netbios_client::NetBiosClient;
use crate::connection::transformer::Transformer;
use crate::connection::worker::Worker;
use crate::sync_helpers::*;
use maybe_async::*;
use std::sync::atomic::AtomicBool;
use std::{collections::HashMap, sync::Arc};

use crate::{
    msg_handler::{IncomingMessage, OutgoingMessage, SendMessageResult},
    packets::netbios::NetBiosTcpMessage,
    Error,
};

use super::backend_trait::MultiWorkerBackend;

/// SMB2 connection worker.
///
/// This struct is responsible for handling the connection to the server,
/// sending netbios messages from SMB2 messages, and redirecting correct messages when received,
/// if using async, to the correct pending task.
/// One-per connection, hence takes ownership of [NetBiosClient] on [MultiWorkerBase::start].
pub struct MultiWorkerBase<T>
where
    T: MultiWorkerBackend + std::fmt::Debug,
    T::AwaitingNotifier: std::fmt::Debug,
{
    /// TODO: Pass it down to the backend?
    pub(crate) state: Mutex<WorkerAwaitState<T>>,
    backend: Mutex<Option<Arc<T>>>,

    transformer: Transformer,

    /// A channel to send messages to the worker.
    pub(crate) sender: mpsc::Sender<T::SendMessage>,
    stopped: AtomicBool,
}

/// Holds state for the worker, regarding messages to be received.
#[derive(Debug)]
pub struct WorkerAwaitState<T>
where
    T: MultiWorkerBackend,
    T::AwaitingNotifier: std::fmt::Debug,
{
    /// Stores the awaiting tasks that are waiting for a specific message ID.
    pub awaiting: HashMap<u64, T::AwaitingNotifier>,
    /// Stores the pending messages, waiting to be receive()-d.
    pub pending: HashMap<u64, IncomingMessage>,
}

impl<T> WorkerAwaitState<T>
where
    T: MultiWorkerBackend,
    T::AwaitingNotifier: std::fmt::Debug,
{
    fn new() -> Self {
        Self {
            awaiting: HashMap::new(),
            pending: HashMap::new(),
        }
    }
}

impl<T> MultiWorkerBase<T>
where
    T: MultiWorkerBackend + std::fmt::Debug,
    T::AwaitingNotifier: std::fmt::Debug,
{
    #[maybe_async]
    pub fn stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[maybe_async]
    pub(crate) async fn loop_handle_incoming(
        self: &Arc<Self>,
        message: crate::Result<NetBiosTcpMessage>,
    ) -> crate::Result<()> {
        log::trace!("Received message from server.");
        let message = { message? };
        let msg = self.transformer.transform_incoming(message).await?;

        // 2. Handle the message.
        let msg_id = msg.message.header.message_id;

        // Update the state: If awaited, wake up the task. Else, store it.
        let mut state = self.state.lock().await?;
        if let Some(tx) = state.awaiting.remove(&msg_id) {
            log::trace!("Waking up awaiting task for message ID {}.", msg_id);
            T::send_notify(tx, Ok(msg))?;
        } else {
            log::trace!("Storing message until awaited: {}.", msg_id);
            state.pending.insert(msg_id, msg);
        }
        Ok(())
    }

    #[maybe_async]
    pub async fn loop_handle_outgoing(
        self: &Arc<Self>,
        message: Option<NetBiosTcpMessage>,
        netbios_client: &mut NetBiosClient,
    ) -> crate::Result<()> {
        log::trace!("Sending a message to the server.");

        let message = match message {
            Some(m) => m,
            None => {
                if self.stopped() {
                    return Err(Error::NotConnected);
                } else {
                    return Err(Error::MessageProcessingError(
                        "Empty message cannot be sent to the server.".to_string(),
                    ));
                }
            }
        };
        netbios_client.send_raw(message).await?;

        Ok(())
    }
}

impl<T> Worker for MultiWorkerBase<T>
where
    T: MultiWorkerBackend + std::fmt::Debug,
    T::AwaitingNotifier: std::fmt::Debug,
{
    #[maybe_async]
    async fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>> {
        // Build the worker
        let (tx, rx) = T::make_send_channel_pair();
        let worker = Arc::new(MultiWorkerBase::<T> {
            state: Mutex::new(WorkerAwaitState::new()),
            backend: Default::default(),
            transformer: Transformer::default(),
            sender: tx,
            stopped: AtomicBool::new(false),
        });

        worker
            .backend
            .lock()
            .await?
            .replace(T::start(netbios_client, worker.clone(), rx).await?);

        Ok(worker)
    }

    #[maybe_async]
    async fn stop(&self) -> crate::Result<()> {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        {
            self.backend
                .lock()
                .await?
                .take()
                .ok_or(Error::InvalidState(
                    "No backend present for worker.".to_string(),
                ))?
        }
        .stop()
        .await
    }

    #[maybe_async]
    async fn send(self: &Self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let finalize_preauth_hash = msg.finalize_preauth_hash;
        let id = msg.message.header.message_id;
        let message = { self.transformer.transform_outgoing(msg).await? };

        let hash = match finalize_preauth_hash {
            true => Some(self.transformer.finalize_preauth_hash().await?),
            false => None,
        };

        log::trace!(
            "Message with ID {} is passed to the worker for sending.",
            id
        );

        let message = T::wrap_msg_to_send(message);

        self.sender.send(message).await.map_err(|_| {
            Error::MessageProcessingError("Failed to send message to worker!".to_string())
        })?;

        Ok(SendMessageResult::new(id, hash))
    }

    /// Receive a message from the server.
    /// This is a user function that will wait for the message to be received.
    #[maybe_async]
    async fn receive(self: &Self, msg_id: u64) -> crate::Result<IncomingMessage> {
        // 1. Insert channel to wait for the message, or return the message if already received.
        let wait_for_receive = {
            let mut state = self.state.lock().await?;

            if self.stopped() {
                log::trace!("Connection is closed, avoid receiving.");
                return Err(Error::NotConnected);
            }
            if state.pending.contains_key(&msg_id) {
                log::trace!(
                    "Message with ID {} is already received, remove from pending.",
                    msg_id
                );
                return Ok(state.pending.remove(&msg_id).unwrap());
            }

            log::trace!(
                "Message with ID {} is not received yet, insert channel and await.",
                msg_id
            );

            let (tx, rx) = T::make_notifier_awaiter_pair();
            state.awaiting.insert(msg_id, tx);
            rx
        };

        let wait_result = T::wait_on_waiter(wait_for_receive).await;

        // Wait for the message to be received.
        Ok(wait_result.map_err(|_| {
            Error::MessageProcessingError("Failed to receive message from worker!".to_string())
        })?)
    }

    fn transformer(&self) -> &Transformer {
        &self.transformer
    }
}

impl<T> std::fmt::Debug for MultiWorkerBase<T>
where
    T: MultiWorkerBackend + std::fmt::Debug,
    T::AwaitingNotifier: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiWorkerBase")
            .field("state", &self.state)
            .field("backend", &self.backend)
            .field("transformer", &self.transformer)
            .field("sender", &self.sender)
            .field("stopped", &self.stopped)
            .finish()
    }
}
