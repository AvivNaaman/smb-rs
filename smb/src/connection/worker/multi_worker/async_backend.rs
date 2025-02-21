use crate::sync_helpers::*;
use std::sync::Arc;
use tokio::{select, sync::oneshot};

use crate::{msg_handler::IncomingMessage, packets::netbios::NetBiosTcpMessage, Error};

use crate::connection::netbios_client::NetBiosClient;

use super::base::MultiWorkerBase;
use super::backend_trait::MultiWorkerBackend;

#[derive(Debug)]
pub struct AsyncBackend {
    /// The loop handle for the worker.
    loop_handle: Mutex<Option<JoinHandle<()>>>,

    token: CancellationToken,
}

#[cfg(feature = "async")]
impl AsyncBackend {
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Internal message loop handler.
    async fn loop_fn(
        self: Arc<Self>,
        mut netbios_client: NetBiosClient,
        mut rx: mpsc::Receiver<NetBiosTcpMessage>,
        worker: Arc<MultiWorkerBase<Self>>,
    ) {
        log::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref
                .handle_next_msg(&mut netbios_client, &mut rx, &worker)
                .await
            {
                Ok(_) => {}
                Err(Error::NotConnected) => {
                    if self.is_cancelled() {
                        log::info!("Connection closed.");
                    } else {
                        log::error!("Connection closed.");
                    }
                    break;
                }
                Err(e) => {
                    log::error!("Error in worker loop: {}", e);
                }
            }
        }

        // Cleanup
        // TODO: Handle cleanup recursively.
        log::debug!("Cleaning up worker loop.");
        rx.close();
        if let Ok(mut state) = worker.state.lock().await {
            for (_, tx) in state.awaiting.drain() {
                tx.send(Err(Error::NotConnected)).unwrap();
            }
        }
    }

    /// Handles the next message in the loop:
    /// - receives a message, transforms it, and sends it to the correct awaiting task.
    /// - sends a message to the server.
    pub(crate) async fn handle_next_msg(
        self: &Self,
        netbios_client: &mut NetBiosClient,
        send_channel: &mut mpsc::Receiver<NetBiosTcpMessage>,
        worker: &Arc<MultiWorkerBase<Self>>,
    ) -> crate::Result<()> {
        select! {
            // Receive a message from the server.
            message = netbios_client.recieve_bytes() => {
                worker.loop_handle_incoming(message).await?;
            }
            // Send a message to the server.
            message = send_channel.recv() => {
                worker.loop_handle_outgoing(message, netbios_client).await?;
            },
            // Cancel the loop.
            _ = self.token.cancelled() => {
                return Err(Error::NotConnected);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
impl MultiWorkerBackend for AsyncBackend {
    type SendMessage = NetBiosTcpMessage;

    type AwaitingNotifier = oneshot::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = oneshot::Receiver<crate::Result<IncomingMessage>>;

    async fn start(
        netbios_client: NetBiosClient,
        worker: Arc<MultiWorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>> {
        // Start the worker loop.
        let backend = Arc::new(Self {
            loop_handle: Mutex::new(None),
            token: CancellationToken::new(),
        });
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            backend_clone
                .loop_fn(netbios_client, send_channel_recv, worker)
                .await
        });
        backend.loop_handle.lock().await?.replace(handle);

        Ok(backend)
    }

    async fn stop(&self) -> crate::Result<()> {
        log::debug!("Stopping worker.");
        self.token.cancel();
        self.loop_handle
            .lock()
            .await?
            .take()
            .ok_or(Error::NotConnected)?
            .await?;
        Ok(())
    }
    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage {
        msg
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        oneshot::channel()
    }

    async fn wait_on_waiter(waiter: Self::AwaitingWaiter) -> crate::Result<IncomingMessage> {
        waiter
            .await
            .map_err(|_| Error::MessageProcessingError("Failed to receive message.".to_string()))?
    }

    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()> {
        tx.send(msg).map_err(|_| {
            Error::MessageProcessingError("Failed to send message to awaiting task.".to_string())
        })
    }

    fn make_send_channel_pair() -> (
        mpsc::Sender<Self::SendMessage>,
        mpsc::Receiver<Self::SendMessage>,
    ) {
        mpsc::channel(100)
    }
}
